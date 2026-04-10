//! Server-Sent Events (SSE) parser used by streaming clients.
//!
//! Translates a byte stream into a stream of typed events. Recognises:
//! - `data: <json>` — emits `Ok(T)` after JSON-deserializing into `T`.
//! - `event: error` — the next `data:` is parsed as a `ProblemDetails`
//!   wrapped in [`TransportError::Problem`].
//! - `event: done` — terminates the stream.
//!
//! All other event types are ignored. Comments (lines starting with `:`) and
//! blank lines are stripped per the SSE spec.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use futures_core::Stream;
use parking_lot::RwLock;
use serde::de::DeserializeOwned;

use modkit_canonical_errors::Problem;

use crate::runtime::transport_error::TransportError;

/// Shared cell holding the latest seen SSE `id:` field. The streaming
/// client clones this handle before constructing the parser; on stream
/// interruption it reads the latest ID and re-issues the request with a
/// `Last-Event-ID` header (per HTML5 EventSource spec).
///
/// Wraps `Arc<RwLock<Option<String>>>` as a newtype so the underlying lock
/// implementation isn't part of the public surface — the `parking_lot` vs
/// `tokio::sync` choice can change without a breaking SDK release.
#[derive(Clone, Debug, Default)]
pub struct LastEventId(Arc<RwLock<Option<String>>>);

impl LastEventId {
    /// Create an empty [`LastEventId`] cell.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Snapshot the latest ID value, if any.
    #[must_use]
    pub fn current(&self) -> Option<String> {
        self.0.read().clone()
    }

    /// Replace the latest ID. `None` clears the cell (per HTML5 spec, an
    /// empty `id:` field resets the saved value).
    pub fn set(&self, value: Option<String>) {
        *self.0.write() = value;
    }
}

/// Parse an SSE byte stream into a stream of typed events.
///
/// `bytes` is typically the byte-stream view of
/// `modkit_http::HttpResponse::into_body()` (adapted via
/// [`crate::runtime::http::body_to_byte_stream`]). Errors from the inner
/// stream are surfaced as [`TransportError::Network`].
///
/// To capture `id:` fields for `Last-Event-ID` reconnect, use
/// [`parse_sse_stream_with_id`] and pass in a shared cell that the
/// streaming client can read from.
pub fn parse_sse_stream<T, S, E>(bytes: S) -> SseStream<T, S>
where
    T: DeserializeOwned + 'static,
    S: Stream<Item = Result<Bytes, E>> + Unpin + 'static,
    E: std::fmt::Display,
{
    parse_sse_stream_with_id(bytes, LastEventId::empty())
}

/// Same as [`parse_sse_stream`] but accepts a [`LastEventId`] cell that the
/// parser updates whenever it encounters an `id:` field. Streaming clients
/// hand the cell into the request-factory closure on reconnect to populate
/// the `Last-Event-ID` header — per HTML5 EventSource spec.
pub fn parse_sse_stream_with_id<T, S, E>(bytes: S, last_event_id: LastEventId) -> SseStream<T, S>
where
    T: DeserializeOwned + 'static,
    S: Stream<Item = Result<Bytes, E>> + Unpin + 'static,
    E: std::fmt::Display,
{
    SseStream {
        inner: bytes,
        buf: BytesMut::with_capacity(4 * 1024),
        pending: Vec::new(),
        next_event: SseEventKind::Message,
        done: false,
        last_event_id,
        _marker: std::marker::PhantomData,
    }
}

/// Iterator yielded by [`parse_sse_stream`].
pub struct SseStream<T, S> {
    inner: S,
    buf: BytesMut,
    pending: Vec<Result<T, TransportError>>,
    next_event: SseEventKind,
    done: bool,
    last_event_id: LastEventId,
    _marker: std::marker::PhantomData<fn() -> T>,
}

impl<T, S> SseStream<T, S> {
    /// Returns a clone of the shared cell that captures the latest `id:`
    /// field seen on the stream. The streaming client uses this to populate
    /// the `Last-Event-ID` header on reconnect.
    #[must_use]
    pub fn last_event_id_handle(&self) -> LastEventId {
        self.last_event_id.clone()
    }
}

// `inner` is bounded by `Unpin` at construction; the rest of the fields are
// trivially `Unpin`. Implement `Unpin` unconditionally so callers can poll
// `Pin<&mut SseStream<...>>` without pinning the type itself.
impl<T, S: Unpin> Unpin for SseStream<T, S> {}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SseEventKind {
    Message,
    Error,
    Done,
}

impl<T, S, E> Stream for SseStream<T, S>
where
    T: DeserializeOwned + 'static,
    S: Stream<Item = Result<Bytes, E>> + Unpin + 'static,
    E: std::fmt::Display,
{
    type Item = Result<T, TransportError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        loop {
            if let Some(item) = this.pending.pop() {
                return Poll::Ready(Some(item));
            }
            if this.done {
                return Poll::Ready(None);
            }

            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    this.done = true;
                    if let Some(extra) = drain_remaining(
                        &mut this.buf,
                        &mut this.next_event,
                        &this.last_event_id,
                    ) {
                        this.pending.insert(0, extra);
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    this.done = true;
                    return Poll::Ready(Some(Err(TransportError::network(e))));
                }
                Poll::Ready(Some(Ok(chunk))) => {
                    this.buf.extend_from_slice(&chunk);
                    drain_buffer(
                        &mut this.buf,
                        &mut this.next_event,
                        &mut this.pending,
                        &this.last_event_id,
                    );
                    if this.next_event == SseEventKind::Done {
                        this.done = true;
                    }
                }
            }
        }
    }
}

fn drain_buffer<T: DeserializeOwned + 'static>(
    buf: &mut BytesMut,
    state: &mut SseEventKind,
    out: &mut Vec<Result<T, TransportError>>,
    last_event_id: &LastEventId,
) {
    while let Some(line_end) = find_line_end(buf) {
        let line_bytes = buf.split_to(line_end.consumed);
        // SSE wire format mandates UTF-8 (RFC 8259 § 8.1, EventSource spec).
        // Surface non-conforming server output as a typed transport error
        // instead of silently dropping the line — invisible data loss is
        // worse than a propagated error.
        match std::str::from_utf8(&line_bytes[..line_end.line_len]) {
            Ok(line) => {
                if let Some(item) = process_line(line, state, last_event_id) {
                    out.insert(0, item);
                }
            }
            Err(e) => {
                out.insert(
                    0,
                    Err(TransportError::sse(format!(
                        "invalid UTF-8 in SSE frame: {e}"
                    ))),
                );
            }
        }
    }
}

fn drain_remaining<T: DeserializeOwned + 'static>(
    buf: &mut BytesMut,
    state: &mut SseEventKind,
    last_event_id: &LastEventId,
) -> Option<Result<T, TransportError>> {
    if buf.is_empty() {
        return None;
    }
    let result = match std::str::from_utf8(buf) {
        Ok(s) => process_line(&s.to_owned(), state, last_event_id),
        Err(e) => Some(Err(TransportError::sse(format!(
            "invalid UTF-8 in SSE frame: {e}"
        )))),
    };
    buf.clear();
    result
}

fn process_line<T: DeserializeOwned + 'static>(
    raw: &str,
    state: &mut SseEventKind,
    last_event_id: &LastEventId,
) -> Option<Result<T, TransportError>> {
    let line = raw.trim_end_matches(['\r', '\n']);
    if line.is_empty() || line.starts_with(':') {
        return None;
    }

    if let Some(value) = line.strip_prefix("event:") {
        match value.trim() {
            "error" => *state = SseEventKind::Error,
            "done" => *state = SseEventKind::Done,
            _ => *state = SseEventKind::Message,
        }
        return None;
    }

    // SSE `id:` field — capture so the streaming client can re-send via
    // `Last-Event-ID` on reconnect (per HTML5 EventSource spec). Empty
    // `id:` clears the saved value, also per spec.
    if let Some(value) = line.strip_prefix("id:") {
        let id = value.trim().to_owned();
        last_event_id.set(if id.is_empty() { None } else { Some(id) });
        return None;
    }

    if let Some(value) = line.strip_prefix("data:") {
        let payload = value.trim();
        let kind = std::mem::replace(state, SseEventKind::Message);
        return match kind {
            SseEventKind::Done => None,
            SseEventKind::Error => Some(Err(parse_problem(payload))),
            SseEventKind::Message => match serde_json::from_str::<T>(payload) {
                Ok(v) => Some(Ok(v)),
                Err(e) => Some(Err(TransportError::serialization(e))),
            },
        };
    }

    None
}

fn parse_problem(payload: &str) -> TransportError {
    match serde_json::from_str::<Problem>(payload) {
        Ok(p) => TransportError::Problem(p),
        Err(e) => TransportError::sse(format!("malformed error event: {e}")),
    }
}

struct LineEnd {
    consumed: usize,
    line_len: usize,
}

fn find_line_end(buf: &[u8]) -> Option<LineEnd> {
    for (i, b) in buf.iter().enumerate() {
        if *b == b'\n' {
            return Some(LineEnd {
                consumed: i + 1,
                line_len: i,
            });
        }
    }
    None
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use futures_util::stream::{self, StreamExt};
    use serde::Deserialize;

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct Item {
        id: u32,
    }

    fn chunks(
        parts: &[&str],
    ) -> impl Stream<Item = Result<Bytes, std::io::Error>> + Unpin + use<> {
        let owned: Vec<Result<Bytes, std::io::Error>> =
            parts.iter().map(|s| Ok(Bytes::from(s.to_string()))).collect();
        Box::pin(stream::iter(owned))
    }

    #[tokio::test]
    async fn parses_data_events() {
        let s = chunks(&[
            "data: {\"id\":1}\n\n",
            "data: {\"id\":2}\n\n",
            "event: done\n\n",
        ]);
        let parsed: Vec<_> = parse_sse_stream::<Item, _, _>(s).collect().await;
        let parsed: Vec<Item> = parsed.into_iter().map(|r| r.unwrap()).collect();
        assert_eq!(parsed, vec![Item { id: 1 }, Item { id: 2 }]);
    }

    #[tokio::test]
    async fn handles_data_split_across_chunks() {
        let s = chunks(&["data: {\"i", "d\":7}\n\nevent: done\n\n"]);
        let parsed: Vec<_> = parse_sse_stream::<Item, _, _>(s).collect().await;
        let parsed: Vec<Item> = parsed.into_iter().map(|r| r.unwrap()).collect();
        assert_eq!(parsed, vec![Item { id: 7 }]);
    }

    #[tokio::test]
    async fn surfaces_error_event_as_problem() {
        // Canonical RFC 9457 Problem on the `event: error` channel.
        let problem = serde_json::json!({
            "type": "gts://gts.cf.core.errors.err.v1~cf.core.err.internal.v1~",
            "title": "Internal",
            "status": 500,
            "detail": "broke",
            "context": {}
        });
        let body = format!("event: error\ndata: {problem}\n\nevent: done\n\n");
        let s = chunks(&[&body]);
        let parsed: Vec<_> = parse_sse_stream::<Item, _, _>(s).collect().await;
        assert_eq!(parsed.len(), 1);
        match parsed.into_iter().next().unwrap() {
            Err(TransportError::Problem(p)) => {
                assert_eq!(p.detail, "broke");
                assert!(p.problem_type.contains("internal"));
            }
            other => panic!("expected Problem, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ignores_comments_and_blank_lines() {
        let s = chunks(&[":heartbeat\n\ndata: {\"id\":3}\n\nevent: done\n\n"]);
        let parsed: Vec<_> = parse_sse_stream::<Item, _, _>(s).collect().await;
        let parsed: Vec<Item> = parsed.into_iter().map(|r| r.unwrap()).collect();
        assert_eq!(parsed, vec![Item { id: 3 }]);
    }

    #[tokio::test]
    async fn malformed_json_yields_serialization_error() {
        let s = chunks(&["data: not-json\n\nevent: done\n\n"]);
        let parsed: Vec<_> = parse_sse_stream::<Item, _, _>(s).collect().await;
        assert_eq!(parsed.len(), 1);
        match parsed.into_iter().next().unwrap() {
            Err(TransportError::Serialization(_)) => {}
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn captures_id_field_for_reconnect() {
        let cell = LastEventId::empty();
        let s = chunks(&[
            "id: 42\ndata: {\"id\":1}\n\n",
            "id: 43\ndata: {\"id\":2}\n\n",
            "event: done\n\n",
        ]);
        let stream = parse_sse_stream_with_id::<Item, _, _>(s, cell.clone());
        let parsed: Vec<_> = stream.collect().await;
        let parsed: Vec<Item> = parsed.into_iter().map(|r| r.unwrap()).collect();
        assert_eq!(parsed, vec![Item { id: 1 }, Item { id: 2 }]);
        // After all events parsed, the cell holds the last seen id.
        assert_eq!(cell.current().as_deref(), Some("43"));
    }

    #[tokio::test]
    async fn empty_id_field_clears_saved_value() {
        // Per HTML5 EventSource spec, an empty `id:` resets the
        // Last-Event-ID to None (won't be sent on reconnect).
        let cell = LastEventId::empty();
        let s = chunks(&[
            "id: 7\ndata: {\"id\":1}\n\n",
            "id: \ndata: {\"id\":2}\n\n",
            "event: done\n\n",
        ]);
        let stream = parse_sse_stream_with_id::<Item, _, _>(s, cell.clone());
        let _: Vec<_> = stream.collect().await;
        assert!(cell.current().is_none());
    }
}
