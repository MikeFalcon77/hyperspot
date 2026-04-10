use serde::{Deserialize, Serialize};

use crate::error::CanonicalError;

// ---------------------------------------------------------------------------
// ProblemCategory — canonical-category selector for typed contract errors.
// ---------------------------------------------------------------------------

/// One of the 16 canonical AIP-193 categories. Mirrors [`CanonicalError`]
/// variants for the purpose of building a [`Problem`] envelope from a
/// typed contract error (PRD #1536 `#[derive(ContractError)]`) without
/// requiring the SDK author to construct a full `CanonicalError`
/// (which requires per-category context payloads).
///
/// HTTP status and GTS URI are determined entirely by the category; the
/// contract error supplies `error_code` / `error_domain` extensions plus a
/// JSON payload in `context["data"]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ProblemCategory {
    Cancelled,
    Unknown,
    InvalidArgument,
    DeadlineExceeded,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    ResourceExhausted,
    FailedPrecondition,
    Aborted,
    OutOfRange,
    Unimplemented,
    Internal,
    ServiceUnavailable,
    DataLoss,
    Unauthenticated,
}

impl ProblemCategory {
    /// GTS URI fragment (without the `gts://` scheme). Identical to the
    /// fragment emitted by [`CanonicalError::gts_type`] for the matching
    /// variant.
    #[must_use]
    pub fn gts_fragment(self) -> &'static str {
        match self {
            Self::Cancelled => "gts.cf.core.errors.err.v1~cf.core.err.cancelled.v1~",
            Self::Unknown => "gts.cf.core.errors.err.v1~cf.core.err.unknown.v1~",
            Self::InvalidArgument => {
                "gts.cf.core.errors.err.v1~cf.core.err.invalid_argument.v1~"
            }
            Self::DeadlineExceeded => {
                "gts.cf.core.errors.err.v1~cf.core.err.deadline_exceeded.v1~"
            }
            Self::NotFound => "gts.cf.core.errors.err.v1~cf.core.err.not_found.v1~",
            Self::AlreadyExists => {
                "gts.cf.core.errors.err.v1~cf.core.err.already_exists.v1~"
            }
            Self::PermissionDenied => {
                "gts.cf.core.errors.err.v1~cf.core.err.permission_denied.v1~"
            }
            Self::ResourceExhausted => {
                "gts.cf.core.errors.err.v1~cf.core.err.resource_exhausted.v1~"
            }
            Self::FailedPrecondition => {
                "gts.cf.core.errors.err.v1~cf.core.err.failed_precondition.v1~"
            }
            Self::Aborted => "gts.cf.core.errors.err.v1~cf.core.err.aborted.v1~",
            Self::OutOfRange => "gts.cf.core.errors.err.v1~cf.core.err.out_of_range.v1~",
            Self::Unimplemented => {
                "gts.cf.core.errors.err.v1~cf.core.err.unimplemented.v1~"
            }
            Self::Internal => "gts.cf.core.errors.err.v1~cf.core.err.internal.v1~",
            Self::ServiceUnavailable => {
                "gts.cf.core.errors.err.v1~cf.core.err.service_unavailable.v1~"
            }
            Self::DataLoss => "gts.cf.core.errors.err.v1~cf.core.err.data_loss.v1~",
            Self::Unauthenticated => {
                "gts.cf.core.errors.err.v1~cf.core.err.unauthenticated.v1~"
            }
        }
    }

    /// HTTP status mapping per AIP-193 and gRPC↔HTTP conventions.
    #[must_use]
    pub fn http_status(self) -> u16 {
        match self {
            Self::Cancelled => 499,
            Self::Unknown => 500,
            Self::InvalidArgument => 400,
            Self::DeadlineExceeded => 504,
            Self::NotFound => 404,
            Self::AlreadyExists => 409,
            Self::PermissionDenied => 403,
            Self::ResourceExhausted => 429,
            Self::FailedPrecondition => 400,
            Self::Aborted => 409,
            Self::OutOfRange => 400,
            Self::Unimplemented => 501,
            Self::Internal => 500,
            Self::ServiceUnavailable => 503,
            Self::DataLoss => 500,
            Self::Unauthenticated => 401,
        }
    }

    /// Human-readable title for the RFC 9457 envelope. Same string as
    /// [`CanonicalError::title`] for the matching variant.
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            Self::Cancelled => "Cancelled",
            Self::Unknown => "Unknown",
            Self::InvalidArgument => "Invalid argument",
            Self::DeadlineExceeded => "Deadline exceeded",
            Self::NotFound => "Not found",
            Self::AlreadyExists => "Already exists",
            Self::PermissionDenied => "Permission denied",
            Self::ResourceExhausted => "Resource exhausted",
            Self::FailedPrecondition => "Failed precondition",
            Self::Aborted => "Aborted",
            Self::OutOfRange => "Out of range",
            Self::Unimplemented => "Unimplemented",
            Self::Internal => "Internal",
            Self::ServiceUnavailable => "Service unavailable",
            Self::DataLoss => "Data loss",
            Self::Unauthenticated => "Unauthenticated",
        }
    }
}

// ---------------------------------------------------------------------------
// Problem (RFC 9457)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Problem {
    #[serde(rename = "type")]
    pub problem_type: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    pub context: serde_json::Value,

    /// Machine-readable identifier of the typed error variant inside its
    /// domain. Set by [`#[derive(ContractError)]`] when a contract error
    /// crosses the wire so PRD-conformant peers can reconstruct the
    /// original Rust enum variant via `error_code` + `error_domain`.
    /// `None` for canonical-category-only errors.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,

    /// Namespace owning the `error_code`. Conventionally
    /// `<service>.<version>` (e.g. `billing.v1`). `None` when no contract
    /// error is in play.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_domain: Option<String>,
}

impl Problem {
    /// Convert a `CanonicalError` to a `Problem`.
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` if the error-category context type
    /// fails to serialize.  Built-in context types are plain structs and
    /// should never fail, but this keeps the failure visible rather than
    /// silently producing an empty `"context": {}`.
    pub fn from_error(err: &CanonicalError) -> Result<Self, serde_json::Error> {
        let problem_type = format!("gts://{}", err.gts_type());
        let title = err.title().to_owned();
        let status = err.status_code();
        let detail = err.detail().to_owned();

        let mut context = serialize_context(err)?;

        if let Some(rt) = err.resource_type() {
            context["resource_type"] = serde_json::Value::String(rt.to_owned());
        }

        if let Some(rn) = err.resource_name() {
            context["resource_name"] = serde_json::Value::String(rn.to_owned());
        }

        Ok(Problem {
            problem_type,
            title,
            status,
            detail,
            instance: None,
            trace_id: None,
            context,
            error_code: None,
            error_domain: None,
        })
    }

    /// Attach the `error_code` extension field (PRD #1536 contract-error
    /// envelope). Returns `self` for chaining.
    #[must_use]
    pub fn with_error_code(mut self, code: impl Into<String>) -> Self {
        self.error_code = Some(code.into());
        self
    }

    /// Attach the `error_domain` extension field. Returns `self` for chaining.
    #[must_use]
    pub fn with_error_domain(mut self, domain: impl Into<String>) -> Self {
        self.error_domain = Some(domain.into());
        self
    }

    /// Build a [`Problem`] for a typed contract error (PRD #1536 envelope).
    ///
    /// `category` selects one of the 16 canonical AIP-193 categories; the
    /// resulting `Problem` carries the matching GTS URI in `type`, the
    /// canonical HTTP status, and the canonical title. `error_code` and
    /// `error_domain` populate the PRD extension fields, and `data` is
    /// placed at `context["data"]` to carry variant-specific payload.
    ///
    /// Used by `#[derive(ContractError)]` emit-paths; SDK authors rarely
    /// call this directly.
    pub fn contract_error(
        category: ProblemCategory,
        error_code: impl Into<String>,
        error_domain: impl Into<String>,
        detail: impl Into<String>,
        data: serde_json::Value,
    ) -> Self {
        let mut context = serde_json::Map::new();
        context.insert("data".to_owned(), data);
        Problem {
            problem_type: format!("gts://{}", category.gts_fragment()),
            title: category.title().to_owned(),
            status: category.http_status(),
            detail: detail.into(),
            instance: None,
            trace_id: None,
            context: serde_json::Value::Object(context),
            error_code: Some(error_code.into()),
            error_domain: Some(error_domain.into()),
        }
    }

    /// Convert a `CanonicalError` to a `Problem`, including the internal
    /// diagnostic string in the `context` for `Internal` and `Unknown`
    /// variants.
    ///
    /// **This method MUST NOT be used in production.** It exists so that
    /// development and test environments can surface the real error cause
    /// in the wire response for easier debugging.
    ///
    /// In production, use [`from_error`](Self::from_error) instead — it
    /// never leaks the diagnostic string.
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` if the context fails to serialize.
    pub fn from_error_debug(err: &CanonicalError) -> Result<Self, serde_json::Error> {
        let mut problem = Self::from_error(err)?;

        if let Some(diag) = err.diagnostic() {
            problem.context["description"] = serde_json::Value::String(diag.to_owned());
        }

        Ok(problem)
    }

    /// Set the `trace_id` field, returning `self` for chaining.
    #[must_use]
    pub fn with_trace_id(mut self, trace_id: impl Into<String>) -> Self {
        self.trace_id = Some(trace_id.into());
        self
    }

    /// Set the `instance` field, returning `self` for chaining.
    #[must_use]
    pub fn with_instance(mut self, instance: impl Into<String>) -> Self {
        self.instance = Some(instance.into());
        self
    }
}

fn serialize_context(err: &CanonicalError) -> Result<serde_json::Value, serde_json::Error> {
    match err {
        CanonicalError::Cancelled { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::Unknown { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::InvalidArgument { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::DeadlineExceeded { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::NotFound { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::AlreadyExists { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::PermissionDenied { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::ResourceExhausted { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::FailedPrecondition { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::Aborted { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::OutOfRange { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::Unimplemented { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::Internal { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::ServiceUnavailable { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::DataLoss { ctx, .. } => serde_json::to_value(ctx),
        CanonicalError::Unauthenticated { ctx, .. } => serde_json::to_value(ctx),
    }
}

impl From<CanonicalError> for Problem {
    fn from(err: CanonicalError) -> Self {
        match Problem::from_error(&err) {
            Ok(p) => p,
            Err(ser_err) => Problem {
                problem_type: format!("gts://{}", err.gts_type()),
                title: err.title().to_owned(),
                status: err.status_code(),
                detail: err.detail().to_owned(),
                instance: None,
                trace_id: None,
                context: serde_json::Value::String(ser_err.to_string()),
                error_code: None,
                error_domain: None,
            },
        }
    }
}
