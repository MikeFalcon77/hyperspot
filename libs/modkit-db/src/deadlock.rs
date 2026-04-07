//! Deadlock and serialization failure detection utilities.
//!
//! > "Always be prepared to re-issue a transaction if it fails due to deadlock.
//! > Deadlocks are not dangerous. Just try again."
//! > — [`MySQL` 8.0 Reference Manual, `InnoDB` Deadlocks](https://dev.mysql.com/doc/refman/8.0/en/innodb-deadlocks.html)
//!
//! `InnoDB` detects deadlocks instantly and rolls back one transaction (the victim).
//! SQLSTATE `40001` signals a serialization failure that is always safe to retry.
//! This module provides detection helpers for use by callers that manage their
//! own transaction lifecycle (e.g., the outbox sequencer, hierarchy mutations).

use sea_orm::DbErr;

/// SQLSTATE `40001` — serialization failure / deadlock.
///
/// This code is used by both `PostgreSQL` (for serialization failures under
/// `SERIALIZABLE` isolation) and `MySQL`/`MariaDB` (for `InnoDB` deadlocks).
const SERIALIZATION_FAILURE_SQLSTATE: &str = "40001";

/// `PostgreSQL` error message substring for serialization failures.
///
/// `PostgreSQL` reports `could not serialize access` when a `SERIALIZABLE`
/// transaction detects a read/write dependency conflict.
const PG_SERIALIZATION_MSG: &str = "could not serialize access";

/// Returns `true` if the error contains SQLSTATE `40001`.
///
/// This matches both `MySQL`/`MariaDB` deadlocks and `PostgreSQL` serialization
/// failures. It does **not** distinguish between the two — both are retryable.
/// [`is_serialization_failure`] broadens detection by also matching the
/// `PostgreSQL` error message text for cases where the SQLSTATE is absent.
///
/// Always returns `false` for non-runtime errors (`Custom`, `RecordNotFound`, etc.)
/// and for `SQLite` errors (single-writer model, no SQLSTATE `40001`).
///
/// Detection is based on the error's string representation containing the
/// SQLSTATE code, which avoids a direct dependency on `sqlx` types.
#[must_use]
pub fn is_deadlock(err: &DbErr) -> bool {
    match err {
        DbErr::Exec(runtime_err) | DbErr::Query(runtime_err) => {
            let msg = runtime_err.to_string();
            msg.contains(SERIALIZATION_FAILURE_SQLSTATE)
        }
        _ => false,
    }
}

/// Returns `true` if the error is a retryable serialization failure.
///
/// This is a superset of [`is_deadlock`] — it matches SQLSTATE `40001` **and**
/// the `PostgreSQL` `could not serialize access` message text.  Both deadlocks
/// and serialization conflicts are retryable, and this function does not
/// distinguish between them.
///
/// Coverage:
/// - **`PostgreSQL`**: `SERIALIZABLE` isolation conflicts
///   (`could not serialize access`, SQLSTATE `40001`)
/// - **`MySQL`/`MariaDB`**: `InnoDB` deadlocks (SQLSTATE `40001`)
/// - **`SQLite`**: Always `false` (single-writer model, no serialization failures)
///
/// Use this to implement bounded retry around `SERIALIZABLE` transactions.
///
/// Detection is based on the error's string representation to avoid a direct
/// dependency on `sqlx` types.
#[must_use]
pub fn is_serialization_failure(err: &DbErr) -> bool {
    match err {
        DbErr::Exec(runtime_err) | DbErr::Query(runtime_err) => {
            let msg = runtime_err.to_string();
            msg.contains(SERIALIZATION_FAILURE_SQLSTATE) || msg.contains(PG_SERIALIZATION_MSG)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::RuntimeErr;

    fn exec_err(msg: &str) -> DbErr {
        DbErr::Exec(RuntimeErr::Internal(msg.to_owned()))
    }

    // -- is_deadlock positive cases --

    #[test]
    fn deadlock_sqlstate_40001_detected() {
        assert!(is_deadlock(&exec_err(
            "error returned from database: 40001: Deadlock found"
        )));
    }

    #[test]
    fn deadlock_pg_serialization_failure_detected() {
        assert!(is_deadlock(&exec_err(
            "ERROR: 40001: could not serialize access"
        )));
    }

    // -- is_deadlock negative cases --

    #[test]
    fn non_deadlock_errors_return_false() {
        assert!(!is_deadlock(&DbErr::Custom("something".into())));
        assert!(!is_deadlock(&DbErr::RecordNotFound("x".into())));
        assert!(!is_deadlock(&exec_err("duplicate key value")));
    }

    // -- is_serialization_failure positive cases --

    #[test]
    fn serialization_failure_sqlstate_detected() {
        assert!(is_serialization_failure(&exec_err(
            "error returned from database: 40001"
        )));
    }

    #[test]
    fn serialization_failure_pg_message_detected() {
        assert!(is_serialization_failure(&exec_err(
            "ERROR: could not serialize access due to concurrent update"
        )));
    }

    // -- is_serialization_failure negative cases --

    #[test]
    fn non_serialization_errors_return_false() {
        assert!(!is_serialization_failure(&DbErr::Custom(
            "something".into()
        )));
        assert!(!is_serialization_failure(&exec_err("unique constraint")));
    }
}
