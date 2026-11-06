use std::io;
use std::time::Duration;

use crate::model::PortState;

/// How a failed connect attempt should be interpreted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    Closed,
    Filtered,
    Unreachable,
    LocalResource,
    Other,
}

impl FailureKind {
    pub const fn state(self) -> PortState {
        match self {
            Self::Closed => PortState::Closed,
            Self::Filtered => PortState::Filtered,
            Self::Unreachable => PortState::Unreachable,
            Self::LocalResource | Self::Other => PortState::Error,
        }
    }

    pub const fn retryable(self) -> bool {
        matches!(self, Self::LocalResource)
    }
}

#[derive(Clone, Debug)]
pub struct Failure {
    pub kind: FailureKind,
    pub detail: String,
}

impl Failure {
    pub fn new(kind: FailureKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    pub fn timed_out(timeout: Duration) -> Self {
        Self::new(
            FailureKind::Filtered,
            format!(
                "connect timed out after {:.0}ms",
                timeout.as_secs_f64() * 1000.0
            ),
        )
    }
}

/// Classify a connect error without ever turning a local resource failure into
/// a port state.
pub fn classify_io_error(error: &io::Error) -> Failure {
    Failure::new(classify_kind(error), error.to_string())
}

/// Classify a connect error's kind without allocating a detail string.
///
/// The scan hot path calls this for every failed probe and only formats the
/// error itself when the result will be retained.
pub fn classify_kind(error: &io::Error) -> FailureKind {
    if let Some(kind) = classify_raw_os_error(error.raw_os_error()) {
        return kind;
    }

    match error.kind() {
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe => FailureKind::Closed,
        io::ErrorKind::TimedOut => FailureKind::Filtered,
        io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkUnreachable => {
            FailureKind::Unreachable
        }
        _ => FailureKind::Other,
    }
}

#[cfg(unix)]
fn classify_raw_os_error(code: Option<i32>) -> Option<FailureKind> {
    let code = code?;
    let kind = match code {
        libc::ECONNREFUSED | libc::ECONNRESET | libc::ECONNABORTED | libc::EPIPE => {
            FailureKind::Closed
        }
        libc::ETIMEDOUT => FailureKind::Filtered,
        libc::EHOSTUNREACH | libc::ENETUNREACH => FailureKind::Unreachable,
        libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM => FailureKind::LocalResource,
        _ => return None,
    };
    Some(kind)
}

#[cfg(not(unix))]
fn classify_raw_os_error(_code: Option<i32>) -> Option<FailureKind> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn classifies_common_unix_connect_errors() {
        assert_eq!(
            classify_io_error(&io::Error::from_raw_os_error(libc::ECONNREFUSED)).kind,
            FailureKind::Closed
        );
        assert_eq!(
            classify_io_error(&io::Error::from_raw_os_error(libc::ETIMEDOUT)).kind,
            FailureKind::Filtered
        );
        assert_eq!(
            classify_io_error(&io::Error::from_raw_os_error(libc::EHOSTUNREACH)).kind,
            FailureKind::Unreachable
        );
        assert_eq!(
            classify_io_error(&io::Error::from_raw_os_error(libc::EMFILE)).kind,
            FailureKind::LocalResource
        );
    }

    #[test]
    fn resource_failures_are_retryable_but_not_port_states() {
        let failure = Failure::new(FailureKind::LocalResource, "too many open files");
        assert!(failure.kind.retryable());
        assert_eq!(failure.kind.state(), PortState::Error);
    }
}
