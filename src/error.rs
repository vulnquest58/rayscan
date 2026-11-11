use std::fmt;

/// A user-facing failure with the process exit code the CLI should return.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppError {
    message: String,
    exit_code: i32,
}

impl AppError {
    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: 2,
        }
    }

    pub fn runtime(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: 1,
        }
    }

    /// Exit with `code` without printing a diagnostic.
    ///
    /// Used for control-flow statuses such as "the differential scan detected
    /// changes" where the normal output already explains the result.
    pub fn silent(code: i32) -> Self {
        Self {
            message: String::new(),
            exit_code: code,
        }
    }

    pub fn exit_code(&self) -> i32 {
        self.exit_code
    }

    pub fn is_silent(&self) -> bool {
        self.message.is_empty()
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for AppError {}
