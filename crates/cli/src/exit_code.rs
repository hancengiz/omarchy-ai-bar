//! Stable process exit-code contract shared by every command mode.

use std::process::ExitCode;

/// Stable exit classes exposed by the executable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AppExitCode {
    /// The command completed successfully.
    Success = 0,
    /// Command syntax or user input was invalid.
    Usage = 2,
    /// A guard policy denied the requested action.
    GuardDenied = 10,
    /// The requested provider or feature is unavailable.
    Unavailable = 69,
    /// An internal runtime or I/O invariant failed.
    Internal = 70,
    /// Authentication or authorization requires user intervention.
    Authentication = 77,
}

impl AppExitCode {
    /// Returns the stable numeric process status.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl From<AppExitCode> for ExitCode {
    fn from(value: AppExitCode) -> Self {
        Self::from(value.as_u8())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_exit_values_do_not_drift() {
        assert_eq!(AppExitCode::Success.as_u8(), 0);
        assert_eq!(AppExitCode::Usage.as_u8(), 2);
        assert_eq!(AppExitCode::GuardDenied.as_u8(), 10);
        assert_eq!(AppExitCode::Unavailable.as_u8(), 69);
        assert_eq!(AppExitCode::Internal.as_u8(), 70);
        assert_eq!(AppExitCode::Authentication.as_u8(), 77);
    }
}
