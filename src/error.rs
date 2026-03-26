//! Error types for ip-discovery

use std::fmt;

/// Main error type for IP detection
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// All configured providers failed
    AllProvidersFailed(Vec<ProviderError>),

    /// No providers support the requested IP version
    NoProvidersForVersion,

    /// Consensus could not be reached
    ConsensusNotReached {
        /// Minimum number of providers that needed to agree
        required: usize,
        /// Maximum number of providers that agreed on the same IP
        got: usize,
        /// Errors from providers that failed during consensus
        errors: Vec<ProviderError>,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AllProvidersFailed(errors) => write!(f, "all providers failed: {:?}", errors),
            Error::NoProvidersForVersion => {
                write!(f, "no providers support the requested IP version")
            }
            Error::ConsensusNotReached {
                required,
                got,
                errors,
            } => {
                write!(
                    f,
                    "consensus not reached (required {}, got {}, {} provider errors)",
                    required,
                    got,
                    errors.len()
                )
            }
        }
    }
}

impl std::error::Error for Error {}

/// Error from a specific provider
#[derive(Debug)]
pub struct ProviderError {
    /// Name of the provider that failed
    pub provider: String,
    /// The error that occurred
    pub error: Box<dyn std::error::Error + Send + Sync>,
}

impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.provider, self.error)
    }
}

impl std::error::Error for ProviderError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.error.as_ref())
    }
}

impl ProviderError {
    /// Create a new provider error from any error type.
    pub fn new<E>(provider: impl Into<String>, error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self {
            provider: provider.into(),
            error: Box::new(error),
        }
    }

    /// Create a new provider error from a message string.
    pub fn message(provider: impl Into<String>, msg: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            error: Box::new(StringError(msg.into())),
        }
    }
}

#[derive(Debug)]
struct StringError(String);

impl fmt::Display for StringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for StringError {}
