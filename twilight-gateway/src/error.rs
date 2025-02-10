//! Errors returned by gateway operations.

#[cfg(any(feature = "zlib-stock", feature = "zlib-simd", feature = "zstd"))]
pub use crate::compression::{CompressionError, CompressionErrorType};

use std::{
    error::Error,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
};

/// Sending a command over a channel failed.
#[derive(Debug)]
pub struct ChannelError {
    /// Type of error.
    pub(crate) kind: ChannelErrorType,
    /// Source error if available.
    pub(crate) source: Option<Box<dyn Error + Send + Sync>>,
}

impl ChannelError {
    /// Immutable reference to the type of error that occurred.
    #[must_use = "retrieving the type has no effect if left unused"]
    pub const fn kind(&self) -> &ChannelErrorType {
        &self.kind
    }

    /// Consume the error, returning the source error if there is any.
    #[must_use = "consuming the error and retrieving the source has no effect if left unused"]
    pub fn into_source(self) -> Option<Box<dyn Error + Send + Sync>> {
        self.source
    }

    /// Consume the error, returning the owned error type and the source error.
    #[must_use = "consuming the error into its parts has no effect if left unused"]
    pub fn into_parts(self) -> (ChannelErrorType, Option<Box<dyn Error + Send + Sync>>) {
        (self.kind, None)
    }
}

impl Display for ChannelError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self.kind {
            ChannelErrorType::Closed => f.write_str("tried sending over a closed channel"),
        }
    }
}

impl Error for ChannelError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| &**source as &(dyn Error + 'static))
    }
}

/// Type of [`ChannelError`] that occurred.
#[derive(Debug)]
#[non_exhaustive]
pub enum ChannelErrorType {
    /// Tried sending over a closed channel.
    Closed,
}

/// Failure when fetching the recommended number of shards to use from Discord's
/// REST API.
#[cfg(feature = "twilight-http")]
#[derive(Debug)]
pub struct StartRecommendedError {
    /// Type of error.
    pub(crate) kind: StartRecommendedErrorType,
    /// Source error if available.
    pub(crate) source: Option<Box<dyn Error + Send + Sync>>,
}

#[cfg(feature = "twilight-http")]
impl StartRecommendedError {
    /// Immutable reference to the type of error that occurred.
    #[must_use = "retrieving the type has no effect if left unused"]
    pub const fn kind(&self) -> &StartRecommendedErrorType {
        &self.kind
    }

    /// Consume the error, returning the source error if there is any.
    #[must_use = "consuming the error and retrieving the source has no effect if left unused"]
    pub fn into_source(self) -> Option<Box<dyn Error + Send + Sync>> {
        self.source
    }

    /// Consume the error, returning the owned error type and the source error.
    #[must_use = "consuming the error into its parts has no effect if left unused"]
    pub fn into_parts(
        self,
    ) -> (
        StartRecommendedErrorType,
        Option<Box<dyn Error + Send + Sync>>,
    ) {
        (self.kind, None)
    }
}

#[cfg(feature = "twilight-http")]
impl Display for StartRecommendedError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self.kind {
            StartRecommendedErrorType::Deserializing => {
                f.write_str("payload isn't a recognized type")
            }
            StartRecommendedErrorType::Request => f.write_str("request failed to complete"),
        }
    }
}

#[cfg(feature = "twilight-http")]
impl Error for StartRecommendedError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| &**source as &(dyn Error + 'static))
    }
}

/// Type of [`StartRecommendedError`] that occurred.
#[cfg(feature = "twilight-http")]
#[derive(Debug)]
pub enum StartRecommendedErrorType {
    /// Received gateway event failed to be deserialized.
    ///
    /// The message payload is likely an unrecognized type that is not yet
    /// supported.
    Deserializing,
    /// Requesting recommended shards from Discord's REST API failed.
    ///
    /// May be due to something such as a network or authentication issue.
    Request,
}

/// Receiving the next Websocket message failed.
#[derive(Debug)]
pub struct ReceiveMessageError {
    /// Type of error.
    pub(crate) kind: ReceiveMessageErrorType,
    /// Source error if available.
    pub(crate) source: Option<Box<dyn Error + Send + Sync>>,
}

impl ReceiveMessageError {
    /// Immutable reference to the type of error that occurred.
    #[must_use = "retrieving the type has no effect if left unused"]
    pub const fn kind(&self) -> &ReceiveMessageErrorType {
        &self.kind
    }

    /// Consume the error, returning the source error if there is any.
    #[must_use = "consuming the error and retrieving the source has no effect if left unused"]
    pub fn into_source(self) -> Option<Box<dyn Error + Send + Sync>> {
        self.source
    }

    /// Consume the error, returning the owned error type and the source error.
    #[must_use = "consuming the error into its parts has no effect if left unused"]
    pub fn into_parts(
        self,
    ) -> (
        ReceiveMessageErrorType,
        Option<Box<dyn Error + Send + Sync>>,
    ) {
        (self.kind, None)
    }

    /// Shortcut to create a new error for a message compression error.
    #[cfg(any(feature = "zlib-stock", feature = "zlib-simd", feature = "zstd"))]
    pub(crate) fn from_compression(source: CompressionError) -> Self {
        Self {
            kind: ReceiveMessageErrorType::Compression,
            source: Some(Box::new(source)),
        }
    }
}

impl Display for ReceiveMessageError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match &self.kind {
            #[cfg(any(feature = "zlib-stock", feature = "zlib-simd", feature = "zstd"))]
            ReceiveMessageErrorType::Compression => {
                f.write_str("binary message could not be decompressed")
            }
            ReceiveMessageErrorType::Deserializing { event } => {
                f.write_str("gateway event could not be deserialized: event=")?;
                f.write_str(event)
            }
            ReceiveMessageErrorType::Reconnect => f.write_str("failed to reconnect to the gateway"),
        }
    }
}

impl Error for ReceiveMessageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| &**source as &(dyn Error + 'static))
    }
}

/// Type of [`ReceiveMessageError`] that occurred.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReceiveMessageErrorType {
    /// Binary message could not be decompressed.
    ///
    /// The associated error downcasts to [`CompressionError`].
    #[cfg(any(feature = "zlib-stock", feature = "zlib-simd", feature = "zstd"))]
    Compression,
    /// Gateway event could not be deserialized.
    Deserializing {
        /// Gateway event.
        ///
        /// Note that the `simd-json` feature may slightly modify the event.
        event: String,
    },
    /// Shard failed to reconnect to the gateway.
    Reconnect,
}

#[cfg(test)]
mod tests {
    use super::{ReceiveMessageError, ReceiveMessageErrorType};
    use static_assertions::assert_impl_all;
    use std::{error::Error, fmt::Debug};

    assert_impl_all!(ReceiveMessageErrorType: Debug, Send, Sync);
    assert_impl_all!(ReceiveMessageError: Error, Send, Sync);

    #[test]
    fn receive_message_error_display() {
        let messages: [(ReceiveMessageErrorType, &str); 3] = [
            (
                ReceiveMessageErrorType::Compression,
                "binary message could not be decompressed",
            ),
            (
                ReceiveMessageErrorType::Deserializing {
                    event: r#"{"t":null,"s":null,"op":10,"d":{"heartbeat_interval":41250,"_trace":["[\"gateway-prd-us-east1-b-0568\",{\"micros\":0.0}]"]}}"#.to_owned(),
                },
                r#"gateway event could not be deserialized: event={"t":null,"s":null,"op":10,"d":{"heartbeat_interval":41250,"_trace":["[\"gateway-prd-us-east1-b-0568\",{\"micros\":0.0}]"]}}"#,
            ),
            (
                ReceiveMessageErrorType::Reconnect,
                "failed to reconnect to the gateway",
            ),
        ];

        for (kind, message) in messages {
            let error = ReceiveMessageError { kind, source: None };

            assert_eq!(error.to_string(), message);
        }
    }
}
