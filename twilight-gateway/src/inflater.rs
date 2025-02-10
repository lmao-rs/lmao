//! Flate2 based decompressor for Discord gateway messages.
//!
//! The [`Inflater`] decompresses messages sent over the gateway by reusing a
//! common buffer to minimize the amount of allocations in the hot path.
//!
//! A compressed message buffer is used to store incomplete messages and gets,
//! if used, shrank every minute to the size of the most recent completed
//! message.

#![allow(deprecated)]

use crate::error::{CompressionError, CompressionErrorType};
use flate2::{Decompress, FlushDecompress};
use std::time::Instant;

/// Whether the message is incomplete.
fn is_incomplete_message(message: &[u8]) -> bool {
    /// The "magic number" deciding if a message is done or if another
    /// message needs to be read.
    ///
    /// The suffix is documented in the [Discord docs].
    ///
    /// [Discord docs]: https://discord.com/developers/docs/topics/gateway#transport-compression-transport-compression-example
    const ZLIB_SUFFIX: [u8; 4] = [0x00, 0x00, 0xff, 0xff];

    message.len() < 4 || message[(message.len() - 4)..] != ZLIB_SUFFIX
}

/// Gateway event decompressor.
///
/// Each received compressed event gets inflated into a [`String`] who's input
/// and output size is recorded.
///
/// # Example
///
/// Calculate the percentage bytes saved:
/// ```
/// # use twilight_gateway::{Intents, Shard, ShardId};
/// # #[tokio::main] async fn main() {
/// # let shard = Shard::new(ShardId::ONE, String::new(), Intents::empty());
/// let inflater = shard.inflater();
/// let total_percentage_compressed =
///     inflater.processed() as f64 * 100.0 / inflater.produced() as f64;
/// let total_percentage_saved = 100.0 - total_percentage_compressed;
/// # }
/// ```
#[deprecated(since = "0.16.1", note = "replaced by zstd compression")]
#[derive(Debug)]
pub struct Inflater {
    /// Common decompressed message buffer.
    buffer: Box<[u8]>,
    /// Per event compressed message buffer.
    compressed: Vec<u8>,
    /// Zlib decompressor with a dictionary of past data.
    decompress: Decompress,
    /// When the compression buffer last shrank.
    last_shrank: Instant,
}

impl Inflater {
    /// [`Self::buffer`]'s size.
    const BUFFER_SIZE: usize = 32 * 1024;

    /// Create a new inflator for a shard.
    pub(crate) fn new() -> Self {
        Self {
            buffer: vec![0; Self::BUFFER_SIZE].into_boxed_slice(),
            compressed: Vec::new(),
            decompress: Decompress::new(true),
            last_shrank: Instant::now(),
        }
    }

    /// Clear the compressed buffer and periodically shrink its capacity.
    fn clear(&mut self) {
        if self.compressed.capacity() != 0 && self.last_shrank.elapsed().as_secs() > 60 {
            self.compressed.shrink_to_fit();

            tracing::trace!(
                compressed.capacity = self.compressed.capacity(),
                "shrank capacity to the size of the last message"
            );

            self.last_shrank = Instant::now();
        }

        self.compressed.clear();
    }

    /// Decompress message.
    ///
    /// Returns `None` if the message is incomplete, saving its content to be
    /// combined with the next one.
    ///
    /// # Errors
    ///
    /// Returns a [`CompressionErrorType::Decompressing`] error type if the
    /// message could not be decompressed.
    ///
    /// Returns a [`CompressionErrorType::NotUtf8`] error type if the
    /// decompressed message is not UTF-8.
    pub(crate) fn inflate(&mut self, message: &[u8]) -> Result<Option<String>, CompressionError> {
        // Complete message. Tries to bypass the `self.compressed` buffer if the
        // message is incomplete.
        let message = if self.compressed.is_empty() {
            if is_incomplete_message(message) {
                tracing::trace!("received incomplete message");
                self.compressed.extend_from_slice(message);
                return Ok(None);
            }
            message
        } else {
            self.compressed.extend_from_slice(message);
            if is_incomplete_message(&self.compressed) {
                tracing::trace!("received incomplete message");
                return Ok(None);
            }
            &self.compressed
        };

        let processed_pre = self.processed();

        let mut processed = 0;

        // Decompressed message. `Vec::extend_from_slice` efficiently allocates
        // only what's necessary.
        let mut decompressed = Vec::new();

        loop {
            let produced_pre = self.produced();

            // Use Sync to ensure data is flushed to the buffer.
            self.decompress
                .decompress(
                    &message[processed..],
                    &mut self.buffer,
                    FlushDecompress::Sync,
                )
                .map_err(|source| CompressionError {
                    kind: CompressionErrorType::Decompressing,
                    source: Some(Box::new(source)),
                })?;

            processed = (self.processed() - processed_pre).try_into().unwrap();
            let produced = (self.produced() - produced_pre).try_into().unwrap();

            decompressed.extend_from_slice(&self.buffer[..produced]);

            // Break when message has been fully decompressed.
            if processed == message.len() {
                break;
            }

            tracing::trace!(bytes.compressed.remaining = message.len() - processed);
        }

        {
            #[allow(clippy::cast_precision_loss)]
            let total_percentage_compressed =
                self.processed() as f64 * 100.0 / self.produced() as f64;
            let total_percentage_saved = 100.0 - total_percentage_compressed;
            let total_kib_saved = (self.produced() - self.processed()) / 1024;

            tracing::trace!(
                bytes.compressed = message.len(),
                bytes.decompressed = decompressed.len(),
                total_percentage_saved,
                "{total_kib_saved} KiB saved in total",
            );
        }

        self.clear();

        String::from_utf8(decompressed)
            .map(Some)
            .map_err(CompressionError::from_utf8_error)
    }

    /// Reset the inflater's state.
    pub(crate) fn reset(&mut self) {
        self.compressed = Vec::new();
        self.decompress.reset(true);
    }

    /// Total number of bytes processed.
    pub fn processed(&self) -> u64 {
        self.decompress.total_in()
    }

    /// Total number of bytes produced.
    pub fn produced(&self) -> u64 {
        self.decompress.total_out()
    }
}

#[cfg(test)]
mod tests {
    use super::Inflater;

    const MESSAGE: &[u8] = &[
        120, 156, 52, 201, 65, 10, 131, 48, 16, 5, 208, 187, 252, 117, 82, 98, 169, 32, 115, 21,
        35, 50, 53, 67, 27, 136, 81, 226, 216, 82, 66, 238, 222, 110, 186, 123, 240, 42, 20, 148,
        207, 148, 12, 142, 63, 182, 29, 212, 57, 131, 0, 170, 120, 10, 23, 189, 11, 235, 28, 179,
        74, 121, 113, 2, 221, 186, 107, 255, 251, 89, 11, 47, 2, 26, 49, 122, 60, 88, 229, 205, 31,
        187, 151, 96, 87, 142, 217, 14, 253, 16, 60, 76, 245, 88, 227, 82, 182, 195, 131, 220, 197,
        181, 9, 83, 107, 95, 0, 0, 0, 255, 255,
    ];
    const OUTPUT: &str = r#"{"t":null,"s":null,"op":10,"d":{"heartbeat_interval":41250,"_trace":["[\"gateway-prd-main-858d\",{\"micros\":0.0}]"]}}"#;

    #[test]
    fn decompress_single_segment() {
        let mut inflator = Inflater::new();
        assert!(inflator.compressed.is_empty());
        assert_eq!(inflator.inflate(MESSAGE).unwrap(), Some(OUTPUT.to_owned()));

        assert!(inflator.compressed.is_empty());
    }

    #[test]
    fn decompress_split_message() {
        let mut inflator = Inflater::new();
        assert!(inflator.compressed.is_empty());
        assert_eq!(
            inflator.inflate(&MESSAGE[0..MESSAGE.len() / 2]).unwrap(),
            None
        );
        assert!(!inflator.compressed.is_empty());

        assert_eq!(
            inflator.inflate(&MESSAGE[MESSAGE.len() / 2..]).unwrap(),
            Some(OUTPUT.to_owned()),
        );
        assert!(inflator.compressed.is_empty());
    }

    #[test]
    fn invalid_is_none() {
        let mut inflator = Inflater::new();
        assert_eq!(inflator.inflate(&[]).unwrap(), None);

        assert_eq!(
            inflator.inflate(&MESSAGE[..MESSAGE.len() - 2]).unwrap(),
            None
        );
    }

    #[test]
    fn reset() {
        let mut inflator = Inflater::new();
        assert_eq!(
            inflator.inflate(&MESSAGE[..MESSAGE.len() - 2]).unwrap(),
            None
        );

        inflator.reset();
        assert_eq!(inflator.inflate(MESSAGE).unwrap(), Some(OUTPUT.to_owned()));
    }
}
