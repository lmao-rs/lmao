//! In-memory based default [`Ratelimiter`] implementation used in `twilight-http`.

mod bucket;

use self::bucket::{Bucket, BucketQueueTask};
use super::{
    ticket::{self, TicketNotifier},
    Bucket as InfoBucket, Ratelimiter,
};
use crate::{
    request::Path, GetBucketFuture, GetTicketFuture, HasBucketFuture, IsGloballyLockedFuture,
};
use futures_util::future;
use std::{
    collections::hash_map::{Entry, HashMap},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::sync::Mutex as AsyncMutex;

/// Global lock. We use a pair to avoid actually locking the mutex every check.
/// This allows futures to only wait on the global lock when a global ratelimit
/// is in place by, in turn, waiting for a guard, and then each immediately
/// dropping it.
#[derive(Debug, Default)]
struct GlobalLockPair(AsyncMutex<()>, AtomicBool);

impl GlobalLockPair {
    /// Set the global ratelimit as exhausted.
    pub fn lock(&self) {
        self.1.store(true, Ordering::Release);
    }

    /// Set the global ratelimit as no longer exhausted.
    pub fn unlock(&self) {
        self.1.store(false, Ordering::Release);
    }

    /// Whether the global ratelimit is exhausted.
    pub fn is_locked(&self) -> bool {
        self.1.load(Ordering::Relaxed)
    }
}

/// Default ratelimiter implementation used in twilight that
/// stores ratelimit information in an in-memory mapping.
///
/// This will meet most users' needs for simple ratelimiting,
/// but for multi-processed bots, consider either implementing
/// your own [`Ratelimiter`] that uses a shared storage backend
/// or use the [HTTP proxy].
///
/// [HTTP proxy]: https://twilight.rs/chapter_2_multi-serviced_approach.html#http-proxy-ratelimiting
#[derive(Clone, Debug, Default)]
pub struct InMemoryRatelimiter {
    /// Mapping of [`Path`]s to their associated [`Bucket`]s.
    buckets: Arc<Mutex<HashMap<Path, Arc<Bucket>>>>,
    /// Global ratelimit data.
    global: Arc<GlobalLockPair>,
}

impl InMemoryRatelimiter {
    /// Create a new in-memory ratelimiter.
    ///
    /// This is used by HTTP client to queue requests in order to avoid
    /// hitting the API's ratelimits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the [`Bucket`] for a [`Path`] and queue for a [`TicketNotifier`]
    /// to be notified when a request may be performed.
    fn entry(&self, path: Path, tx: TicketNotifier) -> (Arc<Bucket>, bool) {
        let mut buckets = self.buckets.lock().expect("buckets poisoned");

        match buckets.entry(path.clone()) {
            Entry::Occupied(bucket) => {
                tracing::debug!("got existing bucket: {:?}", path);

                let bucket = bucket.into_mut();
                bucket.queue.push(tx);

                tracing::debug!("added request into bucket queue: {:?}", path);

                (Arc::clone(bucket), false)
            }
            Entry::Vacant(entry) => {
                tracing::debug!("making new bucket for path: {:?}", path);

                let bucket = Bucket::new(path);
                bucket.queue.push(tx);

                let bucket = Arc::new(bucket);
                entry.insert(Arc::clone(&bucket));

                (bucket, true)
            }
        }
    }
}

impl Ratelimiter for InMemoryRatelimiter {
    fn bucket(&self, path: &Path) -> GetBucketFuture {
        self.buckets
            .lock()
            .expect("buckets poisoned")
            .get(path)
            .map_or_else(
                || Box::pin(future::ok(None)),
                |bucket| {
                    let started_at = bucket.started_at.lock().expect("bucket poisoned");

                    Box::pin(future::ok(Some(InfoBucket {
                        limit: bucket.limit(),
                        remaining: bucket.remaining(),
                        reset_after: Duration::from_millis(bucket.reset_after()),
                        started_at: *started_at,
                    })))
                },
            )
    }

    fn globally_locked(&self) -> IsGloballyLockedFuture {
        Box::pin(future::ok(self.global.is_locked()))
    }

    fn has(&self, path: &Path) -> HasBucketFuture {
        let has = self
            .buckets
            .lock()
            .expect("buckets poisoned")
            .contains_key(path);

        Box::pin(future::ok(has))
    }

    fn ticket(&self, path: Path) -> GetTicketFuture {
        tracing::debug!("getting bucket for path: {:?}", path);

        let (tx, rx) = ticket::channel();
        let (bucket, fresh) = self.entry(path.clone(), tx);

        if fresh {
            tokio::spawn(
                BucketQueueTask::new(
                    bucket,
                    Arc::clone(&self.buckets),
                    Arc::clone(&self.global),
                    path,
                )
                .run(),
            );
        }

        Box::pin(future::ok(rx))
    }
}
