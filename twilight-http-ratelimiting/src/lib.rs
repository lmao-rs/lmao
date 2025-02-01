#![doc = include_str!("../README.md")]
#![warn(
    clippy::missing_const_for_fn,
    clippy::missing_docs_in_private_items,
    clippy::pedantic,
    missing_docs,
    unsafe_code
)]
#![allow(clippy::module_name_repetitions, clippy::must_use_candidate)]

pub mod headers;
pub mod request;

pub use self::{
    headers::RatelimitHeaders,
    request::{Method, Path},
};

use hashbrown::hash_table;
use std::{
    collections::{hash_map::Entry, HashMap, VecDeque},
    future::{poll_fn, Future},
    hash::{BuildHasher as _, Hash, Hasher as _, RandomState},
    mem,
    num::ParseIntError,
    pin::{self, Pin},
    str::{self, FromStr},
    task::{Context, Poll},
};
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinSet,
    time::{self, Duration, Instant},
};
use tokio_util::time::delay_queue::{DelayQueue, Key};

use crate::headers::{HeaderName, HeaderParsingError, HeaderParsingErrorType, HeaderType};

///
#[derive(Debug)]
pub struct Headers {
    bucket: Box<str>,
    limit: u16,
    remaining: u16,
    reset_after: u32,
}

impl Headers {
    ///
    pub fn from_pairs<'a>(
        headers: impl Iterator<Item = (&'a str, &'a [u8])>,
    ) -> Result<Option<Self>, HeaderParsingError> {
        /// Parse a value expected to be a float.
        fn header_float(name: HeaderName, value: &[u8]) -> Result<f64, HeaderParsingError> {
            let text = header_str(name, value)?;

            let end = text.parse().map_err(|source| HeaderParsingError {
                kind: HeaderParsingErrorType::Parsing {
                    kind: HeaderType::Float,
                    name,
                    value: text.to_owned(),
                },
                source: Some(Box::new(source)),
            })?;

            Ok(end)
        }

        /// Parse a value expected to be an integer.
        fn header_int<T: FromStr<Err = ParseIntError>>(
            name: HeaderName,
            value: &[u8],
        ) -> Result<T, HeaderParsingError> {
            let text = header_str(name, value)?;

            let end = text.parse().map_err(|source| HeaderParsingError {
                kind: HeaderParsingErrorType::Parsing {
                    kind: HeaderType::Integer,
                    name,
                    value: text.to_owned(),
                },
                source: Some(Box::new(source)),
            })?;

            Ok(end)
        }

        /// Parse a value expected to be a UTF-8 valid string.
        fn header_str(name: HeaderName, value: &[u8]) -> Result<&str, HeaderParsingError> {
            let text = str::from_utf8(value)
                .map_err(|source| HeaderParsingError::not_utf8(name, value.to_owned(), source))?;

            Ok(text)
        }

        let mut bucket = None;
        let mut limit = None;
        let mut remaining = None;
        let mut reset_after = None;

        for (name, value) in headers {
            match name {
                HeaderName::BUCKET => {
                    bucket.replace(header_str(HeaderName::Bucket, value)?);
                }
                HeaderName::LIMIT => {
                    limit.replace(header_int(HeaderName::Limit, value)?);
                }
                HeaderName::REMAINING => {
                    remaining.replace(header_int(HeaderName::Remaining, value)?);
                }
                HeaderName::RESET_AFTER => {
                    let reset_after_value = header_float(HeaderName::ResetAfter, value)?;

                    #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
                    reset_after.replace((reset_after_value * 1000.).ceil() as u32);
                }
                _ => {}
            }
        }

        if let Some(bucket) = bucket {
            if let Some(limit) = limit {
                if let Some(remaining) = remaining {
                    if let Some(reset_after) = reset_after {
                        return Ok(Some(Headers {
                            bucket: bucket.to_owned().into_boxed_str(),
                            limit,
                            remaining,
                            reset_after,
                        }));
                    }
                }
            }
        }

        Ok(None)
    }
}

/// Permit to send a Discord HTTP API request.
#[derive(Debug)]
#[must_use = "dropping the permit immediately cancels itself"]
pub struct Permit(oneshot::Sender<Option<Headers>>);

impl Permit {
    /// Update the rate limiter based on the response headers.
    ///
    /// Non-completed permits are regarded as cancelled, so only call this
    /// on receiving a response.
    pub fn complete(self, headers: Option<Headers>) {
        _ = self.0.send(headers);
    }
}

/// Future that completes when a permit is ready.
#[derive(Debug)]
pub struct PermitFuture(oneshot::Receiver<oneshot::Sender<Option<Headers>>>);

impl Future for PermitFuture {
    type Output = Permit;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0)
            .poll(cx)
            .map(|r| Permit(r.expect("actor is alive")))
    }
}

/// Future that completes when a permit is ready if it passed the predicate.
#[derive(Debug)]
pub struct MaybePermitFuture(oneshot::Receiver<oneshot::Sender<Option<Headers>>>);

impl Future for MaybePermitFuture {
    type Output = Option<Permit>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx).map(|r| r.ok().map(Permit))
    }
}

/// Pending permit state.
#[derive(Debug)]
struct Request {
    /// Path the permit is for, mapping to a [`Queue`].
    path: Path,
    /// Completion handle for the associated [`PermitFuture`].
    notifier: oneshot::Sender<oneshot::Sender<Option<Headers>>>,
}

/// Grouped pending permits holder snapshot.
///
/// Grouping may be done by path or bucket, based on previous permits' response
/// headers.
#[non_exhaustive]
#[derive(Debug)]
pub struct QueueSnapshot {
    /// Number of already queued permits.
    pub len: usize,
    /// Time at which the bucket resets.
    pub reset_at: Instant,
    /// Total number of permits until the queue becomes exhausted.
    pub limit: u16,
    /// Number of remaining permits until the queue becomes exhausted.
    pub remaining: u16,
}

/// Grouped pending permits holder.
///
/// Grouping may be done by path or bucket, based on previous permits' response
/// headers.
///
/// Queue may not be rate limited, in which case the values of [`limit`][Self::limit],
/// [`reset`][Self::reset], and [`remaining`][Self::remaining] are unused.
#[derive(Debug)]
struct Queue {
    /// Whether the queue is handling outstanding permits.
    ///
    /// Note that this is `true` when globally exhausted and `false` when
    /// the queue is exhausted.
    idle: bool,
    /// List of pending permit requests.
    inner: VecDeque<Request>,
    /// Total number of permits until the queue becomes exhausted.
    limit: u16,
    /// Key mapping to an [`Instant`] when the queue resets, if rate limited.
    reset: Option<Key>,
    /// Number of remaining permits until the queue becomes exhausted.
    remaining: u16,
}

impl Queue {
    /// Create a new non rate limited queue.
    const fn new() -> Self {
        Self {
            idle: true,
            inner: VecDeque::new(),
            limit: 0,
            reset: None,
            remaining: 0,
        }
    }

    /// Completes and returns the first queued permit, unless the queue is
    /// globally exhausted.
    fn pop(
        &mut self,
        globally_exhausted: bool,
    ) -> Option<(Path, oneshot::Receiver<Option<Headers>>)> {
        let (mut tx, rx) = oneshot::channel();
        while self
            .inner
            .front()
            .is_some_and(|req| req.path.is_interaction() || !globally_exhausted)
        {
            let req = self.inner.pop_front().unwrap();
            match req.notifier.send(tx) {
                Ok(()) => return Some((req.path, rx)),
                Err(recover) => tx = recover,
            }
        }
        self.idle = true;

        None
    }
}

/// Discord HTTP client API rate limiter.
///
/// The rate limiter runs an associated actor task to concurrently handle permit
/// requests and responses.
///
/// Cloning a rate limiter increments just the amount of senders for the actor.
/// The actor completes when there are no senders and pending permits left.
#[derive(Clone, Debug)]
pub struct RateLimiter {
    /// Actor message sender.
    tx: mpsc::UnboundedSender<(
        Request,
        Option<Box<dyn FnOnce(Option<QueueSnapshot>) -> bool + Send>>,
    )>,
}

impl RateLimiter {
    /// Create a new rate limiter with custom settings.
    pub fn new(global_limit: u16) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(runner(global_limit, rx));

        Self { tx }
    }

    /// Await a single permit for this path.
    ///
    /// Permits are queued per path in the order they were requested.
    #[allow(clippy::missing_panics_doc)]
    pub fn acquire(&self, path: Path) -> PermitFuture {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send((Request { path, notifier: tx }, None))
            .expect("actor is alive");

        PermitFuture(rx)
    }

    /// Await a single permit for this path, but only if the predicate evaluates
    /// to `true`.
    ///
    /// Permits are queued per path in the order they were requested.
    ///
    /// Note that the predicate is asynchronously called in the actor task.
    #[allow(clippy::missing_panics_doc)]
    pub fn acquire_if<P>(&self, path: Path, predicate: P) -> MaybePermitFuture
    where
        P: FnOnce(Option<QueueSnapshot>) -> bool + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send((Request { path, notifier: tx }, Some(Box::new(predicate))))
            .expect("actor is alive");

        MaybePermitFuture(rx)
    }

    /// Retrieve the [`QueueSnapshot`] for this path.
    ///
    /// The snapshot is internally retrieved via [`acquire_if`][Self::acquire_if].
    pub async fn snapshot(&self, path: Path) -> Option<QueueSnapshot> {
        let (tx, rx) = oneshot::channel();
        self.acquire_if(path, |snapshot| {
            _ = tx.send(snapshot);
            false
        })
        .await;

        rx.await.unwrap()
    }
}

impl Default for RateLimiter {
    /// Create a new rate limiter with Discord's default global limit.
    ///
    /// Currently this is `50`.
    fn default() -> Self {
        Self::new(50)
    }
}

/// Duration from the first globally limited request until the remaining count
/// resets to the global limit count.
const GLOBAL_LIMIT_PERIOD: Duration = Duration::from_secs(1);

/// Rate limiter actor runner.
#[allow(clippy::too_many_lines)]
async fn runner(
    global_limit: u16,
    mut rx: mpsc::UnboundedReceiver<(
        Request,
        Option<Box<dyn FnOnce(Option<QueueSnapshot>) -> bool + Send>>,
    )>,
) {
    let mut global_remaining = global_limit;
    let mut global_timer = pin::pin!(time::sleep(Duration::ZERO));

    let mut buckets = HashMap::<Path, Box<str>>::new();
    let mut in_flight =
        JoinSet::<(Path, Result<Option<Headers>, oneshot::error::RecvError>)>::new();

    let mut reset = DelayQueue::<u64>::new();
    let mut queues = hashbrown::HashTable::<(u64, Queue)>::new();
    let hasher = RandomState::new();

    macro_rules! on_permit {
        () => {
            // Global must be decremented before sending the message as, unlike the bucket,
            // it is not blocked until this request receives response headers.
            global_remaining -= 1;
            if global_remaining == global_limit - 1 {
                global_timer
                    .as_mut()
                    .reset(Instant::now() + GLOBAL_LIMIT_PERIOD);
            } else if global_remaining == 0 {
                let now = Instant::now();
                let reset_after = now.saturating_duration_since(global_timer.deadline());
                if reset_after.is_zero() {
                    global_remaining = global_limit - 1;
                    global_timer.as_mut().reset(now + GLOBAL_LIMIT_PERIOD);
                } else {
                    tracing::info!(?reset_after, "globally exhausted");
                }
            }
        };
    }

    #[allow(clippy::ignored_unit_patterns)]
    loop {
        tokio::select! {
            biased;
            _ = &mut global_timer, if global_remaining == 0 => {
                global_remaining = global_limit;
                for (_, queue) in queues.iter_mut().filter(|(_, queue)| queue.idle) {
                    if let Some((path, rx)) = queue.pop(global_remaining == 0) {
                        queue.idle = false;
                        tracing::debug!(?path, "permitted");
                        on_permit!();
                        in_flight.spawn(async move { (path, rx.await) });
                    }
                }
            }
            Some(hash) = poll_fn(|cx| reset.poll_expired(cx)) => {
                let hash = hash.into_inner();
                let (_, queue) = queues.find_mut(hash, |val| val.0 == hash).expect("hash is unchanged");
                queue.reset = None;
                let maybe_in_flight = queue.remaining != 0;
                if maybe_in_flight { continue; }

                if let Some((path, rx)) = queue.pop(global_remaining == 0) {
                    tracing::debug!(?path, "permitted");
                    if !path.is_interaction() {
                        on_permit!();
                    }
                    in_flight.spawn(async move { (path, rx.await) });
                }
            }
            Some(response) = in_flight.join_next() => {
                let (path, headers) = response.expect("task should not fail");

                let mut builder = hasher.build_hasher();
                path.hash_components(&mut builder);

                let queue = match headers {
                    Ok(Some(headers)) => {
                        let _span = tracing::info_span!("headers", ?path).entered();
                        tracing::trace!(?headers);
                        let bucket = headers.bucket;

                        bucket.hash(&mut builder);
                        let hash = builder.finish();
                        let queue = match buckets.entry(path) {
                            Entry::Occupied(mut entry) if *entry.get() != bucket => {
                                let mut old_builder = hasher.build_hasher();
                                entry.key().hash_components(&mut old_builder);
                                entry.get().hash(&mut old_builder);
                                let old_hash = old_builder.finish();

                                tracing::debug!(new = hash, previous = old_hash, "bucket changed");

                                *entry.get_mut() = bucket;
                                let path = entry.key();

                                let mut entry = queues.find_entry(old_hash, |a| a.0 == old_hash).expect("hash is unchanged");
                                let shared = entry.get().1.inner.iter().any(|req| req.path != *path);
                                let queue = if shared {
                                    let mut inner = VecDeque::new();
                                    for req in mem::take(&mut entry.get_mut().1.inner) {
                                        if req.path == *path {
                                            inner.push_back(req);
                                        } else {
                                            entry.get_mut().1.inner.push_back(req);
                                        }
                                    }

                                    let old_queue = &mut entry.get_mut().1;
                                    if let Some((path, rx)) = old_queue.pop(global_remaining == 0) {
                                        tracing::debug!(?path, "permitted");
                                        if !path.is_interaction() {
                                            on_permit!();
                                        }
                                        in_flight.spawn(async move { (path, rx.await) });
                                    }

                                    Queue {
                                        idle: false,
                                        inner,
                                        limit: 0,
                                        reset: None,
                                        remaining: 0,
                                    }
                                } else {
                                    entry.remove().0.1
                                };

                                match queues.entry(hash, |a| a.0 == hash, |a| a.0) {
                                    hash_table::Entry::Occupied(mut entry) => {
                                        entry.get_mut().1.inner.extend(queue.inner);
                                        &mut entry.into_mut().1
                                    }
                                    hash_table::Entry::Vacant(entry) => &mut entry.insert((hash, queue)).into_mut().1,
                                }
                            }
                            Entry::Occupied(_) => &mut queues.find_mut(hash, |a| a.0 == hash).unwrap().1,
                            Entry::Vacant(entry) => {
                                let mut old_builder = hasher.build_hasher();
                                entry.key().hash_components(&mut old_builder);
                                let old_hash = old_builder.finish();

                                tracing::debug!(hash, "bucket assigned");
                                entry.insert(bucket);

                                let ((_, queue), _) = queues.find_entry(old_hash, |a| a.0 == old_hash).expect("hash is unchanged").remove();
                                &mut queues.insert_unique(hash, (hash, queue), |a| a.0).into_mut().1
                            },
                        };

                        queue.limit = headers.limit;
                        queue.remaining = headers.remaining;
                        let reset_after = Duration::from_millis(headers.reset_after.into());
                        if let Some(key) = &queue.reset {
                            reset.reset(key, reset_after);
                        } else {
                            queue.reset = Some(reset.insert(hash, reset_after));
                        }
                        if queue.remaining == 0 {
                            tracing::info!(?reset_after, "exhausted");
                            queue.idle = true;
                            continue;
                        }

                        queue
                    }
                    Ok(None) => {
                        if let Some(bucket) = buckets.get(&path) {
                            bucket.hash(&mut builder);
                        }
                        let hash = builder.finish();

                        &mut queues.find_mut(hash, |a| a.0 == hash).expect("hash is unchanged").1
                    }
                    Err(_) => {
                        tracing::debug!(?path, "cancelled");
                        if global_remaining != global_limit {
                            global_remaining += 1;
                        }

                        if let Some(bucket) = buckets.get(&path) {
                            bucket.hash(&mut builder);
                        }
                        let hash = builder.finish();

                        &mut queues.find_mut(hash, |a| a.0 == hash).expect("hash is unchanged").1
                    }
                };

                if let Some((path, rx)) = queue.pop(global_remaining == 0) {
                    tracing::debug!(?path, "permitted");
                    if !path.is_interaction() {
                        on_permit!();
                    }
                    in_flight.spawn(async move { (path, rx.await) });
                }
            }
            Some((msg, predicate)) = rx.recv() => {
                let mut builder = hasher.build_hasher();
                msg.path.hash_components(&mut builder);

                let (_, queue) = if let Some(bucket) = buckets.get(&msg.path) {
                    bucket.hash(&mut builder);
                    let hash = builder.finish();
                    queues.find_mut(hash, |a| a.0 == hash).unwrap()
                } else {
                    let hash = builder.finish();
                    queues.entry(hash, |a| a.0 == hash, |a| a.0).or_insert_with(|| (hash, Queue::new())).into_mut()
                };

                let snapshot = queue.reset.map(|key| QueueSnapshot {
                    len: queue.inner.len(),
                    reset_at: reset.deadline(&key),
                    limit: queue.limit,
                    remaining: queue.remaining,
                });

                if predicate.is_some_and(|p| !p(snapshot)) {
                    drop(msg);
                } else if !queue.idle || (!msg.path.is_interaction() && global_remaining == 0) {
                    queue.inner.push_back(msg);
                } else {
                    let (tx, rx) = oneshot::channel();
                    if msg.notifier.send(tx).is_ok() {
                        queue.idle = false;
                        tracing::debug!(path = ?msg.path, "permitted");
                        if !msg.path.is_interaction() {
                            on_permit!();
                        }
                        in_flight.spawn(async move { (msg.path, rx.await) });
                    }
                }
            }
            else => break,
        }
    }
}
