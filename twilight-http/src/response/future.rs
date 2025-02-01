use super::{Response, StatusCode};
use crate::{
    api_error::ApiError,
    error::{Error, ErrorType},
};
use http::StatusCode as HyperStatusCode;
use hyper_util::client::legacy::ResponseFuture as HyperResponseFuture;
use std::{
    future::Future,
    marker::PhantomData,
    mem,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{self, Timeout};
use twilight_http_ratelimiting::{Headers, Permit, PermitFuture};

type Output<T> = Result<Response<T>, Error>;

enum InnerPoll<T> {
    Advance(ResponseFutureStage),
    Pending(ResponseFutureStage),
    Ready(Output<T>),
}

struct Chunking {
    future: Pin<Box<dyn Future<Output = Result<Vec<u8>, Error>> + Send + Sync + 'static>>,
    status: HyperStatusCode,
}

impl Chunking {
    fn poll<T>(mut self, cx: &mut Context<'_>) -> InnerPoll<T> {
        let bytes = match Pin::new(&mut self.future).poll(cx) {
            Poll::Ready(Ok(bytes)) => bytes,
            Poll::Ready(Err(source)) => return InnerPoll::Ready(Err(source)),
            Poll::Pending => return InnerPoll::Pending(ResponseFutureStage::Chunking(self)),
        };

        let error = match crate::json::from_bytes::<ApiError>(&bytes) {
            Ok(error) => error,
            Err(source) => {
                return InnerPoll::Ready(Err(Error {
                    kind: ErrorType::Parsing { body: bytes },
                    source: Some(Box::new(source)),
                }));
            }
        };

        InnerPoll::Ready(Err(Error {
            kind: ErrorType::Response {
                body: bytes,
                error,
                status: StatusCode::new(self.status.as_u16()),
            },
            source: None,
        }))
    }
}

struct Failed {
    source: Error,
}

impl Failed {
    fn poll<T>(self, _: &mut Context<'_>) -> InnerPoll<T> {
        InnerPoll::Ready(Err(self.source))
    }
}

struct InFlight {
    future: Pin<Box<Timeout<HyperResponseFuture>>>,
    invalid_token: Option<Arc<AtomicBool>>,
    tx: Option<Permit>,
}

impl InFlight {
    fn poll<T>(mut self, cx: &mut Context<'_>) -> InnerPoll<T> {
        let resp = match Pin::new(&mut self.future).poll(cx) {
            Poll::Ready(Ok(Ok(resp))) => resp,
            Poll::Ready(Ok(Err(source))) => {
                return InnerPoll::Ready(Err(Error {
                    kind: ErrorType::RequestError,
                    source: Some(Box::new(source)),
                }))
            }
            Poll::Ready(Err(source)) => {
                return InnerPoll::Ready(Err(Error {
                    kind: ErrorType::RequestTimedOut,
                    source: Some(Box::new(source)),
                }))
            }
            Poll::Pending => return InnerPoll::Pending(ResponseFutureStage::InFlight(self)),
        };

        // If the API sent back an Unauthorized response, then the client's
        // configured token is permanently invalid and future requests must be
        // ignored to avoid API bans.
        if resp.status() == HyperStatusCode::UNAUTHORIZED {
            if let Some(invalid_token) = self.invalid_token {
                invalid_token.store(true, Ordering::Relaxed);
            }
        }

        if let Some(tx) = self.tx {
            let headers = resp
                .headers()
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_bytes()));

            match Headers::from_pairs(headers) {
                Ok(v) => tx.complete(v),
                Err(source) => {
                    tracing::warn!("header parsing failed: {source:?}; {resp:?}");

                    tx.complete(None);
                }
            }
        }

        let status = resp.status();

        if status.is_success() {
            #[cfg(feature = "decompression")]
            let mut resp = resp;
            // Inaccurate since end-users can only access the decompressed body.
            #[cfg(feature = "decompression")]
            resp.headers_mut().remove(http::header::CONTENT_LENGTH);

            return InnerPoll::Ready(Ok(Response::new(resp)));
        }

        match status {
            HyperStatusCode::TOO_MANY_REQUESTS => {
                tracing::warn!("429 response: {resp:?}");
            }
            HyperStatusCode::SERVICE_UNAVAILABLE => {
                return InnerPoll::Ready(Err(Error {
                    kind: ErrorType::ServiceUnavailable { response: resp },
                    source: None,
                }));
            }
            _ => {}
        }

        let fut = async {
            Response::<()>::new(resp)
                .bytes()
                .await
                .map_err(|source| Error {
                    kind: ErrorType::ChunkingResponse,
                    source: Some(Box::new(source)),
                })
        };

        InnerPoll::Advance(ResponseFutureStage::Chunking(Chunking {
            future: Box::pin(fut),
            status,
        }))
    }
}

struct RatelimitQueue {
    invalid_token: Option<Arc<AtomicBool>>,
    response_future: HyperResponseFuture,
    timeout: Duration,
    pre_flight_check: Option<Box<dyn FnOnce() -> bool + Send + 'static>>,
    rx: PermitFuture,
}

impl RatelimitQueue {
    fn poll<T>(mut self, cx: &mut Context<'_>) -> InnerPoll<T> {
        let Poll::Ready(tx) = Pin::new(&mut self.rx).poll(cx) else {
            return InnerPoll::Pending(ResponseFutureStage::RatelimitQueue(self));
        };

        if let Some(pre_flight_check) = self.pre_flight_check {
            if !pre_flight_check() {
                return InnerPoll::Ready(Err(Error {
                    kind: ErrorType::RequestCanceled,
                    source: None,
                }));
            }
        }

        InnerPoll::Advance(ResponseFutureStage::InFlight(InFlight {
            future: Box::pin(time::timeout(self.timeout, self.response_future)),
            invalid_token: self.invalid_token,
            tx: Some(tx),
        }))
    }
}

enum ResponseFutureStage {
    Chunking(Chunking),
    Completed,
    Failed(Failed),
    InFlight(InFlight),
    RatelimitQueue(RatelimitQueue),
}

/// Future that will resolve to a [`Response`].
///
/// # Canceling a response future pre-flight
///
/// Response futures can be canceled pre-flight via
/// [`ResponseFuture::set_pre_flight`]. This allows you to cancel requests that
/// are no longer necessary once they have been cleared by the ratelimit queue,
/// which may be necessary in scenarios where requests are being spammed. Refer
/// to its documentation for more information.
///
/// # Errors
///
/// Returns an [`ErrorType::Json`] error type if serializing the response body
/// of the request failed.
///
/// Returns an [`ErrorType::Parsing`] error type if the request failed and the
/// error in the response body could not be deserialized.
///
/// Returns an [`ErrorType::RequestCanceled`] error type if the request was
/// canceled by the user.
///
/// Returns an [`ErrorType::RequestError`] error type if creating the request
/// failed.
///
/// Returns an [`ErrorType::RequestTimedOut`] error type if the request timed
/// out. The timeout value is configured via [`ClientBuilder::timeout`].
///
/// Returns an [`ErrorType::Response`] error type if the request failed.
///
/// Returns an [`ErrorType::ServiceUnavailable`] error type if the Discord API
/// is unavailable.
///
/// [`ClientBuilder::timeout`]: crate::client::ClientBuilder::timeout
/// [`ErrorType::Json`]: crate::error::ErrorType::Json
/// [`ErrorType::Parsing`]: crate::error::ErrorType::Parsing
/// [`ErrorType::RequestCanceled`]: crate::error::ErrorType::RequestCanceled
/// [`ErrorType::RequestError`]: crate::error::ErrorType::RequestError
/// [`ErrorType::RequestTimedOut`]: crate::error::ErrorType::RequestTimedOut
/// [`ErrorType::Response`]: crate::error::ErrorType::Response
/// [`ErrorType::ServiceUnavailable`]: crate::error::ErrorType::ServiceUnavailable
/// [`Response`]: super::Response
#[must_use = "futures do nothing unless you `.await` or poll them"]
pub struct ResponseFuture<T> {
    phantom: PhantomData<T>,
    stage: ResponseFutureStage,
}

impl<T> ResponseFuture<T> {
    pub(crate) const fn new(
        future: Pin<Box<Timeout<HyperResponseFuture>>>,
        invalid_token: Option<Arc<AtomicBool>>,
    ) -> Self {
        Self {
            phantom: PhantomData,
            stage: ResponseFutureStage::InFlight(InFlight {
                future,
                invalid_token,
                tx: None,
            }),
        }
    }

    /// Set a function to call after clearing the ratelimiter but prior to
    /// sending the request to determine if the request is still valid.
    ///
    /// This function will be a no-op if the request has failed, has already
    /// passed the ratelimiter, or if there is no ratelimiter configured.
    ///
    /// Returns whether the pre flight function was set.
    ///
    /// # Examples
    ///
    /// Delete a message, but immediately before sending the request check if
    /// the request should still be sent:
    ///
    /// ```no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use std::{
    ///     collections::HashSet,
    ///     env,
    ///     future::IntoFuture,
    ///     sync::{Arc, Mutex},
    /// };
    /// use twilight_http::{error::ErrorType, Client};
    /// use twilight_model::id::Id;
    ///
    /// let channel_id = Id::new(1);
    /// let message_id = Id::new(2);
    ///
    /// let channels_ignored = {
    ///     let mut map = HashSet::new();
    ///     map.insert(channel_id);
    ///
    ///     Arc::new(Mutex::new(map))
    /// };
    ///
    /// let client = Client::new(env::var("DISCORD_TOKEN")?);
    /// let mut req = client.delete_message(channel_id, message_id).into_future();
    ///
    /// let channels_ignored_clone = channels_ignored.clone();
    /// req.set_pre_flight(Box::new(move || {
    ///     // imagine you have some logic here to external state that checks
    ///     // whether the request should still be performed
    ///     let channels_ignored = channels_ignored_clone.lock().expect("channels poisoned");
    ///
    ///     !channels_ignored.contains(&channel_id)
    /// }));
    ///
    /// // the pre-flight check will cancel the request
    /// assert!(matches!(
    ///     req.await.unwrap_err().kind(),
    ///     ErrorType::RequestCanceled,
    /// ));
    /// # Ok(()) }
    /// ```
    pub fn set_pre_flight(
        &mut self,
        pre_flight: Box<dyn FnOnce() -> bool + Send + 'static>,
    ) -> bool {
        if let ResponseFutureStage::RatelimitQueue(queue) = &mut self.stage {
            queue.pre_flight_check = Some(pre_flight);

            true
        } else {
            false
        }
    }

    pub(crate) const fn error(source: Error) -> Self {
        Self {
            phantom: PhantomData,
            stage: ResponseFutureStage::Failed(Failed { source }),
        }
    }

    pub(crate) fn ratelimit(
        invalid_token: Option<Arc<AtomicBool>>,
        response_future: HyperResponseFuture,
        timeout: Duration,
        wait_for_sender: PermitFuture,
    ) -> Self {
        Self {
            phantom: PhantomData,
            stage: ResponseFutureStage::RatelimitQueue(RatelimitQueue {
                invalid_token,
                response_future,
                timeout,
                pre_flight_check: None,
                rx: wait_for_sender,
            }),
        }
    }
}

impl<T: Unpin> Future for ResponseFuture<T> {
    type Output = Output<T>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            let stage = mem::replace(&mut self.stage, ResponseFutureStage::Completed);

            let result = match stage {
                ResponseFutureStage::Chunking(chunking) => chunking.poll(cx),
                ResponseFutureStage::Completed => panic!("future already completed"),
                ResponseFutureStage::Failed(failed) => failed.poll(cx),
                ResponseFutureStage::InFlight(in_flight) => in_flight.poll(cx),
                ResponseFutureStage::RatelimitQueue(queue) => queue.poll(cx),
            };

            match result {
                InnerPoll::Advance(stage) => {
                    self.stage = stage;
                }
                InnerPoll::Pending(stage) => {
                    self.stage = stage;

                    return Poll::Pending;
                }
                InnerPoll::Ready(output) => {
                    self.stage = ResponseFutureStage::Completed;

                    return Poll::Ready(output);
                }
            }
        }
    }
}
