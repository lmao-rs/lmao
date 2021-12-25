use super::{Response, StatusCode};
use crate::{
    api_error::ApiError,
    error::{Error, ErrorType},
};
use hyper::{client::ResponseFuture as HyperResponseFuture, StatusCode as HyperStatusCode};
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
use twilight_http_ratelimiting::{ticket::TicketSender, RatelimitHeaders, WaitForTicketFuture};
use twilight_model::id::GuildId;

pub enum InvalidToken {
    Forget,
    Remember(Arc<AtomicBool>),
}

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
            Poll::Pending => {
                return InnerPoll::Pending(ResponseFutureStage::Chunking(Self {
                    future: self.future,
                    status: self.status,
                }))
            }
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

        #[cfg(feature = "tracing")]
        if let ApiError::General(ref general) = error {
            use crate::api_error::ErrorCode;

            if let ErrorCode::Other(num) = general.code {
                tracing::debug!("got unknown API error code variant: {}; {:?}", num, error);
            }
        }

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
    guild_id: Option<GuildId>,
    invalid_token: InvalidToken,
    tx: Option<TicketSender>,
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
            Poll::Pending => {
                return InnerPoll::Pending(ResponseFutureStage::InFlight(Self {
                    future: self.future,
                    guild_id: self.guild_id,
                    invalid_token: self.invalid_token,
                    tx: self.tx,
                }))
            }
        };

        // If the API sent back an Unauthorized response, then the client's
        // configured token is permanently invalid and future requests must be
        // ignored to avoid API bans.
        if resp.status() == HyperStatusCode::UNAUTHORIZED {
            if let InvalidToken::Remember(state) = self.invalid_token {
                state.store(true, Ordering::Relaxed);
            }
        }

        if let Some(tx) = self.tx {
            let headers = resp
                .headers()
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_bytes()));

            match RatelimitHeaders::from_pairs(headers) {
                Ok(v) => {
                    let _res = tx.headers(Some(v));
                }
                #[cfg_attr(not(feature = "tracing"), allow(unused_variables))]
                Err(source) => {
                    #[cfg(feature = "tracing")]
                    tracing::warn!("header parsing failed: {:?}; {:?}", source, resp);

                    let _res = tx.headers(None);
                }
            }
        }

        let status = resp.status();

        if status.is_success() {
            #[cfg(feature = "decompression")]
            let mut resp = resp;
            // Inaccurate since end-users can only access the decompressed body.
            #[cfg(feature = "decompression")]
            resp.headers_mut().remove(hyper::header::CONTENT_LENGTH);

            let mut response = Response::new(resp);

            if let Some(guild_id) = self.guild_id {
                response.set_guild_id(guild_id);
            }

            return InnerPoll::Ready(Ok(response));
        }

        match status {
            HyperStatusCode::TOO_MANY_REQUESTS => {
                #[cfg(feature = "tracing")]
                tracing::warn!("429 response: {:?}", resp)
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
    guild_id: Option<GuildId>,
    invalid_token: InvalidToken,
    pre_flight_check: Option<Box<dyn FnOnce() -> bool + Send + 'static>>,
    request_timeout: Duration,
    response_future: HyperResponseFuture,
    wait_for_sender: WaitForTicketFuture,
}

impl RatelimitQueue {
    fn poll<T>(mut self, cx: &mut Context<'_>) -> InnerPoll<T> {
        let tx = match Pin::new(&mut self.wait_for_sender).poll(cx) {
            Poll::Ready(Ok(tx)) => tx,
            Poll::Ready(Err(source)) => {
                return InnerPoll::Ready(Err(Error {
                    kind: ErrorType::RatelimiterTicket,
                    source: Some(source),
                }))
            }
            Poll::Pending => {
                return InnerPoll::Pending(ResponseFutureStage::RatelimitQueue(Self {
                    guild_id: self.guild_id,
                    invalid_token: self.invalid_token,
                    pre_flight_check: self.pre_flight_check,
                    request_timeout: self.request_timeout,
                    response_future: self.response_future,
                    wait_for_sender: self.wait_for_sender,
                }))
            }
        };

        if let Some(pre_flight_check) = self.pre_flight_check {
            if !pre_flight_check() {
                return InnerPoll::Advance(ResponseFutureStage::Failed(Failed {
                    source: Error {
                        kind: ErrorType::RequestCanceled,
                        source: None,
                    },
                }));
            }
        }

        InnerPoll::Advance(ResponseFutureStage::InFlight(InFlight {
            future: Box::pin(time::timeout(self.request_timeout, self.response_future)),
            guild_id: self.guild_id,
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
    pub(crate) fn new(
        invalid_token: InvalidToken,
        future: Timeout<HyperResponseFuture>,
        ratelimit_tx: Option<TicketSender>,
    ) -> Self {
        Self {
            phantom: PhantomData,
            stage: ResponseFutureStage::InFlight(InFlight {
                future: Box::pin(future),
                guild_id: None,
                invalid_token,
                tx: ratelimit_tx,
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
    /// use std::{collections::HashSet, env, sync::{Arc, Mutex}};
    /// use twilight_http::{error::ErrorType, Client};
    /// use twilight_model::id::{ChannelId, MessageId};
    ///
    /// let channel_id = ChannelId::new(1).expect("non zero id");
    /// let message_id = MessageId::new(2).expect("non zero id");
    ///
    /// let channels_ignored = {
    ///     let mut map = HashSet::new();
    ///     map.insert(channel_id);
    ///
    ///     Arc::new(Mutex::new(map))
    /// };
    ///
    /// let client = Client::new(env::var("DISCORD_TOKEN")?);
    /// let mut req = client.delete_message(channel_id, message_id).exec();
    ///
    /// let channels_ignored_clone = channels_ignored.clone();
    /// req.set_pre_flight(Box::new(move || {
    ///     // imagine you have some logic here to external state that checks
    ///     // whether the request should still be performed
    ///     let channels_ignored = channels_ignored_clone
    ///         .lock()
    ///         .expect("channels poisoned");
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
        if let ResponseFutureStage::RatelimitQueue(ref mut queue) = &mut self.stage {
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
        guild_id: Option<GuildId>,
        invalid_token: InvalidToken,
        wait_for_sender: WaitForTicketFuture,
        request_timeout: Duration,
        response_future: HyperResponseFuture,
    ) -> Self {
        Self {
            phantom: PhantomData,
            stage: ResponseFutureStage::RatelimitQueue(RatelimitQueue {
                guild_id,
                invalid_token,
                pre_flight_check: None,
                request_timeout,
                response_future,
                wait_for_sender,
            }),
        }
    }

    /// Set the ID of the relevant guild.
    ///
    /// Necessary for [`MemberBody`] and [`MemberListBody`] deserialization.
    pub(crate) fn set_guild_id(&mut self, guild_id: GuildId) {
        match &mut self.stage {
            ResponseFutureStage::InFlight(ref mut stage) => {
                stage.guild_id.replace(guild_id);
            }
            ResponseFutureStage::RatelimitQueue(ref mut stage) => {
                stage.guild_id.replace(guild_id);
            }
            _ => {}
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
