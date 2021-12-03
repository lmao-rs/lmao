use crate::{client::Client, request::Request, response::ResponseFuture, routing::Route};
use twilight_model::{
    channel::Message,
    id::{ChannelId, MessageId, WebhookId},
};

/// Get a webhook message by [`WebhookId`], token, and [`MessageId`].
///
/// [`WebhookId`]: twilight_model::id::WebhookId
/// [`MessageId`]: twilight_model::id::MessageId
#[must_use = "requests must be configured and executed"]
pub struct GetWebhookMessage<'a> {
    http: &'a Client,
    message_id: MessageId,
    thread_id: Option<ChannelId>,
    token: &'a str,
    webhook_id: WebhookId,
}

impl<'a> GetWebhookMessage<'a> {
    pub(crate) const fn new(
        http: &'a Client,
        webhook_id: WebhookId,
        token: &'a str,
        message_id: MessageId,
    ) -> Self {
        Self {
            http,
            message_id,
            thread_id: None,
            token,
            webhook_id,
        }
    }

    /// Get a message in a thread belonging to the channel instead of the
    /// channel itself.
    pub fn thread_id(mut self, thread_id: ChannelId) -> Self {
        self.thread_id.replace(thread_id);

        self
    }

    /// Execute the request, returning a future resolving to a [`Response`].
    ///
    /// [`Response`]: crate::response::Response
    pub fn exec(self) -> ResponseFuture<Message> {
        let request = Request::builder(&Route::GetWebhookMessage {
            message_id: self.message_id.get(),
            thread_id: self.thread_id.map(ChannelId::get),
            token: self.token,
            webhook_id: self.webhook_id.get(),
        })
        .use_authorization_token(false)
        .build();

        self.http.request(request)
    }
}
