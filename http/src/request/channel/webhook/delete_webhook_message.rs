use crate::{
    client::Client,
    error::Error,
    request::{self, AuditLogReason, AuditLogReasonError, Request},
    response::{marker::EmptyBody, ResponseFuture},
    routing::Route,
};
use twilight_model::id::{MessageId, WebhookId};

/// Delete a message created by a webhook.
///
/// # Examples
///
/// ```no_run
/// # use twilight_http::Client;
/// use twilight_http::request::AuditLogReason;
/// use twilight_model::id::{MessageId, WebhookId};
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let client = Client::new("token");
/// client
///     .delete_webhook_message(WebhookId(1), "token here", MessageId(2))
///     .reason("reason here")?
///     .exec()
///     .await?;
/// # Ok(()) }
/// ```
pub struct DeleteWebhookMessage<'a> {
    http: &'a Client,
    message_id: MessageId,
    reason: Option<String>,
    token: String,
    webhook_id: WebhookId,
}

impl<'a> DeleteWebhookMessage<'a> {
    pub(crate) fn new(
        http: &'a Client,
        webhook_id: WebhookId,
        token: impl Into<String>,
        message_id: MessageId,
    ) -> Self {
        Self {
            http,
            message_id,
            reason: None,
            token: token.into(),
            webhook_id,
        }
    }

    // `self` needs to be consumed and the client returned due to parameters
    // being consumed in request construction.
    fn request(self) -> Result<(Request, &'a Client), Error> {
        let mut request = Request::builder(Route::DeleteWebhookMessage {
            message_id: self.message_id.0,
            token: self.token,
            webhook_id: self.webhook_id.0,
        })
        .use_authorization_token(false);

        if let Some(reason) = self.reason.as_ref() {
            request = request.headers(request::audit_header(reason)?);
        }

        Ok((request.build(), self.http))
    }

    /// Execute the request, returning a future resolving to a [`Response`].
    ///
    /// [`Response`]: crate::response::Response
    pub fn exec(self) -> ResponseFuture<EmptyBody> {
        match self.request() {
            Ok((request, client)) => client.request(request),
            Err(source) => ResponseFuture::error(source),
        }
    }
}

impl<'a> AuditLogReason for DeleteWebhookMessage<'a> {
    fn reason(mut self, reason: impl Into<String>) -> Result<Self, AuditLogReasonError> {
        self.reason
            .replace(AuditLogReasonError::validate(reason.into())?);

        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::DeleteWebhookMessage;
    use crate::{client::Client, request::Request, routing::Route};
    use twilight_model::id::{MessageId, WebhookId};

    #[test]
    fn test_request() {
        let client = Client::new("token");
        let builder = DeleteWebhookMessage::new(&client, WebhookId(1), "token", MessageId(2));
        let (actual, _) = builder.request().expect("failed to create request");

        let expected = Request::from_route(Route::DeleteWebhookMessage {
            message_id: 2,
            token: "token".to_owned(),
            webhook_id: 1,
        });

        assert_eq!(expected.body, actual.body);
        assert_eq!(expected.path, actual.path);
    }
}
