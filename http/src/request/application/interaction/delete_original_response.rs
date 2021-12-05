use crate::{
    client::Client,
    request::Request,
    response::{marker::EmptyBody, ResponseFuture},
    routing::Route,
};
use twilight_model::id::ApplicationId;

/// Delete a original interaction response.
///
/// # Examples
///
/// ```no_run
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use std::env;
/// use twilight_http::Client;
/// use twilight_http::request::AuditLogReason;
/// use twilight_model::id::ApplicationId;
///
/// let client = Client::new(env::var("DISCORD_TOKEN")?);
/// client.set_application_id(ApplicationId::new(1).expect("non zero"));
///
/// client
///     .delete_interaction_original("token here")?
///     .exec()
///     .await?;
/// # Ok(()) }
/// ```
#[must_use = "requests must be configured and executed"]
pub struct DeleteOriginalResponse<'a> {
    application_id: ApplicationId,
    http: &'a Client,
    token: &'a str,
}

impl<'a> DeleteOriginalResponse<'a> {
    pub(crate) const fn new(
        http: &'a Client,
        application_id: ApplicationId,
        token: &'a str,
    ) -> Self {
        Self {
            application_id,
            http,
            token,
        }
    }

    fn request(&self) -> Request {
        Request::builder(&Route::DeleteInteractionOriginal {
            application_id: self.application_id.get(),
            interaction_token: self.token,
        })
        .use_authorization_token(false)
        .build()
    }

    /// Execute the request, returning a future resolving to a [`Response`].
    ///
    /// [`Response`]: crate::response::Response
    pub fn exec(self) -> ResponseFuture<EmptyBody> {
        self.http.request(self.request())
    }
}

#[cfg(test)]
mod tests {
    use crate::client::Client;
    use std::error::Error;
    use twilight_http_ratelimiting::Path;
    use twilight_model::id::ApplicationId;

    #[test]
    fn test_delete_followup_message() -> Result<(), Box<dyn Error>> {
        let application_id = ApplicationId::new(1).expect("non zero id");
        let token = "foo".to_owned().into_boxed_str();

        let client = Client::new(String::new());
        client.set_application_id(application_id);
        let req = client.delete_interaction_original(&token)?.request();

        assert!(!req.use_authorization_token());
        assert_eq!(
            &Path::WebhooksIdTokenMessagesId(application_id.get(), token),
            req.ratelimit_path()
        );

        Ok(())
    }
}
