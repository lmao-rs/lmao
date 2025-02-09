use crate::{
    client::Client,
    error::Error,
    request::{attachment::AttachmentManager, Request, TryIntoRequest},
    response::{Response, ResponseFuture},
    routing::Route,
};
use std::future::IntoFuture;
use twilight_model::{
    http::interaction::InteractionResponse,
    id::{marker::InteractionMarker, Id},
};

/// Respond to an interaction, by its ID and token.
///
/// This endpoint is not bound to the application's global rate limit.
#[must_use = "requests must be configured and executed"]
pub struct CreateResponseWithResponse<'a> {
    interaction_id: Id<InteractionMarker>,
    interaction_token: &'a str,
    response: &'a InteractionResponse,
    http: &'a Client,
}

impl<'a> CreateResponseWithResponse<'a> {
    pub(crate) const fn new(
        http: &'a Client,
        interaction_id: Id<InteractionMarker>,
        interaction_token: &'a str,
        response: &'a InteractionResponse,
    ) -> Self {
        Self {
            interaction_id,
            interaction_token,
            response,
            http,
        }
    }
}

impl IntoFuture for CreateResponseWithResponse<'_> {
    type Output = Result<Response<InteractionResponse>, Error>;

    type IntoFuture = ResponseFuture<InteractionResponse>;

    fn into_future(self) -> Self::IntoFuture {
        let http = self.http;

        match self.try_into_request() {
            Ok(request) => http.request(request),
            Err(source) => ResponseFuture::error(source),
        }
    }
}

impl TryIntoRequest for CreateResponseWithResponse<'_> {
    fn try_into_request(self) -> Result<Request, Error> {
        let mut request = Request::builder(&Route::InteractionCallback {
            interaction_id: self.interaction_id.get(),
            interaction_token: self.interaction_token,
            with_response: true,
        });

        // Interaction executions don't need the authorization token, only the
        // interaction token.
        request = request.use_authorization_token(false);

        // Determine whether we need to use a multipart/form-data body or a JSON
        // body.
        if let Some(attachments) = self
            .response
            .data
            .as_ref()
            .and_then(|data| data.attachments.as_ref())
        {
            let fields = crate::json::to_vec(&self.response).map_err(Error::json)?;

            let form = AttachmentManager::new()
                .set_files(attachments.iter().collect())
                .build_form(&fields);

            request = request.form(form);
        } else {
            request = request.json(&self.response);
        }

        request.build()
    }
}

#[cfg(test)]
mod tests {
    use crate::{client::Client, request::TryIntoRequest};
    use std::error::Error;
    use twilight_http_ratelimiting::Path;
    use twilight_model::{
        http::interaction::{InteractionResponse, InteractionResponseType},
        id::Id,
    };

    #[test]
    fn interaction_callback() -> Result<(), Box<dyn Error>> {
        let application_id = Id::new(1);
        let interaction_id = Id::new(2);
        let token = "foo".to_owned().into_boxed_str();

        let client = Client::new(String::new());

        let response = InteractionResponse {
            kind: InteractionResponseType::DeferredUpdateMessage,
            data: None,
        };

        let req = client
            .interaction(application_id)
            .create_response(interaction_id, &token, &response)
            .with_response()
            .try_into_request()?;

        assert!(!req.use_authorization_token());
        assert_eq!(
            &Path::InteractionCallback(interaction_id.get()),
            req.ratelimit_path()
        );

        Ok(())
    }
}
