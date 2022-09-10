use crate::{
    client::Client,
    error::Error,
    request::{Request, TryIntoRequest},
    response::{marker::EmptyBody, Response, ResponseFuture},
    routing::Route,
};
use std::future::IntoFuture;
use twilight_model::id::{marker::GuildMarker, Id};

/// Delete a guild permanently. The user must be the owner.
#[must_use = "requests must be configured and executed"]
pub struct DeleteGuild<'a> {
    guild_id: Id<GuildMarker>,
    http: &'a Client,
}

impl<'a> DeleteGuild<'a> {
    pub(crate) const fn new(http: &'a Client, guild_id: Id<GuildMarker>) -> Self {
        Self { guild_id, http }
    }

    /// Execute the request, returning a future resolving to a [`Response`].
    #[deprecated(since = "0.14.0", note = "use `.await` or `into_future` instead")]
    pub fn exec(self) -> ResponseFuture<EmptyBody> {
        self.into_future()
    }
}

impl IntoFuture for DeleteGuild<'_> {
    type Output = Result<Response<EmptyBody>, Error>;

    type IntoFuture = ResponseFuture<EmptyBody>;

    fn into_future(self) -> Self::IntoFuture {
        let http = self.http;

        match self.try_into_request() {
            Ok(request) => http.request(request),
            Err(source) => ResponseFuture::error(source),
        }
    }
}

impl TryIntoRequest for DeleteGuild<'_> {
    fn try_into_request(self) -> Result<Request, Error> {
        Ok(Request::from_route(&Route::DeleteGuild {
            guild_id: self.guild_id.get(),
        }))
    }
}
