use crate::{
    client::Client,
    error::Error,
    request::{self, AuditLogReason, Request, TryIntoRequest},
    response::{Response, ResponseFuture},
    routing::Route,
};
use serde::Serialize;
use std::future::IntoFuture;
use twilight_model::{
    guild::MfaLevel,
    id::{marker::GuildMarker, Id},
};
use twilight_validate::request::{audit_reason as validate_audit_reason, ValidationError};

#[derive(Serialize)]
struct UpdateGuildMfaFields<'a> {
    level: MfaLevel,
    reason: Option<&'a str>,
}

/// Update a guild's MFA level.
#[must_use = "requests must be configured and executed"]
pub struct UpdateGuildMfa<'a> {
    fields: UpdateGuildMfaFields<'a>,
    guild_id: Id<GuildMarker>,
    http: &'a Client,
}

impl<'a> UpdateGuildMfa<'a> {
    pub(crate) const fn new(http: &'a Client, guild_id: Id<GuildMarker>, level: MfaLevel) -> Self {
        Self {
            fields: UpdateGuildMfaFields {
                level,
                reason: None,
            },
            guild_id,
            http,
        }
    }
}

impl IntoFuture for UpdateGuildMfa<'_> {
    type Output = Result<Response<MfaLevel>, Error>;

    type IntoFuture = ResponseFuture<MfaLevel>;

    fn into_future(self) -> Self::IntoFuture {
        let http = self.http;

        match self.try_into_request() {
            Ok(request) => http.request(request),
            Err(source) => ResponseFuture::error(source),
        }
    }
}

impl<'a> AuditLogReason<'a> for UpdateGuildMfa<'a> {
    fn reason(mut self, reason: &'a str) -> Result<Self, ValidationError> {
        validate_audit_reason(reason)?;

        self.fields.reason.replace(reason);

        Ok(self)
    }
}

impl TryIntoRequest for UpdateGuildMfa<'_> {
    fn try_into_request(self) -> Result<Request, Error> {
        let mut request = Request::builder(&Route::UpdateGuildMfa {
            guild_id: self.guild_id.get(),
        });

        if let Some(reason) = self.fields.reason.as_ref() {
            let header = request::audit_header(reason)?;

            request = request.headers(header);
        }

        request = request.json(&self.fields)?;

        Ok(request.build())
    }
}
