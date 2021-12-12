use super::{StickerValidationError, StickerValidationErrorType};
use crate::{
    client::Client,
    error::Error as HttpError,
    request::{validate_inner, AuditLogReason, AuditLogReasonError, Request, TryIntoRequest},
    response::ResponseFuture,
    routing::Route,
};
use serde::Serialize;
use twilight_model::{
    channel::message::sticker::Sticker,
    id::{
        marker::{GuildMarker, StickerMarker},
        Id,
    },
};

#[derive(Serialize)]
struct UpdateGuildStickerFields<'a> {
    description: Option<&'a str>,
    name: Option<&'a str>,
    tags: Option<&'a str>,
}

/// Updates a sticker in a guild, and returns the updated sticker.
///
/// # Examples
///
/// ```no_run
/// use twilight_http::Client;
/// use twilight_model::id::Id;
///
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let client = Client::new("my token".to_owned());
///
/// let guild_id = Id::new(1).expect("non zero");
/// let sticker_id = Id::new(2).expect("non zero");
/// let sticker = client
///     .update_guild_sticker(guild_id, sticker_id)
///     .description("new description")?
///     .exec()
///     .await?
///     .model()
///     .await?;
///
/// println!("{:#?}", sticker);
/// # Ok(()) }
/// ```
pub struct UpdateGuildSticker<'a> {
    fields: UpdateGuildStickerFields<'a>,
    guild_id: Id<GuildMarker>,
    http: &'a Client,
    reason: Option<&'a str>,
    sticker_id: Id<StickerMarker>,
}

impl<'a> UpdateGuildSticker<'a> {
    pub(crate) const fn new(
        http: &'a Client,
        guild_id: Id<GuildMarker>,
        sticker_id: Id<StickerMarker>,
    ) -> Self {
        Self {
            guild_id,
            fields: UpdateGuildStickerFields {
                description: None,
                name: None,
                tags: None,
            },
            http,
            reason: None,
            sticker_id,
        }
    }

    pub fn description(mut self, description: &'a str) -> Result<Self, StickerValidationError> {
        if !validate_inner::sticker_description(description) {
            return Err(StickerValidationError {
                kind: StickerValidationErrorType::DescriptionInvalid,
            });
        }

        self.fields.description = Some(description);

        Ok(self)
    }

    pub fn name(mut self, name: &'a str) -> Result<Self, StickerValidationError> {
        if !validate_inner::sticker_name(name) {
            return Err(StickerValidationError {
                kind: StickerValidationErrorType::NameInvalid,
            });
        }

        self.fields.name = Some(name);

        Ok(self)
    }

    pub fn tags(mut self, tags: &'a str) -> Result<Self, StickerValidationError> {
        if !validate_inner::sticker_tags(tags) {
            return Err(StickerValidationError {
                kind: StickerValidationErrorType::TagsInvalid,
            });
        }

        self.fields.tags = Some(tags);

        Ok(self)
    }

    /// Execute the request, returning a future resolving to a [`Response`].
    ///
    /// [`Response`]: crate::response::Response
    pub fn exec(self) -> ResponseFuture<Sticker> {
        let http = self.http;

        match self.try_into_request() {
            Ok(request) => http.request(request),
            Err(source) => ResponseFuture::error(source),
        }
    }
}

impl<'a> AuditLogReason<'a> for UpdateGuildSticker<'a> {
    fn reason(mut self, reason: &'a str) -> Result<Self, AuditLogReasonError> {
        self.reason.replace(AuditLogReasonError::validate(reason)?);

        Ok(self)
    }
}

impl TryIntoRequest for UpdateGuildSticker<'_> {
    fn try_into_request(self) -> Result<Request, HttpError> {
        let request = Request::builder(&Route::UpdateGuildSticker {
            guild_id: self.guild_id.get(),
            sticker_id: self.sticker_id.get(),
        })
        .json(&self.fields)?;

        Ok(request.build())
    }
}
