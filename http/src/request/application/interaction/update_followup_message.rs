//! Update a followup message created from a interaction.

use crate::{
    client::Client,
    error::Error as HttpError,
    request::{
        self,
        validate_inner::{self, ComponentValidationError, ComponentValidationErrorType},
        AttachmentFile, Form, NullableField, Request, TryIntoRequest,
    },
    response::{marker::EmptyBody, ResponseFuture},
    routing::Route,
};
use serde::Serialize;
use std::{
    borrow::Cow,
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};
use twilight_model::{
    application::component::Component,
    channel::{embed::Embed, message::AllowedMentions, Attachment},
    id::{
        marker::{ApplicationMarker, MessageMarker},
        Id,
    },
};

/// A followup message can not be updated as configured.
#[derive(Debug)]
pub struct UpdateFollowupMessageError {
    kind: UpdateFollowupMessageErrorType,
    source: Option<Box<dyn Error + Send + Sync>>,
}

impl UpdateFollowupMessageError {
    /// Immutable reference to the type of error that occurred.
    #[must_use = "retrieving the type has no effect if left unused"]
    pub const fn kind(&self) -> &UpdateFollowupMessageErrorType {
        &self.kind
    }

    /// Consume the error, returning the source error if there is any.
    #[must_use = "consuming the error and retrieving the source has no effect if left unused"]
    pub fn into_source(self) -> Option<Box<dyn Error + Send + Sync>> {
        self.source
    }

    /// Consume the error, returning the owned error type and the source error.
    #[must_use = "consuming the error into its parts has no effect if left unused"]
    pub fn into_parts(
        self,
    ) -> (
        UpdateFollowupMessageErrorType,
        Option<Box<dyn Error + Send + Sync>>,
    ) {
        (self.kind, self.source)
    }
}

impl Display for UpdateFollowupMessageError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match &self.kind {
            UpdateFollowupMessageErrorType::ComponentCount { count } => {
                Display::fmt(count, f)?;
                f.write_str(" components were provided, but only ")?;
                Display::fmt(&ComponentValidationError::COMPONENT_COUNT, f)?;

                f.write_str(" root components are allowed")
            }
            UpdateFollowupMessageErrorType::ComponentInvalid { .. } => {
                f.write_str("a provided component is invalid")
            }
            UpdateFollowupMessageErrorType::ContentInvalid => {
                f.write_str("message content is invalid")
            }
            UpdateFollowupMessageErrorType::EmbedTooLarge { .. } => {
                f.write_str("length of one of the embeds is too large")
            }
            UpdateFollowupMessageErrorType::TooManyEmbeds => {
                f.write_str("only 10 embeds may be provided")
            }
        }
    }
}

impl Error for UpdateFollowupMessageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| &**source as &(dyn Error + 'static))
    }
}

/// Type of [`UpdateFollowupMessageError`] that occurred.
#[derive(Debug)]
#[non_exhaustive]
pub enum UpdateFollowupMessageErrorType {
    /// An invalid message component was provided.
    ComponentInvalid {
        /// Additional details about the validation failure type.
        kind: ComponentValidationErrorType,
    },
    /// Too many message components were provided.
    ComponentCount {
        /// Number of components that were provided.
        count: usize,
    },
    /// Content is over 2000 UTF-16 characters.
    ContentInvalid,
    /// Length of one of the embeds is over 6000 characters.
    EmbedTooLarge {
        /// Index of the embed that was too large.
        ///
        /// This can be used to index into the provided embeds to retrieve the
        /// invalid embed.
        index: usize,
    },
    /// Too many embeds were provided.
    ///
    /// A followup message can have up to 10 embeds.
    TooManyEmbeds,
}

#[derive(Serialize)]
struct UpdateFollowupMessageFields<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    allowed_mentions: Option<AllowedMentions>,
    #[serde(skip_serializing_if = "request::slice_is_empty")]
    attachments: &'a [Attachment],
    #[serde(skip_serializing_if = "Option::is_none")]
    components: Option<NullableField<&'a [Component]>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<NullableField<&'a str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    embeds: Option<NullableField<&'a [Embed]>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_json: Option<&'a [u8]>,
}

/// Update a followup message.
///
/// A followup message must always have at least one embed or some amount of
/// content. If you wish to delete a followup message refer to
/// [`DeleteFollowupMessage`].
///
/// # Examples
///
/// Update a followup message by setting the content to `test <@3>` -
/// attempting to mention user ID 3 - and specifying that only that the user may
/// not be mentioned.
///
/// ```no_run
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use std::env;
/// use twilight_http::Client;
/// use twilight_model::{
///     channel::message::AllowedMentions,
///     id::Id,
/// };
///
/// let client = Client::new(env::var("DISCORD_TOKEN")?);
/// let application_id = Id::new(1).expect("non zero");
///
/// client
///     .interaction(application_id)
///     .update_followup_message("token here", Id::new(2).expect("non zero"))
///     // By creating a default set of allowed mentions, no entity can be
///     // mentioned.
///     .allowed_mentions(AllowedMentions::default())
///     .content(Some("test <@3>"))?
///     .exec()
///     .await?;
/// # Ok(()) }
/// ```
///
/// [`DeleteFollowupMessage`]: super::DeleteFollowupMessage
#[must_use = "requests must be configured and executed"]
pub struct UpdateFollowupMessage<'a> {
    application_id: Id<ApplicationMarker>,
    attachments: Cow<'a, [AttachmentFile<'a>]>,
    fields: UpdateFollowupMessageFields<'a>,
    http: &'a Client,
    message_id: Id<MessageMarker>,
    token: &'a str,
}

impl<'a> UpdateFollowupMessage<'a> {
    /// Maximum number of embeds that a followup message may have.
    pub const EMBED_COUNT_LIMIT: usize = 10;

    pub(crate) const fn new(
        http: &'a Client,
        application_id: Id<ApplicationMarker>,
        token: &'a str,
        message_id: Id<MessageMarker>,
    ) -> Self {
        Self {
            fields: UpdateFollowupMessageFields {
                allowed_mentions: None,
                attachments: &[],
                components: None,
                content: None,
                embeds: None,
                payload_json: None,
            },
            attachments: Cow::Borrowed(&[]),
            http,
            message_id,
            token,
            application_id,
        }
    }

    /// Set the allowed mentions in the message.
    pub fn allowed_mentions(mut self, allowed: AllowedMentions) -> Self {
        self.fields.allowed_mentions.replace(allowed);

        self
    }

    /// Specify multiple attachments already present in the target message to keep.
    ///
    /// If called, all unspecified attachments will be removed from the message.
    /// If not called, all attachments will be kept.
    pub const fn attachments(mut self, attachments: &'a [Attachment]) -> Self {
        self.fields.attachments = attachments;

        self
    }

    /// Add multiple [`Component`]s to a message.
    ///
    /// Calling this method multiple times will clear previous calls.
    ///
    /// Pass `None` to clear existing components.
    ///
    /// # Errors
    ///
    /// Returns an [`UpdateFollowupMessageErrorType::ComponentCount`] error type
    /// if too many components are provided.
    ///
    /// Returns an [`UpdateFollowupMessageErrorType::ComponentInvalid`] error
    /// type if one of the provided components is invalid.
    pub fn components(
        mut self,
        components: Option<&'a [Component]>,
    ) -> Result<Self, UpdateFollowupMessageError> {
        if let Some(components) = components.as_ref() {
            validate_inner::components(components).map_err(|source| {
                let (kind, inner_source) = source.into_parts();

                match kind {
                    ComponentValidationErrorType::ComponentCount { count } => {
                        UpdateFollowupMessageError {
                            kind: UpdateFollowupMessageErrorType::ComponentCount { count },
                            source: inner_source,
                        }
                    }
                    other => UpdateFollowupMessageError {
                        kind: UpdateFollowupMessageErrorType::ComponentInvalid { kind: other },
                        source: inner_source,
                    },
                }
            })?;
        }

        self.fields.components = Some(NullableField(components));

        Ok(self)
    }

    /// Set the content of the message.
    ///
    /// Pass `None` if you want to remove the message content.
    ///
    /// Note that if there is are no embeds then you will not be able to remove
    /// the content of the message.
    ///
    /// The maximum length is 2000 UTF-16 characters.
    ///
    /// # Errors
    ///
    /// Returns an [`UpdateFollowupMessageErrorType::ContentInvalid`] error type if
    /// the content length is too long.
    pub fn content(mut self, content: Option<&'a str>) -> Result<Self, UpdateFollowupMessageError> {
        if let Some(content_ref) = content.as_ref() {
            if !validate_inner::content_limit(content_ref) {
                return Err(UpdateFollowupMessageError {
                    kind: UpdateFollowupMessageErrorType::ContentInvalid,
                    source: None,
                });
            }
        }

        self.fields.content = Some(NullableField(content));

        Ok(self)
    }

    /// Set the list of embeds of the followup message.
    ///
    /// Pass `None` to remove all of the embeds.
    ///
    /// The maximum number of allowed embeds is defined by
    /// [`EMBED_COUNT_LIMIT`].
    ///
    /// The total character length of each embed must not exceed 6000
    /// characters. Additionally, the internal fields also have character
    /// limits. Refer to [the discord docs] for more information.
    ///
    /// # Examples
    ///
    /// Create an embed and update the message with the new embed. The content
    /// of the original message is unaffected and only the embed(s) are
    /// modified.
    ///
    /// ```no_run
    /// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use std::env;
    /// use twilight_http::Client;
    /// use twilight_embed_builder::EmbedBuilder;
    /// use twilight_model::id::Id;
    ///
    /// let client = Client::new(env::var("DISCORD_TOKEN")?);
    /// let application_id = Id::new(1).expect("non zero");
    ///
    /// let embed = EmbedBuilder::new()
    ///     .description("Powerful, flexible, and scalable ecosystem of Rust libraries for the Discord API.")
    ///     .title("Twilight")
    ///     .url("https://twilight.rs")
    ///     .build()?;
    ///
    /// client
    ///     .interaction(application_id)
    ///     .update_followup_message("token", Id::new(2).expect("non zero"))
    ///     .embeds(Some(&[embed]))?
    ///     .exec()
    ///     .await?;
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an [`UpdateFollowupMessageErrorType::EmbedTooLarge`] error type
    /// if one of the embeds are too large.
    ///
    /// Returns an [`UpdateFollowupMessageErrorType::TooManyEmbeds`] error type
    /// if more than 10 embeds are provided.
    ///
    /// [the discord docs]: https://discord.com/developers/docs/resources/channel#embed-limits
    /// [`EMBED_COUNT_LIMIT`]: Self::EMBED_COUNT_LIMIT
    pub fn embeds(
        mut self,
        embeds: Option<&'a [Embed]>,
    ) -> Result<Self, UpdateFollowupMessageError> {
        if let Some(embeds_present) = embeds {
            if embeds_present.len() > Self::EMBED_COUNT_LIMIT {
                return Err(UpdateFollowupMessageError {
                    kind: UpdateFollowupMessageErrorType::TooManyEmbeds,
                    source: None,
                });
            }

            for (idx, embed) in embeds_present.iter().enumerate() {
                if let Err(source) = validate_inner::embed(embed) {
                    return Err(UpdateFollowupMessageError {
                        kind: UpdateFollowupMessageErrorType::EmbedTooLarge { index: idx },
                        source: Some(Box::new(source)),
                    });
                }
            }
        }

        self.fields.embeds = Some(NullableField(embeds));

        Ok(self)
    }

    /// Attach multiple files to the message.
    ///
    /// Calling this method will clear any previous calls.
    #[allow(clippy::missing_const_for_fn)] // False positive
    pub fn attach(mut self, attachments: &'a [AttachmentFile<'a>]) -> Self {
        self.attachments = Cow::Borrowed(attachments);

        self
    }

    /// Attach multiple files to the message.
    ///
    /// Calling this method will clear any previous calls.
    #[deprecated(since = "0.7.2", note = "Use attach instead")]
    pub fn files(mut self, files: &'a [(&'a str, &'a [u8])]) -> Self {
        self.attachments = Cow::Owned(AttachmentFile::from_pairs(files));

        self
    }

    /// JSON encoded body of any additional request fields.
    ///
    /// If this method is called, all other fields are ignored, except for
    /// [`attachments`]. See [Discord Docs/Create Message] and
    /// [`CreateFollowupMessage::payload_json`].
    ///
    /// [`attachments`]: Self::attachments
    /// [`CreateFollowupMessage::payload_json`]: super::CreateFollowupMessage::payload_json
    /// [Discord Docs/Create Message]: https://discord.com/developers/docs/resources/channel#create-message-params
    pub const fn payload_json(mut self, payload_json: &'a [u8]) -> Self {
        self.fields.payload_json = Some(payload_json);

        self
    }

    pub fn exec(self) -> ResponseFuture<EmptyBody> {
        let http = self.http;

        match self.try_into_request() {
            Ok(request) => http.request(request),
            Err(source) => ResponseFuture::error(source),
        }
    }
}

impl TryIntoRequest for UpdateFollowupMessage<'_> {
    fn try_into_request(mut self) -> Result<Request, HttpError> {
        let mut request = Request::builder(&Route::UpdateWebhookMessage {
            message_id: self.message_id.get(),
            thread_id: None,
            token: self.token,
            webhook_id: self.application_id.get(),
        });

        if !self.attachments.is_empty() || self.fields.payload_json.is_some() {
            let mut form = Form::new();

            if !self.attachments.is_empty() {
                for (index, attachment) in self.attachments.iter().enumerate() {
                    form.attach(
                        index as u64,
                        attachment.filename.as_bytes(),
                        attachment.file,
                    );
                }
            }

            if let Some(payload_json) = self.fields.payload_json {
                form.payload_json(payload_json);
            } else {
                if self.fields.allowed_mentions.is_none() {
                    self.fields.allowed_mentions = self.http.default_allowed_mentions();
                }

                let body = crate::json::to_vec(&self.fields).map_err(HttpError::json)?;
                form.payload_json(&body);
            }

            request = request.form(form);
        } else {
            if self.fields.allowed_mentions.is_none() {
                self.fields.allowed_mentions = self.http.default_allowed_mentions();
            }

            request = request.json(&self.fields)?;
        }

        Ok(request.use_authorization_token(false).build())
    }
}

#[cfg(test)]
mod tests {
    use crate::{client::Client, request::TryIntoRequest};
    use std::error::Error;
    use twilight_http_ratelimiting::Path;
    use twilight_model::id::Id;

    #[test]
    fn test_update_followup_message() -> Result<(), Box<dyn Error>> {
        let application_id = Id::new(1).expect("non zero id");
        let message_id = Id::new(2).expect("non zero id");
        let token = "foo".to_owned().into_boxed_str();

        let client = Client::new(String::new());
        let req = client
            .interaction(application_id)
            .update_followup_message(&token, message_id)
            .content(Some("test"))?
            .try_into_request()?;

        assert!(!req.use_authorization_token());
        assert_eq!(
            &Path::WebhooksIdTokenMessagesId(application_id.get(), token),
            req.ratelimit_path()
        );

        Ok(())
    }
}
