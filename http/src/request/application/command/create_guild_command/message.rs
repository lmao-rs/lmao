use super::super::CommandBorrowed;
use crate::{
    client::Client,
    error::Error,
    request::{Request, RequestBuilder, TryIntoRequest},
    response::ResponseFuture,
    routing::Route,
};
use twilight_model::{
    application::command::{Command, CommandType},
    guild::Permissions,
    id::{
        marker::{ApplicationMarker, GuildMarker},
        Id,
    },
};
use twilight_validate::command::{name as validate_name, CommandValidationError};

/// Create a message command in a guild.
///
/// Creating a guild command with the same name as an already-existing guild
/// command in the same guild will overwrite the old command. See
/// [Discord Docs/Create Guild Application Command].
///
/// [Discord Docs/Create Guild Application Command]: https://discord.com/developers/docs/interactions/application-commands#create-guild-application-command
#[must_use = "requests must be configured and executed"]
pub struct CreateGuildMessageCommand<'a> {
    application_id: Id<ApplicationMarker>,
    default_permission: Option<bool>,
    default_member_permissions: Option<Permissions>,
    guild_id: Id<GuildMarker>,
    http: &'a Client,
    name: &'a str,
}

impl<'a> CreateGuildMessageCommand<'a> {
    pub(crate) fn new(
        http: &'a Client,
        application_id: Id<ApplicationMarker>,
        guild_id: Id<GuildMarker>,
        name: &'a str,
    ) -> Result<Self, CommandValidationError> {
        validate_name(name)?;

        Ok(Self {
            application_id,
            default_permission: None,
            default_member_permissions: None,
            guild_id,
            http,
            name,
        })
    }

    /// Whether the command is enabled by default when the app is added to a
    /// guild.
    #[deprecated = "use `default_member_permissions` and `dm_permission` instead"]
    pub const fn default_permission(mut self, default: bool) -> Self {
        self.default_permission = Some(default);

        self
    }

    /// Default permissions required for a member to run the command.
    ///
    /// Defaults to [`None`].
    pub const fn default_member_permissions(mut self, default: Permissions) -> Self {
        self.default_member_permissions = Some(default);

        self
    }

    /// Execute the request, returning a future resolving to a [`Response`].
    ///
    /// [`Response`]: crate::response::Response
    pub fn exec(self) -> ResponseFuture<Command> {
        let http = self.http;

        match self.try_into_request() {
            Ok(request) => http.request(request),
            Err(source) => ResponseFuture::error(source),
        }
    }
}

impl TryIntoRequest for CreateGuildMessageCommand<'_> {
    fn try_into_request(self) -> Result<Request, Error> {
        Request::builder(&Route::CreateGuildCommand {
            application_id: self.application_id.get(),
            guild_id: self.guild_id.get(),
        })
        .json(&CommandBorrowed {
            application_id: Some(self.application_id),
            default_permission: self.default_permission,
            default_member_permissions: self.default_member_permissions,
            dm_permission: None,
            description: None,
            kind: CommandType::Message,
            name: self.name,
            options: None,
        })
        .map(RequestBuilder::build)
    }
}
