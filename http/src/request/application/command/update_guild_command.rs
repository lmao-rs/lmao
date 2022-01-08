use crate::{
    client::Client,
    error::Error,
    request::{Request, RequestBuilder},
    response::ResponseFuture,
    routing::Route,
};
use serde::Serialize;
use twilight_model::{
    application::command::{Command, CommandOption},
    id::{ApplicationId, CommandId, GuildId},
};

#[derive(Serialize)]
struct UpdateGuildCommandFields<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<&'a [CommandOption]>,
}

/// Edit a command in a guild, by ID.
///
/// You must specify a name and description. See [the Discord docs] for more
/// information.
///
/// [the Discord docs]: https://discord.com/developers/docs/interactions/application-commands#edit-guild-application-command
#[must_use = "requests must be configured and executed"]
pub struct UpdateGuildCommand<'a> {
    fields: UpdateGuildCommandFields<'a>,
    application_id: ApplicationId,
    command_id: CommandId,
    guild_id: GuildId,
    http: &'a Client,
}

impl<'a> UpdateGuildCommand<'a> {
    pub(crate) const fn new(
        http: &'a Client,
        application_id: ApplicationId,
        guild_id: GuildId,
        command_id: CommandId,
    ) -> Self {
        Self {
            application_id,
            command_id,
            fields: UpdateGuildCommandFields {
                description: None,
                name: None,
                options: None,
            },
            guild_id,
            http,
        }
    }

    /// Edit the name of the command.
    pub const fn name(mut self, name: &'a str) -> Self {
        self.fields.name = Some(name);

        self
    }

    /// Edit the description of the command.
    pub const fn description(mut self, description: &'a str) -> Self {
        self.fields.description = Some(description);

        self
    }

    /// Edit the command options of the command.
    pub const fn command_options(mut self, options: &'a [CommandOption]) -> Self {
        self.fields.options = Some(options);

        self
    }

    fn request(&self) -> Result<Request, Error> {
        Request::builder(&Route::UpdateGuildCommand {
            application_id: self.application_id.get(),
            command_id: self.command_id.get(),
            guild_id: self.guild_id.get(),
        })
        .json(&self.fields)
        .map(RequestBuilder::build)
    }

    /// Execute the request, returning a future resolving to a [`Response`].
    ///
    /// [`Response`]: crate::response::Response
    pub fn exec(self) -> ResponseFuture<Command> {
        match self.request() {
            Ok(request) => self.http.request(request),
            Err(source) => ResponseFuture::error(source),
        }
    }
}
