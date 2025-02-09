mod private {
    use crate::request::{
        application::{
            command::{
                create_global_command::{
                    CreateGlobalChatInputCommand, CreateGlobalMessageCommand,
                    CreateGlobalUserCommand,
                },
                create_guild_command::{
                    CreateGuildChatInputCommand, CreateGuildMessageCommand, CreateGuildUserCommand,
                },
                CreateGlobalCommand, CreateGuildCommand, DeleteGlobalCommand, DeleteGuildCommand,
                GetCommandPermissions, GetGlobalCommand, GetGlobalCommands, GetGuildCommand,
                GetGuildCommandPermissions, GetGuildCommands, SetGlobalCommands, SetGuildCommands,
                UpdateCommandPermissions, UpdateGlobalCommand, UpdateGuildCommand,
            },
            emoji::{
                AddApplicationEmoji, DeleteApplicationEmoji, ListApplicationEmojis,
                UpdateApplicationEmoji,
            },
            interaction::{
                CreateFollowup, CreateResponse, CreateResponseWithResponse, DeleteFollowup,
                DeleteResponse, GetFollowup, GetResponse, UpdateFollowup, UpdateResponse,
            },
            monetization::{
                create_test_entitlement::CreateTestEntitlement, get_entitlements::GetEntitlements,
                DeleteTestEntitlement, GetSKUs,
            },
        },
        channel::{
            invite::{CreateInvite, DeleteInvite, GetChannelInvites, GetInvite},
            message::{
                CreateMessage, CrosspostMessage, DeleteMessage, DeleteMessages, GetChannelMessages,
                GetChannelMessagesConfigured, GetMessage, UpdateMessage,
            },
            reaction::{
                CreateReaction, DeleteAllReaction, DeleteAllReactions, DeleteReaction, GetReactions,
            },
            stage::{
                CreateStageInstance, DeleteStageInstance, GetStageInstance, UpdateStageInstance,
            },
            thread::{
                create_forum_thread::CreateForumThreadMessage, AddThreadMember, CreateThread,
                CreateThreadFromMessage, GetJoinedPrivateArchivedThreads,
                GetPrivateArchivedThreads, GetPublicArchivedThreads, GetThreadMember,
                GetThreadMembers, JoinThread, LeaveThread, RemoveThreadMember, UpdateThread,
            },
            webhook::{
                CreateWebhook, DeleteWebhook, DeleteWebhookMessage, ExecuteWebhook,
                ExecuteWebhookAndWait, GetChannelWebhooks, GetWebhook, GetWebhookMessage,
                UpdateWebhook, UpdateWebhookMessage, UpdateWebhookWithToken,
            },
            CreatePin, CreateTypingTrigger, DeleteChannel, DeleteChannelPermission,
            DeleteChannelPermissionConfigured, DeletePin, FollowNewsChannel, GetChannel, GetPins,
            UpdateChannel, UpdateChannelPermission,
        },
        guild::{
            auto_moderation::{
                CreateAutoModerationRule, DeleteAutoModerationRule, GetAutoModerationRule,
                GetGuildAutoModerationRules, UpdateAutoModerationRule,
            },
            ban::{CreateBan, DeleteBan, GetBan, GetBans},
            emoji::{CreateEmoji, DeleteEmoji, GetEmoji, GetEmojis, UpdateEmoji},
            integration::{DeleteGuildIntegration, GetGuildIntegrations},
            member::{
                AddGuildMember, AddRoleToMember, GetGuildMembers, GetMember, RemoveMember,
                RemoveRoleFromMember, SearchGuildMembers, UpdateGuildMember,
            },
            role::{
                CreateRole, DeleteRole, GetGuildRoles, GetRole, UpdateRole, UpdateRolePositions,
            },
            sticker::{
                CreateGuildSticker, DeleteGuildSticker, GetGuildSticker, GetGuildStickers,
                UpdateGuildSticker,
            },
            update_guild_onboarding::UpdateGuildOnboarding,
            user::{
                GetCurrentUserVoiceState, GetUserVoiceState, UpdateCurrentUserVoiceState,
                UpdateUserVoiceState,
            },
            CreateGuild, CreateGuildChannel, CreateGuildPrune, DeleteGuild, GetActiveThreads,
            GetAuditLog, GetGuild, GetGuildChannels, GetGuildInvites, GetGuildOnboarding,
            GetGuildPreview, GetGuildPruneCount, GetGuildVanityUrl, GetGuildVoiceRegions,
            GetGuildWebhooks, GetGuildWelcomeScreen, GetGuildWidget, GetGuildWidgetSettings,
            UpdateCurrentMember, UpdateGuild, UpdateGuildChannelPositions, UpdateGuildMfa,
            UpdateGuildWelcomeScreen, UpdateGuildWidgetSettings,
        },
        poll::{EndPoll, GetAnswerVoters},
        scheduled_event::{
            CreateGuildExternalScheduledEvent, CreateGuildStageInstanceScheduledEvent,
            CreateGuildVoiceScheduledEvent, DeleteGuildScheduledEvent, GetGuildScheduledEvent,
            GetGuildScheduledEventUsers, GetGuildScheduledEvents, UpdateGuildScheduledEvent,
        },
        sticker::{GetNitroStickerPacks, GetSticker},
        template::{
            CreateGuildFromTemplate, CreateTemplate, DeleteTemplate, GetTemplate, GetTemplates,
            SyncTemplate, UpdateTemplate,
        },
        update_user_application::UpdateCurrentUserApplication,
        user::{
            CreatePrivateChannel, GetCurrentUser, GetCurrentUserConnections,
            GetCurrentUserGuildMember, GetCurrentUserGuilds, GetUser, LeaveGuild,
            UpdateCurrentUser,
        },
        GetCurrentAuthorizationInformation, GetGateway, GetGatewayAuthed, GetUserApplicationInfo,
        GetVoiceRegions,
    };

    pub trait Sealed {}

    impl Sealed for AddApplicationEmoji<'_> {}
    impl Sealed for AddGuildMember<'_> {}
    impl Sealed for AddRoleToMember<'_> {}
    impl Sealed for AddThreadMember<'_> {}
    impl Sealed for CreateAutoModerationRule<'_> {}
    impl Sealed for CreateBan<'_> {}
    impl Sealed for CreateEmoji<'_> {}
    impl Sealed for CreateFollowup<'_> {}
    impl Sealed for CreateForumThreadMessage<'_> {}
    impl Sealed for CreateGlobalChatInputCommand<'_> {}
    impl Sealed for CreateGlobalCommand<'_> {}
    impl Sealed for CreateGlobalMessageCommand<'_> {}
    impl Sealed for CreateGlobalUserCommand<'_> {}
    impl Sealed for CreateGuild<'_> {}
    impl Sealed for CreateGuildChannel<'_> {}
    impl Sealed for CreateGuildChatInputCommand<'_> {}
    impl Sealed for CreateGuildCommand<'_> {}
    impl Sealed for CreateGuildExternalScheduledEvent<'_> {}
    impl Sealed for CreateGuildFromTemplate<'_> {}
    impl Sealed for CreateGuildMessageCommand<'_> {}
    impl Sealed for CreateGuildPrune<'_> {}
    impl Sealed for CreateGuildStageInstanceScheduledEvent<'_> {}
    impl Sealed for CreateGuildSticker<'_> {}
    impl Sealed for CreateGuildUserCommand<'_> {}
    impl Sealed for CreateGuildVoiceScheduledEvent<'_> {}
    impl Sealed for CreateInvite<'_> {}
    impl Sealed for CreateMessage<'_> {}
    impl Sealed for CreatePin<'_> {}
    impl Sealed for CreatePrivateChannel<'_> {}
    impl Sealed for CreateReaction<'_> {}
    impl Sealed for CreateResponse<'_> {}
    impl Sealed for CreateResponseWithResponse<'_> {}
    impl Sealed for CreateRole<'_> {}
    impl Sealed for CreateStageInstance<'_> {}
    impl Sealed for CreateTemplate<'_> {}
    impl Sealed for CreateTestEntitlement<'_> {}
    impl Sealed for CreateThread<'_> {}
    impl Sealed for CreateThreadFromMessage<'_> {}
    impl Sealed for CreateTypingTrigger<'_> {}
    impl Sealed for CreateWebhook<'_> {}
    impl Sealed for CrosspostMessage<'_> {}
    impl Sealed for DeleteAllReaction<'_> {}
    impl Sealed for DeleteAllReactions<'_> {}
    impl Sealed for DeleteAutoModerationRule<'_> {}
    impl Sealed for DeleteBan<'_> {}
    impl Sealed for DeleteChannel<'_> {}
    impl Sealed for DeleteChannelPermission<'_> {}
    impl Sealed for DeleteChannelPermissionConfigured<'_> {}
    impl Sealed for DeleteEmoji<'_> {}
    impl Sealed for DeleteFollowup<'_> {}
    impl Sealed for DeleteGlobalCommand<'_> {}
    impl Sealed for DeleteGuild<'_> {}
    impl Sealed for DeleteGuildCommand<'_> {}
    impl Sealed for DeleteGuildIntegration<'_> {}
    impl Sealed for DeleteGuildScheduledEvent<'_> {}
    impl Sealed for DeleteGuildSticker<'_> {}
    impl Sealed for DeleteInvite<'_> {}
    impl Sealed for DeleteMessage<'_> {}
    impl Sealed for DeleteMessages<'_> {}
    impl Sealed for DeletePin<'_> {}
    impl Sealed for DeleteReaction<'_> {}
    impl Sealed for DeleteResponse<'_> {}
    impl Sealed for DeleteRole<'_> {}
    impl Sealed for DeleteStageInstance<'_> {}
    impl Sealed for DeleteTemplate<'_> {}
    impl Sealed for DeleteWebhook<'_> {}
    impl Sealed for DeleteWebhookMessage<'_> {}
    impl Sealed for DeleteTestEntitlement<'_> {}
    impl Sealed for DeleteApplicationEmoji<'_> {}
    impl Sealed for UpdateApplicationEmoji<'_> {}
    impl Sealed for EndPoll<'_> {}
    impl Sealed for ExecuteWebhook<'_> {}
    impl Sealed for ExecuteWebhookAndWait<'_> {}
    impl Sealed for FollowNewsChannel<'_> {}
    impl Sealed for GetActiveThreads<'_> {}
    impl Sealed for ListApplicationEmojis<'_> {}
    impl Sealed for GetAnswerVoters<'_> {}
    impl Sealed for GetAuditLog<'_> {}
    impl Sealed for GetAutoModerationRule<'_> {}
    impl Sealed for GetBan<'_> {}
    impl Sealed for GetBans<'_> {}
    impl Sealed for GetChannel<'_> {}
    impl Sealed for GetChannelInvites<'_> {}
    impl Sealed for GetChannelMessages<'_> {}
    impl Sealed for GetChannelMessagesConfigured<'_> {}
    impl Sealed for GetChannelWebhooks<'_> {}
    impl Sealed for GetCommandPermissions<'_> {}
    impl Sealed for GetCurrentUser<'_> {}
    impl Sealed for GetCurrentAuthorizationInformation<'_> {}
    impl Sealed for GetCurrentUserConnections<'_> {}
    impl Sealed for GetCurrentUserGuildMember<'_> {}
    impl Sealed for GetCurrentUserGuilds<'_> {}
    impl Sealed for GetCurrentUserVoiceState<'_> {}
    impl Sealed for GetEmoji<'_> {}
    impl Sealed for GetEmojis<'_> {}
    impl Sealed for GetEntitlements<'_> {}
    impl Sealed for GetFollowup<'_> {}
    impl Sealed for GetGateway<'_> {}
    impl Sealed for GetGatewayAuthed<'_> {}
    impl Sealed for GetGlobalCommand<'_> {}
    impl Sealed for GetGlobalCommands<'_> {}
    impl Sealed for GetGuild<'_> {}
    impl Sealed for GetGuildAutoModerationRules<'_> {}
    impl Sealed for GetGuildChannels<'_> {}
    impl Sealed for GetGuildCommand<'_> {}
    impl Sealed for GetGuildCommandPermissions<'_> {}
    impl Sealed for GetGuildCommands<'_> {}
    impl Sealed for GetGuildIntegrations<'_> {}
    impl Sealed for GetGuildInvites<'_> {}
    impl Sealed for GetGuildMembers<'_> {}
    impl Sealed for GetGuildOnboarding<'_> {}
    impl Sealed for GetGuildPreview<'_> {}
    impl Sealed for GetGuildPruneCount<'_> {}
    impl Sealed for GetGuildRoles<'_> {}
    impl Sealed for GetGuildScheduledEvent<'_> {}
    impl Sealed for GetGuildScheduledEventUsers<'_> {}
    impl Sealed for GetGuildScheduledEvents<'_> {}
    impl Sealed for GetGuildSticker<'_> {}
    impl Sealed for GetGuildStickers<'_> {}
    impl Sealed for GetGuildVanityUrl<'_> {}
    impl Sealed for GetGuildVoiceRegions<'_> {}
    impl Sealed for GetGuildWebhooks<'_> {}
    impl Sealed for GetGuildWelcomeScreen<'_> {}
    impl Sealed for GetGuildWidget<'_> {}
    impl Sealed for GetGuildWidgetSettings<'_> {}
    impl Sealed for GetInvite<'_> {}
    impl Sealed for GetJoinedPrivateArchivedThreads<'_> {}
    impl Sealed for GetMember<'_> {}
    impl Sealed for GetMessage<'_> {}
    impl Sealed for GetNitroStickerPacks<'_> {}
    impl Sealed for GetPins<'_> {}
    impl Sealed for GetPrivateArchivedThreads<'_> {}
    impl Sealed for GetPublicArchivedThreads<'_> {}
    impl Sealed for GetReactions<'_> {}
    impl Sealed for GetResponse<'_> {}
    impl Sealed for GetRole<'_> {}
    impl Sealed for GetSKUs<'_> {}
    impl Sealed for GetStageInstance<'_> {}
    impl Sealed for GetSticker<'_> {}
    impl Sealed for GetTemplate<'_> {}
    impl Sealed for GetTemplates<'_> {}
    impl Sealed for GetThreadMember<'_> {}
    impl Sealed for GetThreadMembers<'_> {}
    impl Sealed for GetUser<'_> {}
    impl Sealed for GetUserApplicationInfo<'_> {}
    impl Sealed for GetUserVoiceState<'_> {}
    impl Sealed for GetVoiceRegions<'_> {}
    impl Sealed for GetWebhook<'_> {}
    impl Sealed for GetWebhookMessage<'_> {}
    impl Sealed for JoinThread<'_> {}
    impl Sealed for LeaveGuild<'_> {}
    impl Sealed for LeaveThread<'_> {}
    impl Sealed for RemoveMember<'_> {}
    impl Sealed for RemoveRoleFromMember<'_> {}
    impl Sealed for RemoveThreadMember<'_> {}
    impl Sealed for SearchGuildMembers<'_> {}
    impl Sealed for SetGlobalCommands<'_> {}
    impl Sealed for SetGuildCommands<'_> {}
    impl Sealed for SyncTemplate<'_> {}
    impl Sealed for UpdateAutoModerationRule<'_> {}
    impl Sealed for UpdateChannel<'_> {}
    impl Sealed for UpdateChannelPermission<'_> {}
    impl Sealed for UpdateCommandPermissions<'_> {}
    impl Sealed for UpdateCurrentMember<'_> {}
    impl Sealed for UpdateCurrentUser<'_> {}
    impl Sealed for UpdateCurrentUserVoiceState<'_> {}
    impl Sealed for UpdateEmoji<'_> {}
    impl Sealed for UpdateFollowup<'_> {}
    impl Sealed for UpdateGlobalCommand<'_> {}
    impl Sealed for UpdateGuild<'_> {}
    impl Sealed for UpdateGuildChannelPositions<'_> {}
    impl Sealed for UpdateGuildCommand<'_> {}
    impl Sealed for UpdateGuildMember<'_> {}
    impl Sealed for UpdateGuildMfa<'_> {}
    impl Sealed for UpdateGuildOnboarding<'_> {}
    impl Sealed for UpdateGuildScheduledEvent<'_> {}
    impl Sealed for UpdateGuildSticker<'_> {}
    impl Sealed for UpdateGuildWelcomeScreen<'_> {}
    impl Sealed for UpdateGuildWidgetSettings<'_> {}
    impl Sealed for UpdateMessage<'_> {}
    impl Sealed for UpdateResponse<'_> {}
    impl Sealed for UpdateRole<'_> {}
    impl Sealed for UpdateRolePositions<'_> {}
    impl Sealed for UpdateStageInstance<'_> {}
    impl Sealed for UpdateTemplate<'_> {}
    impl Sealed for UpdateThread<'_> {}
    impl Sealed for UpdateUserVoiceState<'_> {}
    impl Sealed for UpdateWebhook<'_> {}
    impl Sealed for UpdateWebhookMessage<'_> {}
    impl Sealed for UpdateWebhookWithToken<'_> {}
    impl Sealed for UpdateCurrentUserApplication<'_> {}
}

use super::base::Request;
use crate::error::Error;

/// Convert a typed request builder into a raw [`Request`].
///
/// Converting a typed request builder into a raw request may be preferable in
/// order to verify whether a request is valid prior to passing it to
/// [`Client::request`].
///
/// Creating raw requests is useful for unit tests and debugging.
///
/// # Examples
///
/// Convert a [`CreateMessage`] builder into a [`Request`], inspect its body
/// and route, and then send the request:
///
/// ```no_run
/// # #[tokio::main] async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use std::{env, str};
/// use twilight_http::{client::Client, request::TryIntoRequest};
/// use twilight_model::{channel::Message, id::Id};
///
/// let client = Client::new(env::var("DISCORD_TOKEN")?);
/// let channel_id = Id::new(1);
/// let builder = client
///     .create_message(channel_id)
///     .content("This is a test message!")
///     .tts(false);
///
/// let request = builder.try_into_request()?;
///
/// println!("{:?} {}", request.method(), request.path());
///
/// if let Some(body) = request.body() {
///     println!("{}", str::from_utf8(body)?);
/// }
///
/// // Because a raw request is being performed, the output type must be
/// // explicit.
/// let response = client.request::<Message>(request).await?;
/// # Ok(()) }
/// ```
///
/// [`Client::request`]: crate::client::Client::request
/// [`CreateMessage`]: super::channel::message::CreateMessage
pub trait TryIntoRequest: private::Sealed {
    /// Try to convert a request builder into a raw [`Request`].
    ///
    /// # Errors
    ///
    /// Not all typed request builder conversions return an error and may
    /// instead always succeed. Refer to the documentation for each
    /// implementation for clarification.
    ///
    /// Requests may return an error type of [`ErrorType::CreatingHeader`] if
    /// creating an audit log header value fails.
    ///
    /// Requests may return an error type of [`ErrorType::Json`] if serializing
    /// a request body fails.
    ///
    /// [`ErrorType::CreatingHeader`]: crate::error::ErrorType::CreatingHeader
    /// [`ErrorType::Json`]: crate::error::ErrorType::Json
    fn try_into_request(self) -> Result<Request, Error>;
}

#[cfg(test)]
mod tests {
    use super::TryIntoRequest;
    use crate::{client::Client, request::Method};
    use static_assertions::assert_obj_safe;
    use std::error::Error;
    use twilight_model::id::Id;

    assert_obj_safe!(TryIntoRequest);

    #[test]
    fn conversion() -> Result<(), Box<dyn Error>> {
        let client = Client::new("token".to_owned());
        let channel_id = Id::new(1);
        let request = client
            .create_message(channel_id)
            .content("test")
            .try_into_request()?;

        assert_eq!(Some(br#"{"content":"test"}"#.as_ref()), request.body());
        assert!(request.form().is_none());
        assert_eq!(Method::Post, request.method());

        Ok(())
    }
}
