use crate::{config::ResourceType, InMemoryCache, UpdateCache};
use std::borrow::Cow;
use twilight_model::{application::interaction::Interaction, gateway::payload::InteractionCreate};

impl UpdateCache for InteractionCreate {
    fn update(&self, cache: &InMemoryCache) {
        #[allow(clippy::single_match)]
        match &self.0 {
            Interaction::ApplicationCommand(command) => {
                if cache.wants(ResourceType::MEMBER) {
                    if let Some(member) = &command.member {
                        if let Some(user) = &member.user {
                            cache.cache_user(Cow::Borrowed(user), command.guild_id);

                            cache.cache_borrowed_partial_member(
                                command.guild_id.unwrap(),
                                member,
                                user.id,
                            );
                        }
                    }
                }

                if let Some(user) = &command.user {
                    cache.cache_user(Cow::Borrowed(user), None);
                }

                if let Some(resolved) = &command.data.resolved {
                    for u in &resolved.users {
                        cache.cache_user(Cow::Borrowed(u), command.guild_id);

                        if !cache.wants(ResourceType::MEMBER) || command.guild_id.is_none() {
                            continue;
                        }

                        // This should always match, because resolved members
                        // are guaranteed to have a matching resolved user
                        if let Some(member) = &resolved.members.iter().find(|m| m.id == u.id) {
                            if let Some(guild_id) = command.guild_id {
                                cache.cache_borrowed_interaction_member(guild_id, member);
                            }
                        }
                    }

                    if cache.wants(ResourceType::ROLE) {
                        if let Some(guild_id) = command.guild_id {
                            cache.cache_roles(guild_id, resolved.roles.iter().cloned());
                        }
                    }
                }
            }
            _ => {}
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use twilight_model::{
        application::interaction::{
            application_command::{CommandData, CommandInteractionDataResolved, InteractionMember},
            ApplicationCommand, InteractionType,
        },
        channel::{
            message::{
                sticker::{MessageSticker, StickerFormatType, StickerId},
                MessageFlags, MessageType,
            },
            Message,
        },
        guild::{PartialMember, Permissions, Role},
        id::{
            ApplicationId, ChannelId, CommandId, GuildId, InteractionId, MessageId, RoleId, UserId,
        },
        user::User,
    };

    #[test]
    fn test_interaction_create() {
        let cache = InMemoryCache::new();
        cache.update(&InteractionCreate(Interaction::ApplicationCommand(
            Box::new(ApplicationCommand {
                application_id: ApplicationId(1),
                channel_id: ChannelId(2),
                data: CommandData {
                    id: CommandId(5),
                    name: "command name".into(),
                    options: Vec::new(),
                    resolved: Some(CommandInteractionDataResolved {
                        channels: Vec::new(),
                        members: Vec::from([InteractionMember {
                            hoisted_role: None,
                            id: UserId(7),
                            joined_at: Some("joined at date".into()),
                            nick: None,
                            premium_since: None,
                            roles: vec![RoleId(8)],
                        }]),
                        messages: Vec::from([Message {
                            activity: None,
                            application: None,
                            application_id: None,
                            attachments: Vec::new(),
                            author: User {
                                avatar: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()),
                                bot: false,
                                discriminator: "0001".to_owned(),
                                email: None,
                                flags: None,
                                id: UserId(3),
                                locale: None,
                                mfa_enabled: None,
                                name: "test".to_owned(),
                                premium_type: None,
                                public_flags: None,
                                system: None,
                                verified: None,
                            },
                            channel_id: ChannelId(2),
                            components: Vec::new(),
                            content: "ping".to_owned(),
                            edited_timestamp: None,
                            embeds: Vec::new(),
                            flags: Some(MessageFlags::empty()),
                            guild_id: Some(GuildId(1)),
                            id: MessageId(4),
                            interaction: None,
                            kind: MessageType::Regular,
                            member: Some(PartialMember {
                                deaf: false,
                                joined_at: Some("2020-01-01T00:00:00.000000+00:00".to_owned()),
                                mute: false,
                                nick: Some("member nick".to_owned()),
                                permissions: None,
                                premium_since: None,
                                roles: Vec::new(),
                                user: None,
                            }),
                            mention_channels: Vec::new(),
                            mention_everyone: false,
                            mention_roles: Vec::new(),
                            mentions: Vec::new(),
                            pinned: false,
                            reactions: Vec::new(),
                            reference: None,
                            sticker_items: vec![MessageSticker {
                                format_type: StickerFormatType::Png,
                                id: StickerId(1),
                                name: "sticker name".to_owned(),
                            }],
                            referenced_message: None,
                            timestamp: "2020-02-02T02:02:02.020000+00:00".to_owned(),
                            tts: false,
                            webhook_id: None,
                        }]),
                        roles: Vec::from([Role {
                            color: 0u32,
                            hoist: false,
                            id: RoleId(8),
                            managed: false,
                            mentionable: true,
                            name: "role name".into(),
                            permissions: Permissions::empty(),
                            position: 2i64,
                            tags: None,
                        }]),
                        users: Vec::from([User {
                            avatar: Some("different avatar".into()),
                            bot: false,
                            discriminator: "5678".into(),
                            email: None,
                            flags: None,
                            id: UserId(7),
                            locale: None,
                            mfa_enabled: None,
                            name: "different name".into(),
                            premium_type: None,
                            public_flags: None,
                            system: None,
                            verified: None,
                        }]),
                    }),
                },
                guild_id: Some(GuildId(3)),
                id: InteractionId(4),
                kind: InteractionType::ApplicationCommand,
                member: Some(PartialMember {
                    deaf: false,
                    joined_at: Some("joined at".into()),
                    mute: false,
                    nick: None,
                    permissions: Some(Permissions::empty()),
                    premium_since: None,
                    roles: Vec::new(),
                    user: Some(User {
                        avatar: Some("avatar string".into()),
                        bot: false,
                        discriminator: "1234".into(),
                        email: None,
                        flags: None,
                        id: UserId(6),
                        locale: None,
                        mfa_enabled: None,
                        name: "username".into(),
                        premium_type: None,
                        public_flags: None,
                        system: None,
                        verified: None,
                    }),
                }),
                token: "token".into(),
                user: None,
            }),
        )));

        {
            let guild_members = cache.guild_members(GuildId(3)).unwrap();
            assert_eq!(guild_members.len(), 2);
        }

        {
            let member = cache.member(GuildId(3), UserId(6)).unwrap();
            let user = cache.user(member.user_id).unwrap();
            assert_eq!(user.avatar.unwrap(), "avatar string");
        }

        {
            let member = cache.member(GuildId(3), UserId(7)).unwrap();
            let user = cache.user(member.user_id).unwrap();
            assert_eq!(user.avatar.unwrap(), "different avatar");
        }

        {
            let guild_roles = cache.guild_roles(GuildId(3)).unwrap();
            assert_eq!(guild_roles.len(), 1);
        }
    }
}
