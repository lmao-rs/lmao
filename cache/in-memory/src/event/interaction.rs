use crate::{config::ResourceType, InMemoryCache, UpdateCache};
use std::borrow::Cow;
use twilight_model::{
    application::interaction::Interaction, gateway::payload::incoming::InteractionCreate,
};

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
                    for u in resolved.users.values() {
                        cache.cache_user(Cow::Borrowed(u), command.guild_id);

                        if !cache.wants(ResourceType::MEMBER) || command.guild_id.is_none() {
                            continue;
                        }

                        // This should always match, because resolved members
                        // are guaranteed to have a matching resolved user
                        if let Some((&id, member)) =
                            &resolved.members.iter().find(|(&id, _)| id == u.id)
                        {
                            if let Some(guild_id) = command.guild_id {
                                cache.cache_borrowed_interaction_member(guild_id, member, id);
                            }
                        }
                    }

                    if cache.wants(ResourceType::ROLE) {
                        if let Some(guild_id) = command.guild_id {
                            cache.cache_roles(
                                guild_id,
                                resolved.roles.iter().map(|(_, v)| v).cloned(),
                            );
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
    use std::collections::HashMap;
    use twilight_model::{
        application::interaction::{
            application_command::{CommandData, CommandInteractionDataResolved, InteractionMember},
            ApplicationCommand, InteractionType,
        },
        channel::{
            message::{
                sticker::{MessageSticker, StickerFormatType},
                MessageFlags, MessageType,
            },
            Message,
        },
        datetime::Timestamp,
        guild::{PartialMember, Permissions, Role},
        id::Id,
        user::User,
    };

    #[test]
    fn test_interaction_create() {
        let timestamp = Timestamp::from_secs(1_632_072_645).expect("non zero");

        let cache = InMemoryCache::new();
        cache.update(&InteractionCreate(Interaction::ApplicationCommand(
            Box::new(ApplicationCommand {
                application_id: Id::new(1).expect("non zero"),
                channel_id: Id::new(2).expect("non zero"),
                data: CommandData {
                    id: Id::new(5).expect("non zero"),
                    name: "command name".into(),
                    options: Vec::new(),
                    resolved: Some(CommandInteractionDataResolved {
                        channels: HashMap::new(),
                        members: IntoIterator::into_iter([(
                            Id::new(7).expect("non zero"),
                            InteractionMember {
                                avatar: None,
                                joined_at: timestamp,
                                nick: None,
                                pending: false,
                                permissions: Permissions::empty(),
                                premium_since: None,
                                roles: vec![Id::new(8).expect("non zero")],
                            },
                        )])
                        .collect(),
                        messages: IntoIterator::into_iter([(
                            Id::new(4).expect("non zero"),
                            Message {
                                activity: None,
                                application: None,
                                application_id: None,
                                attachments: Vec::new(),
                                author: User {
                                    accent_color: None,
                                    avatar: Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned()),
                                    banner: None,
                                    bot: false,
                                    discriminator: 1,
                                    email: None,
                                    flags: None,
                                    id: Id::new(3).expect("non zero"),
                                    locale: None,
                                    mfa_enabled: None,
                                    name: "test".to_owned(),
                                    premium_type: None,
                                    public_flags: None,
                                    system: None,
                                    verified: None,
                                },
                                channel_id: Id::new(2).expect("non zero"),
                                components: Vec::new(),
                                content: "ping".to_owned(),
                                edited_timestamp: None,
                                embeds: Vec::new(),
                                flags: Some(MessageFlags::empty()),
                                guild_id: Some(Id::new(1).expect("non zero")),
                                id: Id::new(4).expect("non zero"),
                                interaction: None,
                                kind: MessageType::Regular,
                                member: Some(PartialMember {
                                    avatar: None,
                                    deaf: false,
                                    joined_at: timestamp,
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
                                    id: Id::new(1).expect("non zero"),
                                    name: "sticker name".to_owned(),
                                }],
                                referenced_message: None,
                                thread: None,
                                timestamp,
                                tts: false,
                                webhook_id: None,
                            },
                        )])
                        .collect(),
                        roles: IntoIterator::into_iter([(
                            Id::new(8).expect("non zero"),
                            Role {
                                color: 0u32,
                                hoist: false,
                                icon: None,
                                id: Id::new(8).expect("non zero"),
                                managed: false,
                                mentionable: true,
                                name: "role name".into(),
                                permissions: Permissions::empty(),
                                position: 2i64,
                                tags: None,
                                unicode_emoji: None,
                            },
                        )])
                        .collect(),
                        users: IntoIterator::into_iter([(
                            Id::new(7).expect("non zero"),
                            User {
                                accent_color: None,
                                avatar: Some("different avatar".into()),
                                banner: None,
                                bot: false,
                                discriminator: 5678,
                                email: None,
                                flags: None,
                                id: Id::new(7).expect("non zero"),
                                locale: None,
                                mfa_enabled: None,
                                name: "different name".into(),
                                premium_type: None,
                                public_flags: None,
                                system: None,
                                verified: None,
                            },
                        )])
                        .collect(),
                    }),
                },
                guild_id: Some(Id::new(3).expect("non zero")),
                id: Id::new(4).expect("non zero"),
                kind: InteractionType::ApplicationCommand,
                member: Some(PartialMember {
                    avatar: None,
                    deaf: false,
                    joined_at: timestamp,
                    mute: false,
                    nick: None,
                    permissions: Some(Permissions::empty()),
                    premium_since: None,
                    roles: Vec::new(),
                    user: Some(User {
                        accent_color: None,
                        avatar: Some("avatar string".into()),
                        banner: None,
                        bot: false,
                        discriminator: 1234,
                        email: None,
                        flags: None,
                        id: Id::new(6).expect("non zero"),
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
            let guild_members = cache.guild_members(Id::new(3).expect("non zero")).unwrap();
            assert_eq!(guild_members.len(), 2);
        }

        {
            let member = cache
                .member(Id::new(3).expect("non zero"), Id::new(6).expect("non zero"))
                .unwrap();
            let user = cache.user(member.user_id).unwrap();
            assert_eq!(user.avatar.as_ref().unwrap(), "avatar string");
        }

        {
            let member = cache
                .member(Id::new(3).expect("non zero"), Id::new(7).expect("non zero"))
                .unwrap();
            let user = cache.user(member.user_id).unwrap();
            assert_eq!(user.avatar.as_ref().unwrap(), "different avatar");
        }

        {
            let guild_roles = cache.guild_roles(Id::new(3).expect("non zero")).unwrap();
            assert_eq!(guild_roles.len(), 1);
        }
    }
}
