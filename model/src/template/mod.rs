mod guild;
mod role;

pub use guild::TemplateGuild;
pub use role::TemplateRole;

use crate::{
    datetime::Timestamp,
    id::{
        marker::{GuildMarker, UserMarker},
        Id,
    },
    user::User,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Template {
    pub code: String,
    pub created_at: Timestamp,
    /// User object of who created this template.
    pub creator: User,
    /// ID of the user who created this template.
    pub creator_id: Id<UserMarker>,
    pub description: Option<String>,
    /// Whether the template has unsynced changes.
    pub is_dirty: Option<bool>,
    pub name: String,
    pub serialized_source_guild: TemplateGuild,
    pub source_guild_id: Id<GuildMarker>,
    pub updated_at: Timestamp,
    pub usage_count: u64,
}

#[cfg(test)]
mod tests {
    use super::{Template, TemplateGuild, TemplateRole};
    use crate::{
        channel::{
            permission_overwrite::{PermissionOverwrite, PermissionOverwriteType},
            Channel, ChannelType,
        },
        datetime::{Timestamp, TimestampParseError},
        guild::{
            DefaultMessageNotificationLevel, ExplicitContentFilter, Permissions,
            SystemChannelFlags, VerificationLevel,
        },
        id::Id,
        test::image_hash,
        user::{User, UserFlags},
    };
    use serde_test::Token;
    use std::str::FromStr;

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_template() -> Result<(), TimestampParseError> {
        let created_at = Timestamp::from_str("2021-04-07T14:55:37+00:00")?;
        let updated_at = Timestamp::from_str("2021-04-07T14:55:37+00:00")?;

        let raw = format!(
            r#"{{
    "code": "code",
    "created_at": "2021-04-07T14:55:37+00:00",
    "creator": {{
        "accent_color": null,
        "avatar": "{avatar}",
        "banner": "{banner}",
        "discriminator": "1111",
        "id": "100",
        "public_flags": 0,
        "username": "username"
    }},
    "creator_id": "100",
    "description": "description",
    "is_dirty": null,
    "name": "name",
    "serialized_source_guild": {{
        "afk_channel_id": null,
        "afk_timeout": 300,
        "channels": [
            {{
                "bitrate": null,
                "id": 1,
                "name": "Text Channels",
                "nsfw": false,
                "parent_id": null,
                "permission_overwrites": [],
                "position": 0,
                "topic": null,
                "type": 4
            }},
            {{
                "bitrate": null,
                "id": 2,
                "name": "general",
                "nsfw": false,
                "parent_id": 1,
                "permission_overwrites": [
                    {{
                        "allow": "0",
                        "deny": "2048",
                        "id": 1,
                        "type": 0
                    }},
                    {{
                        "allow": "2048",
                        "deny": "0",
                        "id": 2,
                        "type": 0
                    }}
                ],
                "position": 0,
                "rate_limit_per_user": 0,
                "topic": null,
                "type": 0
            }},
            {{
                "bitrate": null,
                "id": 3,
                "name": "Voice Channels",
                "nsfw": false,
                "parent_id": null,
                "permission_overwrites": [],
                "position": 0,
                "topic": null,
                "type": 4
            }},
            {{
                "bitrate": 64000,
                "id": 4,
                "name": "General",
                "nsfw": false,
                "parent_id": 3,
                "permission_overwrites": [],
                "position": 0,
                "topic": null,
                "type": 2,
                "user_limit": 0
            }}
        ],
        "default_message_notifications": 0,
        "description": null,
        "explicit_content_filter": 0,
        "icon_hash": null,
        "name": "server name",
        "preferred_locale": "en-US",
        "roles": [
            {{
                "color": 0,
                "hoist": false,
                "id": 200,
                "mentionable": false,
                "name": "@everyone",
                "permissions": "104320577"
            }},
            {{
                "color": 0,
                "hoist": false,
                "id": 1,
                "mentionable": false,
                "name": "new role",
                "permissions": "104320577"
            }}
        ],
        "system_channel_flags": 0,
        "system_channel_id": 2,
        "verification_level": 0
    }},
    "source_guild_id": "200",
    "updated_at": "2021-04-07T14:55:37+00:00",
    "usage_count": 0
}}"#,
            avatar = image_hash::AVATAR_INPUT,
            banner = image_hash::BANNER_INPUT
        );

        let value = Template {
            code: "code".into(),
            created_at,
            creator: User {
                accent_color: None,
                avatar: Some(image_hash::AVATAR),
                banner: Some(image_hash::BANNER),
                bot: false,
                email: None,
                discriminator: 1111,
                flags: None,
                id: Id::new(100),
                locale: None,
                mfa_enabled: None,
                name: "username".into(),
                premium_type: None,
                public_flags: Some(UserFlags::empty()),
                system: None,
                verified: None,
            },
            creator_id: Id::new(100),
            description: Some("description".into()),
            is_dirty: None,
            name: "name".into(),
            serialized_source_guild: TemplateGuild {
                afk_channel_id: None,
                afk_timeout: 300,
                channels: Vec::from([
                    Channel {
                        application_id: None,
                        bitrate: None,
                        default_auto_archive_duration: None,
                        guild_id: None,
                        icon: None,
                        id: Id::new(1),
                        kind: ChannelType::GuildCategory,
                        name: Some("Text Channels".into()),
                        invitable: None,
                        last_message_id: None,
                        last_pin_timestamp: None,
                        nsfw: Some(false),
                        member: None,
                        member_count: None,
                        message_count: None,
                        owner_id: None,
                        parent_id: None,
                        permission_overwrites: Some(vec![]),
                        position: Some(0),
                        rate_limit_per_user: None,
                        recipients: None,
                        rtc_region: None,
                        topic: None,
                        thread_metadata: None,
                        user_limit: None,
                        video_quality_mode: None,
                    },
                    Channel {
                        application_id: None,
                        bitrate: None,
                        default_auto_archive_duration: None,
                        guild_id: None,
                        icon: None,
                        id: Id::new(2),
                        kind: ChannelType::GuildText,
                        name: Some("general".into()),
                        invitable: None,
                        last_message_id: None,
                        last_pin_timestamp: None,
                        nsfw: Some(false),
                        member: None,
                        member_count: None,
                        message_count: None,
                        owner_id: None,
                        parent_id: Some(Id::new(1)),
                        permission_overwrites: Some(vec![
                            PermissionOverwrite {
                                allow: Permissions::from_bits(0).unwrap(),
                                deny: Permissions::from_bits(2048).unwrap(),
                                kind: PermissionOverwriteType::Role(Id::new(1)),
                            },
                            PermissionOverwrite {
                                allow: Permissions::from_bits(2048).unwrap(),
                                deny: Permissions::from_bits(0).unwrap(),
                                kind: PermissionOverwriteType::Role(Id::new(2)),
                            },
                        ]),
                        position: Some(0),
                        rate_limit_per_user: Some(0),
                        recipients: None,
                        rtc_region: None,
                        topic: None,
                        thread_metadata: None,
                        user_limit: None,
                        video_quality_mode: None,
                    },
                    Channel {
                        application_id: None,
                        bitrate: None,
                        default_auto_archive_duration: None,
                        guild_id: None,
                        icon: None,
                        id: Id::new(3),
                        kind: ChannelType::GuildCategory,
                        name: Some("Voice Channels".into()),
                        invitable: None,
                        last_message_id: None,
                        last_pin_timestamp: None,
                        nsfw: Some(false),
                        member: None,
                        member_count: None,
                        message_count: None,
                        owner_id: None,
                        parent_id: None,
                        permission_overwrites: Some(vec![]),
                        position: Some(0),
                        rate_limit_per_user: None,
                        recipients: None,
                        rtc_region: None,
                        topic: None,
                        thread_metadata: None,
                        user_limit: None,
                        video_quality_mode: None,
                    },
                    Channel {
                        bitrate: Some(64000),
                        guild_id: None,
                        id: Id::new(4),
                        kind: ChannelType::GuildVoice,
                        name: Some("General".into()),
                        parent_id: Some(Id::new(3)),
                        permission_overwrites: Some(vec![]),
                        rtc_region: None,
                        position: Some(0),
                        user_limit: Some(0),
                        video_quality_mode: None,
                        application_id: None,
                        default_auto_archive_duration: None,
                        icon: None,
                        invitable: None,
                        last_message_id: None,
                        last_pin_timestamp: None,
                        nsfw: Some(false),
                        member: None,
                        member_count: None,
                        message_count: None,
                        owner_id: None,
                        rate_limit_per_user: None,
                        recipients: None,
                        topic: None,
                        thread_metadata: None,
                    },
                ]),
                default_message_notifications: DefaultMessageNotificationLevel::All,
                description: None,
                explicit_content_filter: ExplicitContentFilter::None,
                icon_hash: None,
                name: "server name".into(),
                preferred_locale: "en-US".into(),
                roles: vec![
                    TemplateRole {
                        color: 0,
                        hoist: false,
                        id: Id::new(200),
                        mentionable: false,
                        name: "@everyone".into(),
                        permissions: Permissions::CREATE_INVITE
                            | Permissions::ADD_REACTIONS
                            | Permissions::STREAM
                            | Permissions::VIEW_CHANNEL
                            | Permissions::SEND_MESSAGES
                            | Permissions::EMBED_LINKS
                            | Permissions::ATTACH_FILES
                            | Permissions::READ_MESSAGE_HISTORY
                            | Permissions::MENTION_EVERYONE
                            | Permissions::USE_EXTERNAL_EMOJIS
                            | Permissions::CONNECT
                            | Permissions::SPEAK
                            | Permissions::USE_VAD
                            | Permissions::CHANGE_NICKNAME,
                        tags: None,
                    },
                    TemplateRole {
                        color: 0,
                        hoist: false,
                        id: Id::new(1),
                        mentionable: false,
                        name: "new role".into(),
                        permissions: Permissions::CREATE_INVITE
                            | Permissions::ADD_REACTIONS
                            | Permissions::STREAM
                            | Permissions::VIEW_CHANNEL
                            | Permissions::SEND_MESSAGES
                            | Permissions::EMBED_LINKS
                            | Permissions::ATTACH_FILES
                            | Permissions::READ_MESSAGE_HISTORY
                            | Permissions::MENTION_EVERYONE
                            | Permissions::USE_EXTERNAL_EMOJIS
                            | Permissions::CONNECT
                            | Permissions::SPEAK
                            | Permissions::USE_VAD
                            | Permissions::CHANGE_NICKNAME,
                        tags: None,
                    },
                ],
                system_channel_flags: SystemChannelFlags::empty(),
                system_channel_id: Some(Id::new(2)),
                verification_level: VerificationLevel::None,
            },
            source_guild_id: Id::new(200),
            updated_at,
            usage_count: 0,
        };

        let deserialized = serde_json::from_str::<Template>(&raw).unwrap();

        assert_eq!(deserialized, value);

        serde_test::assert_tokens(
            &value,
            &[
                Token::Struct {
                    name: "Template",
                    len: 11,
                },
                Token::Str("code"),
                Token::Str("code"),
                Token::Str("created_at"),
                Token::Str("2021-04-07T14:55:37.000000+00:00"),
                Token::Str("creator"),
                Token::Struct {
                    name: "User",
                    len: 8,
                },
                Token::Str("accent_color"),
                Token::None,
                Token::Str("avatar"),
                Token::Some,
                Token::Str(image_hash::AVATAR_INPUT),
                Token::Str("banner"),
                Token::Some,
                Token::Str(image_hash::BANNER_INPUT),
                Token::Str("bot"),
                Token::Bool(false),
                Token::Str("discriminator"),
                Token::Str("1111"),
                Token::Str("id"),
                Token::NewtypeStruct { name: "Id" },
                Token::Str("100"),
                Token::Str("username"),
                Token::Str("username"),
                Token::Str("public_flags"),
                Token::Some,
                Token::U64(0),
                Token::StructEnd,
                Token::Str("creator_id"),
                Token::NewtypeStruct { name: "Id" },
                Token::Str("100"),
                Token::Str("description"),
                Token::Some,
                Token::Str("description"),
                Token::Str("is_dirty"),
                Token::None,
                Token::Str("name"),
                Token::Str("name"),
                Token::Str("serialized_source_guild"),
                Token::Struct {
                    name: "TemplateGuild",
                    len: 13,
                },
                Token::Str("afk_channel_id"),
                Token::None,
                Token::Str("afk_timeout"),
                Token::U64(300),
                Token::Str("channels"),
                Token::Seq { len: Some(4) },
                Token::Struct {
                    name: "Channel",
                    len: 6,
                },
                Token::Str("id"),
                Token::NewtypeStruct { name: "Id" },
                Token::Str("1"),
                Token::Str("type"),
                Token::U8(4),
                Token::Str("name"),
                Token::Some,
                Token::Str("Text Channels"),
                Token::Str("nsfw"),
                Token::Some,
                Token::Bool(false),
                Token::Str("permission_overwrites"),
                Token::Some,
                Token::Seq { len: Some(0) },
                Token::SeqEnd,
                Token::Str("position"),
                Token::Some,
                Token::I64(0),
                Token::StructEnd,
                Token::Struct {
                    name: "Channel",
                    len: 8,
                },
                Token::Str("id"),
                Token::NewtypeStruct { name: "Id" },
                Token::Str("2"),
                Token::Str("type"),
                Token::U8(0),
                Token::Str("name"),
                Token::Some,
                Token::Str("general"),
                Token::Str("nsfw"),
                Token::Some,
                Token::Bool(false),
                Token::Str("parent_id"),
                Token::Some,
                Token::NewtypeStruct { name: "Id" },
                Token::Str("1"),
                Token::Str("permission_overwrites"),
                Token::Some,
                Token::Seq { len: Some(2) },
                Token::Struct {
                    name: "PermissionOverwriteData",
                    len: 4,
                },
                Token::Str("allow"),
                Token::Str("0"),
                Token::Str("deny"),
                Token::Str("2048"),
                Token::Str("id"),
                Token::Str("1"),
                Token::Str("type"),
                Token::U8(0),
                Token::StructEnd,
                Token::Struct {
                    name: "PermissionOverwriteData",
                    len: 4,
                },
                Token::Str("allow"),
                Token::Str("2048"),
                Token::Str("deny"),
                Token::Str("0"),
                Token::Str("id"),
                Token::Str("2"),
                Token::Str("type"),
                Token::U8(0),
                Token::StructEnd,
                Token::SeqEnd,
                Token::Str("position"),
                Token::Some,
                Token::I64(0),
                Token::Str("rate_limit_per_user"),
                Token::Some,
                Token::U16(0),
                Token::StructEnd,
                Token::Struct {
                    name: "Channel",
                    len: 6,
                },
                Token::Str("id"),
                Token::NewtypeStruct { name: "Id" },
                Token::Str("3"),
                Token::Str("type"),
                Token::U8(4),
                Token::Str("name"),
                Token::Some,
                Token::Str("Voice Channels"),
                Token::Str("nsfw"),
                Token::Some,
                Token::Bool(false),
                Token::Str("permission_overwrites"),
                Token::Some,
                Token::Seq { len: Some(0) },
                Token::SeqEnd,
                Token::Str("position"),
                Token::Some,
                Token::I64(0),
                Token::StructEnd,
                Token::Struct {
                    name: "Channel",
                    len: 9,
                },
                Token::Str("bitrate"),
                Token::Some,
                Token::U32(64000),
                Token::Str("id"),
                Token::NewtypeStruct { name: "Id" },
                Token::Str("4"),
                Token::Str("type"),
                Token::U8(2),
                Token::Str("name"),
                Token::Some,
                Token::Str("General"),
                Token::Str("nsfw"),
                Token::Some,
                Token::Bool(false),
                Token::Str("parent_id"),
                Token::Some,
                Token::NewtypeStruct { name: "Id" },
                Token::Str("3"),
                Token::Str("permission_overwrites"),
                Token::Some,
                Token::Seq { len: Some(0) },
                Token::SeqEnd,
                Token::Str("position"),
                Token::Some,
                Token::I64(0),
                Token::Str("user_limit"),
                Token::Some,
                Token::U16(0),
                Token::StructEnd,
                Token::SeqEnd,
                Token::Str("default_message_notifications"),
                Token::U8(0),
                Token::Str("description"),
                Token::None,
                Token::Str("explicit_content_filter"),
                Token::U8(0),
                Token::Str("icon_hash"),
                Token::None,
                Token::Str("name"),
                Token::Str("server name"),
                Token::Str("preferred_locale"),
                Token::Str("en-US"),
                Token::Str("roles"),
                Token::Seq { len: Some(2) },
                Token::Struct {
                    name: "TemplateRole",
                    len: 6,
                },
                Token::Str("color"),
                Token::U32(0),
                Token::Str("hoist"),
                Token::Bool(false),
                Token::Str("id"),
                Token::NewtypeStruct { name: "Id" },
                Token::Str("200"),
                Token::Str("mentionable"),
                Token::Bool(false),
                Token::Str("name"),
                Token::Str("@everyone"),
                Token::Str("permissions"),
                Token::Str("104320577"),
                Token::StructEnd,
                Token::Struct {
                    name: "TemplateRole",
                    len: 6,
                },
                Token::Str("color"),
                Token::U32(0),
                Token::Str("hoist"),
                Token::Bool(false),
                Token::Str("id"),
                Token::NewtypeStruct { name: "Id" },
                Token::Str("1"),
                Token::Str("mentionable"),
                Token::Bool(false),
                Token::Str("name"),
                Token::Str("new role"),
                Token::Str("permissions"),
                Token::Str("104320577"),
                Token::StructEnd,
                Token::SeqEnd,
                Token::Str("system_channel_flags"),
                Token::U64(0),
                Token::Str("system_channel_id"),
                Token::Some,
                Token::NewtypeStruct { name: "Id" },
                Token::Str("2"),
                Token::Str("verification_level"),
                Token::U8(0),
                Token::StructEnd,
                Token::Str("source_guild_id"),
                Token::NewtypeStruct { name: "Id" },
                Token::Str("200"),
                Token::Str("updated_at"),
                Token::Str("2021-04-07T14:55:37.000000+00:00"),
                Token::Str("usage_count"),
                Token::U64(0),
                Token::StructEnd,
            ],
        );

        Ok(())
    }
}
