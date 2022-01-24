use crate::channel::{
    permission_overwrite::PermissionOverwrite,
    thread::{AutoArchiveDuration, ThreadMember, ThreadMetadata},
    ChannelType,
};
use crate::id::{
    marker::{ChannelMarker, GuildMarker, MessageMarker, UserMarker},
    Id,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct PrivateThread {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_auto_archive_duration: Option<AutoArchiveDuration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guild_id: Option<Id<GuildMarker>>,
    pub id: Id<ChannelMarker>,
    /// Whether non-moderators can add other non-moderators to a thread.
    ///
    /// Only available on private threads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invitable: Option<bool>,
    #[serde(rename = "type")]
    pub kind: ChannelType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_message_id: Option<Id<MessageMarker>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub member: Option<ThreadMember>,
    /// Max value of 50.
    pub member_count: u8,
    /// Max value of 50.
    pub message_count: u8,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<Id<UserMarker>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<Id<ChannelMarker>>,
    pub permission_overwrites: Vec<PermissionOverwrite>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_per_user: Option<u64>,
    pub thread_metadata: ThreadMetadata,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::{ChannelType, ThreadMember, ThreadMetadata};
    use crate::{
        channel::thread::{AutoArchiveDuration, PrivateThread},
        datetime::{Timestamp, TimestampParseError},
        id::Id,
    };
    use serde_test::Token;

    #[test]
    #[allow(clippy::too_many_lines)]
    fn test_private_thread() -> Result<(), TimestampParseError> {
        const DATETIME: &str = "2021-09-19T14:17:32.000000+00:00";

        let timestamp = Timestamp::from_str(DATETIME)?;

        let value = PrivateThread {
            default_auto_archive_duration: Some(AutoArchiveDuration::Hour),
            guild_id: Some(Id::new(2)),
            id: Id::new(1),
            invitable: Some(true),
            kind: ChannelType::GuildPrivateThread,
            last_message_id: Some(Id::new(5)),
            member: Some(ThreadMember {
                flags: 12,
                id: Some(Id::new(10)),
                join_timestamp: timestamp,
                member: None,
                presence: None,
                user_id: Some(Id::new(11)),
            }),
            member_count: 7,
            message_count: 6,
            name: "test".to_owned(),
            owner_id: Some(Id::new(3)),
            parent_id: Some(Id::new(4)),
            permission_overwrites: Vec::new(),
            rate_limit_per_user: Some(8),
            thread_metadata: ThreadMetadata {
                archived: true,
                auto_archive_duration: AutoArchiveDuration::Hour,
                archive_timestamp: timestamp,
                create_timestamp: Some(timestamp),
                invitable: Some(true),
                locked: true,
            },
        };

        serde_test::assert_tokens(
            &value,
            &[
                Token::Struct {
                    name: "PrivateThread",
                    len: 15,
                },
                Token::Str("default_auto_archive_duration"),
                Token::Some,
                Token::U16(60),
                Token::Str("guild_id"),
                Token::Some,
                Token::NewtypeStruct { name: "Id" },
                Token::Str("2"),
                Token::Str("id"),
                Token::NewtypeStruct { name: "Id" },
                Token::Str("1"),
                Token::Str("invitable"),
                Token::Some,
                Token::Bool(true),
                Token::Str("type"),
                Token::U8(12),
                Token::Str("last_message_id"),
                Token::Some,
                Token::NewtypeStruct { name: "Id" },
                Token::Str("5"),
                Token::Str("member"),
                Token::Some,
                Token::Struct {
                    name: "ThreadMember",
                    len: 4,
                },
                Token::Str("flags"),
                Token::U64(12),
                Token::Str("id"),
                Token::Some,
                Token::NewtypeStruct { name: "Id" },
                Token::Str("10"),
                Token::Str("join_timestamp"),
                Token::Str(DATETIME),
                Token::Str("user_id"),
                Token::Some,
                Token::NewtypeStruct { name: "Id" },
                Token::Str("11"),
                Token::StructEnd,
                Token::Str("member_count"),
                Token::U8(7),
                Token::Str("message_count"),
                Token::U8(6),
                Token::Str("name"),
                Token::Str("test"),
                Token::Str("owner_id"),
                Token::Some,
                Token::NewtypeStruct { name: "Id" },
                Token::Str("3"),
                Token::Str("parent_id"),
                Token::Some,
                Token::NewtypeStruct { name: "Id" },
                Token::Str("4"),
                Token::Str("permission_overwrites"),
                Token::Seq { len: Some(0) },
                Token::SeqEnd,
                Token::Str("rate_limit_per_user"),
                Token::Some,
                Token::U64(8),
                Token::Str("thread_metadata"),
                Token::Struct {
                    name: "ThreadMetadata",
                    len: 6,
                },
                Token::Str("archived"),
                Token::Bool(true),
                Token::Str("auto_archive_duration"),
                Token::U16(60),
                Token::Str("archive_timestamp"),
                Token::Str(DATETIME),
                Token::Str("create_timestamp"),
                Token::Some,
                Token::Str(DATETIME),
                Token::Str("invitable"),
                Token::Some,
                Token::Bool(true),
                Token::Str("locked"),
                Token::Bool(true),
                Token::StructEnd,
                Token::StructEnd,
            ],
        );

        Ok(())
    }
}
