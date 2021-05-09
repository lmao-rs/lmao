use serde::{Deserialize, Serialize};
use crate::id::{GuildId, ChannelId, MessageId, UserId};
use crate::channel::{ChannelType, ThreadMember, ThreadMetadata};

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct PublicThread {
    pub id: ChannelId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guild_id: Option<GuildId>,
    #[serde(rename = "type")]
    pub kind: ChannelType,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<UserId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<ChannelId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_message_id: Option<MessageId>,
    pub message_count: u8,
    /// Max value of 50.
    pub member_count: u8,
    /// Max value of 50.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit_per_user: Option<u64>,
    pub thread_metadata: ThreadMetadata,
    pub member: ThreadMember,
}

#[cfg(test)]
mod tests {
    use super::PublicThread;
    use serde_test::Token;
    use crate::{
        channel::{AutoArchiveDuration, ChannelType, ThreadMember, ThreadMetadata},
        id::{ChannelId, GuildId, MessageId, UserId},
    };

    #[test]
    fn test_public_thread() {
        let value = PublicThread {
            id: ChannelId(1),
            guild_id: Some(GuildId(2)),
            kind: ChannelType::GuildPublicThread,
            name: "test".to_owned(),
            owner_id: Some(UserId(3)),
            parent_id: Some(ChannelId(4)),
            last_message_id: Some(MessageId(5)),
            message_count: 6,
            member_count: 7,
            rate_limit_per_user: Some(8),
            thread_metadata: ThreadMetadata {
                archived: true,
                archiver_id: Some(UserId(9)),
                auto_archive_duration: AutoArchiveDuration::Hour,
                archive_timestamp: "123".to_string(),
                locked: true,
            },
            member: ThreadMember {
                id: ChannelId(10),
                user_id: UserId(11),
                join_timestamp: "456".to_owned(),
                flags: 12
            },
        };

        serde_test::assert_tokens(
            &value,
            &[
                Token::Struct {
                    name: "PublicThread",
                    len: 12,
                },
                Token::Str("id"),
                Token::NewtypeStruct { name: "ChannelId" },
                Token::Str("1"),
                Token::Str("guild_id"),
                Token::Some,
                Token::NewtypeStruct { name: "GuildId" },
                Token::Str("2"),
                Token::Str("type"),
                Token::U8(11),
                Token::Str("name"),
                Token::Str("test"),
                Token::Str("owner_id"),
                Token::Some,
                Token::NewtypeStruct { name: "UserId" },
                Token::Str("3"),
                Token::Str("parent_id"),
                Token::Some,
                Token::NewtypeStruct { name: "ChannelId" },
                Token::Str("4"),
                Token::Str("last_message_id"),
                Token::Some,
                Token::NewtypeStruct { name: "MessageId" },
                Token::Str("5"),
                Token::Str("message_count"),
                Token::U8(6),
                Token::Str("member_count"),
                Token::U8(7),
                Token::Str("rate_limit_per_user"),
                Token::Some,
                Token::U64(8),
                Token::Str("thread_metadata"),
                Token::Struct {
                    name: "ThreadMetadata",
                    len: 5,
                },
                Token::Str("archived"),
                Token::Bool(true),
                Token::Str("archiver_id"),
                Token::Some,
                Token::NewtypeStruct { name: "UserId" },
                Token::Str("9"),
                Token::Str("auto_archive_duration"),
                Token::U16(60),
                Token::Str("archive_timestamp"),
                Token::Str("123"),
                Token::Str("locked"),
                Token::Bool(true),
                Token::StructEnd,
                Token::Str("member"),
                Token::Struct {
                    name: "ThreadMember",
                    len: 4,
                },
                Token::Str("id"),
                Token::NewtypeStruct { name: "ChannelId" },
                Token::Str("10"),
                Token::Str("user_id"),
                Token::NewtypeStruct { name: "UserId" },
                Token::Str("11"),
                Token::Str("join_timestamp"),
                Token::Str("456"),
                Token::Str("flags"),
                Token::U64(12),
                Token::StructEnd,
                Token::StructEnd,
            ],
        );
    }
}
