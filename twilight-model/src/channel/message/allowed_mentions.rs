use crate::{
    id::{
        marker::{RoleMarker, UserMarker},
        Id,
    },
    util::{is_false, known_string::KnownString},
};
use serde::{Deserialize, Serialize};

/// Allowed mentions (pings).
///
/// Filters mentions to only ping one's specified here, regardless of the message's content[^1].
///
/// Mentions can be clicked to reveal additional context, whilst only requiring an ID to create. See
/// [Discord Docs/Message Formatting].
///
/// [`AllowedMentions::default`] disallows all pings.
///
/// [^1]: Messages must still contain mentions, e.g. `@everyone`!
///
/// [Discord Docs/Message Formatting]: https://discord.com/developers/docs/reference#message-formatting
#[derive(Clone, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct AllowedMentions {
    /// List of allowed mention types.
    ///
    /// [`MentionType::ROLES`] and [`MentionType::USERS`] allows all roles and users to be
    /// mentioned; they are mutually exclusive with the [`roles`] and [`users`] fields.
    ///
    /// [`roles`]: Self::roles
    /// [`users`]: Self::users
    #[serde(default)]
    pub parse: Vec<MentionType>,
    /// For replies, whether to mention the message author.
    ///
    /// Defaults to false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub replied_user: bool,
    /// List of roles to mention.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<Id<RoleMarker>>,
    /// List of users to mention.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<Id<UserMarker>>,
}

/// Allowed mention type.
#[derive(Clone, Copy, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct MentionType(KnownString<16>);

impl MentionType {
    /// `@everyone` and `@here` mentions.
    pub const EVERYONE: Self = Self::from_bytes(b"everyone");

    /// Role mentions.
    pub const ROLES: Self = Self::from_bytes(b"roles");

    /// User mentions.
    pub const USERS: Self = Self::from_bytes(b"users");

    /// Name of the associated constant.
    ///
    /// Returns `None` if the value doesn't have a defined constant.
    pub const fn name(self) -> Option<&'static str> {
        Some(match self {
            Self::EVERYONE => "EVERYONE",
            Self::ROLES => "ROLES",
            Self::USERS => "USERS",
            _ => return None,
        })
    }
}

impl_typed!(MentionType, String);

#[cfg(test)]
mod tests {
    use super::{AllowedMentions, MentionType};
    use crate::id::Id;
    use serde_test::Token;

    #[test]
    fn minimal() {
        let value = AllowedMentions {
            parse: Vec::new(),
            users: Vec::new(),
            roles: Vec::new(),
            replied_user: false,
        };

        serde_test::assert_tokens(
            &value,
            &[
                Token::Struct {
                    name: "AllowedMentions",
                    len: 1,
                },
                Token::Str("parse"),
                Token::Seq { len: Some(0) },
                Token::SeqEnd,
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn full() {
        let value = AllowedMentions {
            parse: Vec::from([MentionType::EVERYONE]),
            users: Vec::from([Id::new(100)]),
            roles: Vec::from([Id::new(200)]),
            replied_user: true,
        };

        serde_test::assert_tokens(
            &value,
            &[
                Token::Struct {
                    name: "AllowedMentions",
                    len: 4,
                },
                Token::Str("parse"),
                Token::Seq { len: Some(1) },
                Token::NewtypeStruct {
                    name: "MentionType",
                },
                Token::Str("everyone"),
                Token::SeqEnd,
                Token::Str("replied_user"),
                Token::Bool(true),
                Token::Str("roles"),
                Token::Seq { len: Some(1) },
                Token::NewtypeStruct { name: "Id" },
                Token::Str("200"),
                Token::SeqEnd,
                Token::Str("users"),
                Token::Seq { len: Some(1) },
                Token::NewtypeStruct { name: "Id" },
                Token::Str("100"),
                Token::SeqEnd,
                Token::StructEnd,
            ],
        );
    }
}
