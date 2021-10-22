use crate::datetime::Timestamp;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct InviteMetadata {
    pub created_at: Timestamp,
    pub max_age: u64,
    pub max_uses: u64,
    pub temporary: bool,
    pub uses: u64,
}

#[cfg(test)]
mod tests {
    use crate::datetime::Timestamp;

    use super::InviteMetadata;
    use serde_test::Token;

    #[test]
    fn test_invite_metadata() {
        let created_at = Timestamp::from_secs(1_628_546_464).expect("non zero");

        let value = InviteMetadata {
            created_at,
            max_age: 86_400,
            max_uses: 10,
            temporary: false,
            uses: 3,
        };

        serde_test::assert_tokens(
            &value,
            &[
                Token::Struct {
                    name: "InviteMetadata",
                    len: 5,
                },
                Token::Str("created_at"),
                Token::Str("2021-08-09T22:01:04.000000+00:00"),
                Token::Str("max_age"),
                Token::U64(86_400),
                Token::Str("max_uses"),
                Token::U64(10),
                Token::Str("temporary"),
                Token::Bool(false),
                Token::Str("uses"),
                Token::U64(3),
                Token::StructEnd,
            ],
        );
    }
}
