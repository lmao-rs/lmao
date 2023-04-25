use bitflags::bitflags;
use serde::{Deserialize, Serialize};

bitflags! {
    #[allow(clippy::unsafe_derive_deserialize)]
    #[derive(Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct ApplicationFlags: u64 {
        /// Intent required for bots in 100 guilds or more to receive
        /// [`PresenceUpdate`] events.
        ///
        /// [`PresenceUpdate`]: crate::gateway::payload::incoming::PresenceUpdate
        const GATEWAY_PRESENCE = 1 << 12;
        /// Intent required for bots in less than 100 guilds to receive
        /// [`PresenceUpdate`] events.
        ///
        /// [`PresenceUpdate`]: crate::gateway::payload::incoming::PresenceUpdate
        const GATEWAY_PRESENCE_LIMITED = 1 << 13;
        /// Intent required for bots in 100 guilds or more to receive
        /// member-related events like [`MemberAdd`].
        ///
        /// [`MemberAdd`]: crate::gateway::payload::incoming::MemberAdd
        const GATEWAY_GUILD_MEMBERS = 1 << 14;
        /// Intent required for bots in less than 100 guilds to receive
        /// member-related events like [`MemberAdd`].
        ///
        /// [`MemberAdd`]: crate::gateway::payload::incoming::MemberAdd
        const GATEWAY_GUILD_MEMBERS_LIMITED = 1 << 15;
        /// Indicates unusual growth of an app that prevents verification.
        const VERIFICATION_PENDING_GUILD_LIMIT = 1 << 16;
        /// Indicates if an app is embedded within the Discord client.
        const EMBEDDED = 1 << 17;
        /// Intent required for bots in 100 guilds or more to receive
        /// [message content].
        ///
        /// [message content]: https://support-dev.discord.com/hc/en-us/articles/4404772028055
        const GATEWAY_MESSAGE_CONTENT = 1 << 18;
        /// Intent required for bots in less than 100 guilds to receive
        /// [message content].
        ///
        /// [message content]: https://support-dev.discord.com/hc/en-us/articles/4404772028055
        const GATEWAY_MESSAGE_CONTENT_LIMITED = 1 << 19;

        /// Indicates whether an app has registered global [application commands].
        ///
        /// [application commands]: https://discord.com/developers/docs/interactions/application-commands
        const APPLICATION_COMMAND_BADGE = 1 << 23;
    }
}

#[cfg(test)]
mod tests {
    use super::ApplicationFlags;
    use serde::{Deserialize, Serialize};
    use serde_test::Token;
    use static_assertions::{assert_impl_all, const_assert_eq};
    use std::{
        fmt::{Binary, Debug, LowerHex, Octal, UpperHex},
        hash::Hash,
        ops::{
            BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not, Sub, SubAssign,
        },
    };

    assert_impl_all!(
        ApplicationFlags: Binary,
        BitAnd,
        BitAndAssign,
        BitOr,
        BitOrAssign,
        BitXor,
        BitXorAssign,
        Clone,
        Copy,
        Debug,
        Deserialize<'static>,
        Eq,
        Extend<ApplicationFlags>,
        FromIterator<ApplicationFlags>,
        Hash,
        LowerHex,
        Not,
        Octal,
        Ord,
        PartialEq,
        PartialOrd,
        Send,
        Serialize,
        Sub,
        SubAssign,
        Sync,
        UpperHex
    );
    const_assert_eq!(ApplicationFlags::GATEWAY_PRESENCE.bits(), 1 << 12);
    const_assert_eq!(ApplicationFlags::GATEWAY_PRESENCE_LIMITED.bits(), 1 << 13);
    const_assert_eq!(ApplicationFlags::GATEWAY_GUILD_MEMBERS.bits(), 1 << 14);
    const_assert_eq!(
        ApplicationFlags::GATEWAY_GUILD_MEMBERS_LIMITED.bits(),
        1 << 15
    );
    const_assert_eq!(
        ApplicationFlags::VERIFICATION_PENDING_GUILD_LIMIT.bits(),
        1 << 16
    );
    const_assert_eq!(ApplicationFlags::EMBEDDED.bits(), 1 << 17);
    const_assert_eq!(ApplicationFlags::GATEWAY_MESSAGE_CONTENT.bits(), 1 << 18);
    const_assert_eq!(
        ApplicationFlags::GATEWAY_MESSAGE_CONTENT_LIMITED.bits(),
        1 << 19
    );
    const_assert_eq!(ApplicationFlags::APPLICATION_COMMAND_BADGE.bits(), 1 << 23);

    #[test]
    fn serde() {
        serde_test::assert_tokens(
            &ApplicationFlags::GATEWAY_MESSAGE_CONTENT,
            &[Token::U64(ApplicationFlags::GATEWAY_MESSAGE_CONTENT.bits())],
        );
        // Safety:
        //
        // Deserialization doesn't truncate unknown bits.
        //
        // `bitflags` requires unsafe code to create bitflags with unknown bits
        // due to an unorthodox definition of unsafe:
        //
        // <https://github.com/bitflags/bitflags/issues/262>
        #[allow(unsafe_code)]
        let value = unsafe { ApplicationFlags::from_bits_unchecked(1 << 63) };
        serde_test::assert_de_tokens(&value, &[Token::U64(1 << 63)]);
    }
}
