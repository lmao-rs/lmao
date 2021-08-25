//! Provides the Snowflake trait for defining extractable information from a Discord Snowflake.

use twilight_model::id::{
    ApplicationId, AttachmentId, AuditLogEntryId, ChannelId, CommandId, EmojiId, GenericId,
    GuildId, IntegrationId, InteractionId, MessageId, RoleId, StageId, UserId, WebhookId,
};

/// Snowflake is a trait for defining extractable information from a Snowflake. A Snowflake is a
/// u64 generated by Discord to uniquely identify a resource.
pub trait Snowflake {
    /// Returns the u64 backing the Snowflake.
    fn id(&self) -> u64;

    /// The Unix epoch of the Snowflake in milliseconds, indicating when it was generated.
    ///
    /// Derived from bits 22..63 of the id.
    ///
    /// # Examples
    ///
    /// See when a user was created using [`chrono`](https://docs.rs/chrono):
    ///
    /// ```rust
    /// use chrono::{Utc, TimeZone};
    /// use twilight_util::snowflake::Snowflake;
    /// use twilight_model::id::UserId;
    ///
    /// let id = UserId::new(105484726235607040).expect("non zero");
    ///
    /// assert_eq!(
    ///     "2015-10-19T01:58:38.546+00:00",
    ///     Utc.timestamp_millis(id.timestamp()).to_rfc3339()
    /// );
    /// ```
    ///
    /// See when a user was created using [`time`](https://docs.rs/time):
    ///
    /// ```rust
    /// use time::{Duration, Format, OffsetDateTime};
    ///
    /// use twilight_util::snowflake::Snowflake;
    /// use twilight_model::id::UserId;
    ///
    /// let id = UserId::new(105484726235607040).expect("non zero");
    /// let dur = Duration::milliseconds(id.timestamp());
    /// // Or use seconds, at the cost of lost precision.
    /// let ts = OffsetDateTime::from_unix_timestamp_nanos(dur.whole_nanoseconds());
    ///
    /// assert_eq!("2015-10-19T01:58:38+00:00", ts.format(Format::Rfc3339));
    /// ```
    #[allow(clippy::cast_possible_wrap)]
    fn timestamp(&self) -> i64 {
        // Discord's custom epoch, the unix time in milliseconds for the first second of 2015.
        const DISCORD_EPOCH: u64 = 1_420_070_400_000;

        ((self.id() >> 22) + DISCORD_EPOCH) as i64
    }

    /// The id of the internal worker that generated the Snowflake.
    ///
    /// Derived from bits 17..21 of the id.
    #[allow(clippy::cast_possible_truncation)]
    fn worker_id(&self) -> u8 {
        ((self.id() & 0x003E_0000) >> 17) as u8
    }

    /// The id of the internal process that generated the Snowflake.
    ///
    /// Derived from bits 12..16 of the id.
    #[allow(clippy::cast_possible_truncation)]
    fn process_id(&self) -> u8 {
        ((self.id() & 0x1F000) >> 12) as u8
    }

    /// The increment of the Snowflake. For every id that is generated on a process, this number is
    /// incremented.
    ///
    /// Derived from bits 0..11 of the id.
    #[allow(clippy::cast_possible_truncation)]
    fn increment(&self) -> u16 {
        (self.id() & 0xFFF) as u16
    }
}

impl Snowflake for ApplicationId {
    fn id(&self) -> u64 {
        self.get()
    }
}

impl Snowflake for AttachmentId {
    fn id(&self) -> u64 {
        self.get()
    }
}

impl Snowflake for AuditLogEntryId {
    fn id(&self) -> u64 {
        self.get()
    }
}

impl Snowflake for ChannelId {
    fn id(&self) -> u64 {
        self.get()
    }
}

impl Snowflake for CommandId {
    fn id(&self) -> u64 {
        self.get()
    }
}

impl Snowflake for EmojiId {
    fn id(&self) -> u64 {
        self.get()
    }
}

impl Snowflake for GenericId {
    fn id(&self) -> u64 {
        self.get()
    }
}

impl Snowflake for GuildId {
    fn id(&self) -> u64 {
        self.get()
    }
}

impl Snowflake for IntegrationId {
    fn id(&self) -> u64 {
        self.get()
    }
}

impl Snowflake for InteractionId {
    fn id(&self) -> u64 {
        self.get()
    }
}

impl Snowflake for MessageId {
    fn id(&self) -> u64 {
        self.get()
    }
}

impl Snowflake for RoleId {
    fn id(&self) -> u64 {
        self.get()
    }
}

impl Snowflake for StageId {
    fn id(&self) -> u64 {
        self.get()
    }
}

impl Snowflake for UserId {
    fn id(&self) -> u64 {
        self.get()
    }
}

impl Snowflake for WebhookId {
    fn id(&self) -> u64 {
        self.get()
    }
}

#[cfg(test)]
mod tests {
    use super::Snowflake;
    use static_assertions::{assert_impl_all, assert_obj_safe};
    use twilight_model::id::{
        ApplicationId, AttachmentId, AuditLogEntryId, ChannelId, CommandId, EmojiId, GenericId,
        GuildId, IntegrationId, InteractionId, MessageId, RoleId, StageId, UserId, WebhookId,
    };

    assert_impl_all!(ApplicationId: Snowflake);
    assert_impl_all!(AttachmentId: Snowflake);
    assert_impl_all!(AuditLogEntryId: Snowflake);
    assert_impl_all!(ChannelId: Snowflake);
    assert_impl_all!(CommandId: Snowflake);
    assert_impl_all!(EmojiId: Snowflake);
    assert_impl_all!(GenericId: Snowflake);
    assert_impl_all!(GuildId: Snowflake);
    assert_impl_all!(IntegrationId: Snowflake);
    assert_impl_all!(InteractionId: Snowflake);
    assert_impl_all!(MessageId: Snowflake);
    assert_impl_all!(RoleId: Snowflake);
    assert_impl_all!(StageId: Snowflake);
    assert_impl_all!(UserId: Snowflake);
    assert_impl_all!(WebhookId: Snowflake);
    assert_obj_safe!(Snowflake);

    #[test]
    fn test_timestamp() {
        let expected: i64 = 1_445_219_918_546;
        let id = GenericId::new(105_484_726_235_607_040).expect("non zero");

        assert_eq!(expected, id.timestamp())
    }

    #[test]
    fn test_worker_id() {
        let expected: u8 = 8;
        let id = GenericId::new(762_022_344_856_174_632).expect("non zero");

        assert_eq!(expected, id.worker_id())
    }

    #[test]
    fn test_process_id() {
        let expected: u8 = 1;
        let id = GenericId::new(61_189_081_970_774_016).expect("non zero");

        assert_eq!(expected, id.process_id())
    }

    #[test]
    fn test_increment() {
        let expected: u16 = 40;
        let id = GenericId::new(762_022_344_856_174_632).expect("non zero");

        assert_eq!(expected, id.increment())
    }
}
