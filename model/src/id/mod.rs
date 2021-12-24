//! ID with type-safe markers for each resource.
//!
//! When IDs are simple 64-bit integers then it may be easy to accidentally use
//! the ID of a role in place of where one means to use the ID of a user. This
//! is a programmatic error; it's on the programmer to notice. By using IDs with
//! typed markers, it can be ensured that only an ID with a guild marker is used
//! where an ID with a guild marker is requested.
//!
//! # Parsing
//!
//! IDs may be initialized or parsed in a variety of manners depending on the
//! context:
//!
//! - `serde` deserialization
//! - [`std::str::FromStr`]
//! - [`std::convert::TryFrom`]\<i64>
//! - [`std::convert::TryFrom`]\<u64>
//! - [`Id::new`]
//! - [`Id::new_unchecked`]
//! - [`std::convert::From`]<[`std::num::NonZeroU64`]>
//!
//! # Casting between resource types
//!
//! Discord may have constraints where IDs are the same across resources. For
//! example, the `@everyone` role of a guild has the same ID as the guild
//! itself. In this case, all one needs to do is use the guild's ID in place of
//! a role in order to operate on the `@everyone` role of the guild. IDs can be
//! easily casted in order to fulfill this:
//!
//! ```
//! use twilight_model::id::{marker::{GuildMarker, RoleMarker}, Id};
//!
//! // Often Rust's type inference will be able to infer the type of ID.
//! let guild_id = Id::<GuildMarker>::new(123).expect("non zero id");
//! let role_id = guild_id.cast::<RoleMarker>();
//!
//! assert_eq!(guild_id.get(), role_id.get());
//! ```

pub mod marker;

mod r#type;

pub use self::r#type::*;

use marker::Snowflake;
use serde::{
    de::{Deserialize, Deserializer, Error as DeError, Unexpected, Visitor},
    ser::{Serialize, Serializer},
};
use std::{
    any,
    cmp::Ordering,
    convert::TryFrom,
    fmt::{Debug, Display, Formatter, Result as FmtResult},
    hash::{Hash, Hasher},
    marker::PhantomData,
    num::{NonZeroI64, NonZeroU64, ParseIntError, TryFromIntError},
    str::FromStr,
};

/// ID of a resource, such as the ID of a [channel] or [user].
///
/// Markers themselves perform no logical action, and are only used to ensure
/// that IDs of incorrect types aren't used. Read the [marker documentation] for
/// additional information.
///
/// # serde
///
/// This ID deserializes from both integers and strings and serializes into a
/// string.
///
/// [channel]: marker::ChannelMarker
/// [marker documentation]: marker
/// [user]: marker::UserMarker
#[derive(Clone, Copy)]
pub struct Id<T> {
    phantom: PhantomData<T>,
    value: NonZeroU64,
}

impl<T> Id<T> {
    const fn from_nonzero(value: NonZeroU64) -> Self {
        Self {
            phantom: PhantomData,
            value,
        }
    }

    /// Create a non-zero application ID without checking the value.
    ///
    /// Equivalent to [`NonZeroU64::new_unchecked`].
    ///
    /// # Safety
    ///
    /// The value must not be zero.
    #[allow(unsafe_code)]
    pub const unsafe fn new_unchecked(n: u64) -> Self {
        Self::from_nonzero(NonZeroU64::new_unchecked(n))
    }

    /// Create a non-zero application ID if the given value is not zero.
    ///
    /// Equivalent to [`NonZeroU64::new`].
    pub const fn new(n: u64) -> Option<Self> {
        #[allow(clippy::option_if_let_else)]
        if let Some(n) = NonZeroU64::new(n) {
            Some(Self::from_nonzero(n))
        } else {
            None
        }
    }

    /// Return the inner primitive value.
    ///
    /// Equivalent to [`NonZeroU64::get`].
    ///
    /// # Examples
    ///
    /// Create an ID with a value and then confirm its inner value:
    ///
    /// ```
    /// use twilight_model::id::{marker::ChannelMarker, Id};
    ///
    /// # fn try_main() -> Option<()> {
    /// let channel_id = Id::<ChannelMarker>::new(7)?;
    ///
    /// assert_eq!(7, channel_id.get());
    /// # Some(()) }
    /// #
    /// # fn main() { try_main().unwrap(); }
    /// ```
    pub const fn get(self) -> u64 {
        self.value.get()
    }

    /// Cast an ID from one type to another.
    ///
    /// # Examples
    ///
    /// Cast a role ID to a guild ID, useful for the `@everyone` role:
    ///
    /// ```
    /// use twilight_model::id::{marker::{GuildMarker, RoleMarker}, Id};
    ///
    /// let role_id: Id<RoleMarker> = Id::new(1).expect("non zero id");
    ///
    /// let guild_id: Id<GuildMarker> = role_id.cast();
    /// assert_eq!(1, guild_id.get());
    /// ```
    pub const fn cast<New>(self) -> Id<New> {
        Id::from_nonzero(self.value)
    }
}

impl<T: Snowflake> Id<T> {
    /// The Unix epoch of the Snowflake in milliseconds, indicating when it was generated.
    ///
    /// Derived from bits 22..63 of the id.
    ///
    /// # Examples
    ///
    /// ```
    /// use twilight_model::{
    ///     datetime::Timestamp,
    ///     id::{marker::UserMarker, Id},
    /// };
    ///
    /// let id = Id::<UserMarker>::new(105484726235607040).expect("non zero");
    ///
    /// assert_eq!(id.timestamp(), 1445219918546);
    ///
    /// assert_eq!(
    ///     "2015-10-19T01:58:38.546000+00:00",
    ///     Timestamp::from_micros(id.timestamp() * 1000)?
    ///         .iso_8601()
    ///         .to_string()
    /// );
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    #[allow(clippy::cast_possible_wrap)]
    pub fn timestamp(self) -> i64 {
        // Discord's custom epoch, the unix time in milliseconds for the first second of 2015.
        const DISCORD_EPOCH: u64 = 1_420_070_400_000;

        ((self.get() >> 22) + DISCORD_EPOCH) as i64
    }

    /// The id of the internal worker that generated the Snowflake.
    ///
    /// Derived from bits 17..21 of the id.
    #[allow(clippy::cast_possible_truncation)]
    pub fn worker_id(self) -> u8 {
        ((self.get() & 0x003E_0000) >> 17) as u8
    }

    /// The id of the internal process that generated the Snowflake.
    ///
    /// Derived from bits 12..16 of the id.
    #[allow(clippy::cast_possible_truncation)]
    pub fn process_id(self) -> u8 {
        ((self.get() & 0x1F000) >> 12) as u8
    }

    /// The increment of the Snowflake. For every id that is generated on a process, this number is
    /// incremented.
    ///
    /// Derived from bits 0..11 of the id.
    #[allow(clippy::cast_possible_truncation)]
    pub fn increment(self) -> u16 {
        (self.get() & 0xFFF) as u16
    }
}

impl<T> Debug for Id<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("Id")?;
        let type_name = any::type_name::<T>();

        // `any::type_name` will usually provide an FQN, so we'll do our best
        // (and simplest) method here of removing it to only get the type name
        // itself.
        if let Some(position) = type_name.rfind("::") {
            if let Some(slice) = type_name.get(position + 2..) {
                f.write_str("<")?;
                f.write_str(slice)?;
                f.write_str(">")?;
            }
        }

        f.write_str("(")?;
        Debug::fmt(&self.value, f)?;

        f.write_str(")")
    }
}

impl<'de, T> Deserialize<'de> for Id<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct IdVisitor<T> {
            phantom: PhantomData<T>,
        }

        impl<T> IdVisitor<T> {
            const fn new() -> Self {
                Self {
                    phantom: PhantomData,
                }
            }
        }

        impl<'de, T> Visitor<'de> for IdVisitor<T> {
            type Value = Id<T>;

            fn expecting(&self, f: &mut Formatter<'_>) -> FmtResult {
                f.write_str("a discord snowflake")
            }

            fn visit_u64<E: DeError>(self, value: u64) -> Result<Self::Value, E> {
                let value = NonZeroU64::new(value).ok_or_else(|| {
                    DeError::invalid_value(Unexpected::Unsigned(value), &"non zero u64")
                })?;

                Ok(Id::from(value))
            }

            fn visit_newtype_struct<D: Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<Self::Value, D::Error> {
                deserializer.deserialize_any(IdVisitor::new())
            }

            fn visit_str<E: DeError>(self, v: &str) -> Result<Self::Value, E> {
                let value = v.parse().map_err(|_| {
                    let unexpected = Unexpected::Str(v);

                    DeError::invalid_value(unexpected, &"non zero u64 string")
                })?;

                self.visit_u64(value)
            }
        }

        deserializer.deserialize_any(IdVisitor::new())
    }
}

impl<T> Display for Id<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Display::fmt(&self.value.get(), f)
    }
}

impl<T> From<NonZeroU64> for Id<T> {
    fn from(id: NonZeroU64) -> Self {
        Self::from_nonzero(id)
    }
}

impl<T> FromStr for Id<T> {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        NonZeroU64::from_str(s).map(Self::from_nonzero)
    }
}

impl<T> Eq for Id<T> {}

impl<T> Hash for Id<T> {
    fn hash<U: Hasher>(&self, state: &mut U) {
        state.write_u64(self.value.get());
    }
}

impl<T> Ord for Id<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.value.cmp(&other.value)
    }
}

impl<T> PartialEq for Id<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T> PartialEq<i64> for Id<T> {
    fn eq(&self, other: &i64) -> bool {
        u64::try_from(*other)
            .map(|v| v == self.value.get())
            .unwrap_or_default()
    }
}

impl<T> PartialEq<Id<T>> for i64 {
    fn eq(&self, other: &Id<T>) -> bool {
        u64::try_from(*self)
            .map(|v| v == other.value.get())
            .unwrap_or_default()
    }
}

impl<T> PartialEq<u64> for Id<T> {
    fn eq(&self, other: &u64) -> bool {
        self.value.get() == *other
    }
}

impl<T> PartialEq<Id<T>> for u64 {
    fn eq(&self, other: &Id<T>) -> bool {
        other.value.get() == *self
    }
}

impl<T> PartialOrd for Id<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.value.partial_cmp(&other.value)
    }
}

impl<T> Serialize for Id<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Avoid requiring a Copy trait bound by simply reconstructing self.
        let copy = Self::from_nonzero(self.value);
        let formatter = IdStringDisplay::new(copy);

        serializer.serialize_newtype_struct("Id", &formatter)
    }
}

impl<T> TryFrom<i64> for Id<T> {
    type Error = TryFromIntError;

    fn try_from(value: i64) -> Result<Self, Self::Error> {
        let signed_nonzero = NonZeroI64::try_from(value)?;
        let unsigned_nonzero = NonZeroU64::try_from(signed_nonzero)?;

        Ok(Self::from_nonzero(unsigned_nonzero))
    }
}

impl<T> TryFrom<u64> for Id<T> {
    type Error = TryFromIntError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        let nonzero = NonZeroU64::try_from(value)?;

        Ok(Self::from_nonzero(nonzero))
    }
}

/// Display implementation to format an ID as a string.
#[derive(Debug)]
struct IdStringDisplay<T> {
    inner: Id<T>,
}

impl<T> IdStringDisplay<T> {
    /// Create a new formatter.
    const fn new(id: Id<T>) -> Self {
        Self { inner: id }
    }
}

impl<T> Display for IdStringDisplay<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        Display::fmt(&self.inner.value, f)
    }
}

impl<T> Serialize for IdStringDisplay<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        marker::{
            ApplicationMarker, AttachmentMarker, AuditLogEntryMarker, ChannelMarker, CommandMarker,
            CommandVersionMarker, EmojiMarker, GenericMarker, GuildMarker, IntegrationMarker,
            InteractionMarker, MessageMarker, RoleMarker, Snowflake, StageMarker, UserMarker,
            WebhookMarker,
        },
        Id, IdStringDisplay,
    };
    use serde::{Deserialize, Serialize};
    use serde_test::Token;
    use static_assertions::assert_impl_all;
    use std::{
        collections::hash_map::DefaultHasher,
        convert::TryFrom,
        error::Error,
        fmt::{Debug, Display},
        hash::{Hash, Hasher},
        num::NonZeroU64,
        str::FromStr,
    };

    assert_impl_all!(ApplicationMarker: Clone, Copy, Debug, Send, Snowflake, Sync);
    assert_impl_all!(AttachmentMarker: Clone, Copy, Debug, Send, Snowflake, Sync);
    assert_impl_all!(
        AuditLogEntryMarker: Clone,
        Copy,
        Debug,
        Send,
        Snowflake,
        Sync
    );
    assert_impl_all!(ChannelMarker: Clone, Copy, Debug, Send, Snowflake, Sync);
    assert_impl_all!(CommandMarker: Clone, Copy, Debug, Send, Snowflake, Sync);
    assert_impl_all!(
        CommandVersionMarker: Clone,
        Copy,
        Debug,
        Send,
        Snowflake,
        Sync
    );
    assert_impl_all!(EmojiMarker: Clone, Copy, Debug, Send, Snowflake, Sync);
    assert_impl_all!(GenericMarker: Clone, Copy, Debug, Send, Snowflake, Sync);
    assert_impl_all!(GuildMarker: Clone, Copy, Debug, Send, Snowflake, Sync);
    assert_impl_all!(IntegrationMarker: Clone, Copy, Debug, Send, Snowflake, Sync);
    assert_impl_all!(InteractionMarker: Clone, Copy, Debug, Send, Snowflake, Sync);
    assert_impl_all!(MessageMarker: Clone, Copy, Debug, Send, Snowflake, Sync);
    assert_impl_all!(RoleMarker: Clone, Copy, Debug, Send, Snowflake, Sync);
    assert_impl_all!(StageMarker: Clone, Copy, Debug, Send, Snowflake, Sync);
    assert_impl_all!(UserMarker: Clone, Copy, Debug, Send, Snowflake, Sync);
    assert_impl_all!(WebhookMarker: Clone, Copy, Debug, Send, Snowflake, Sync);
    assert_impl_all!(Id<GenericMarker>:
        Clone, Copy, Debug, Deserialize<'static>, Display, Eq, From<NonZeroU64>,
        FromStr, Hash, Ord, PartialEq, PartialEq<i64>, PartialEq<u64>, PartialOrd, Send, Serialize, Sync,
        TryFrom<i64>, TryFrom<u64>
    );
    assert_impl_all!(IdStringDisplay<GenericMarker>: Debug, Display, Send, Serialize, Sync);

    /// Test that various methods of initializing IDs are correct, such as via
    /// [`Id::new`] or [`Id`]'s [`TryFrom`] implementations.
    #[test]
    fn test_initializers() -> Result<(), Box<dyn Error>> {
        // `Id::new`
        assert!(Id::<GenericMarker>::new(0).is_none());
        assert_eq!(Some(1), Id::<GenericMarker>::new(1).map(Id::get));

        // `From`
        assert_eq!(
            123_u64,
            Id::<GenericMarker>::from(NonZeroU64::new(123).expect("non zero"))
        );

        // `FromStr`
        assert_eq!(123_u64, Id::<GenericMarker>::from_str("123")?);
        assert!(Id::<GenericMarker>::from_str("0").is_err());
        assert!(Id::<GenericMarker>::from_str("123a").is_err());

        // `TryFrom`
        assert!(Id::<GenericMarker>::try_from(-123_i64).is_err());
        assert!(Id::<GenericMarker>::try_from(0_i64).is_err());
        assert_eq!(123_u64, Id::<GenericMarker>::try_from(123_i64)?);
        assert!(Id::<GenericMarker>::try_from(0_u64).is_err());
        assert_eq!(123_u64, Id::<GenericMarker>::try_from(123_u64)?);

        Ok(())
    }

    /// Test that casting IDs maintains the original value.
    #[test]
    fn test_cast() {
        let id = Id::<GenericMarker>::new(123).expect("non zero");
        assert_eq!(123_u64, id.cast::<RoleMarker>());
    }

    #[test]
    fn test_timestamp() {
        let expected: i64 = 1_445_219_918_546;
        let id = Id::<GenericMarker>::new(105_484_726_235_607_040).expect("non zero");

        assert_eq!(expected, id.timestamp())
    }

    #[test]
    fn test_worker_id() {
        let expected: u8 = 8;
        let id = Id::<GenericMarker>::new(762_022_344_856_174_632).expect("non zero");

        assert_eq!(expected, id.worker_id())
    }

    #[test]
    fn test_process_id() {
        let expected: u8 = 1;
        let id = Id::<GenericMarker>::new(61_189_081_970_774_016).expect("non zero");

        assert_eq!(expected, id.process_id())
    }

    #[test]
    fn test_increment() {
        let expected: u16 = 40;
        let id = Id::<GenericMarker>::new(762_022_344_856_174_632).expect("non zero");

        assert_eq!(expected, id.increment())
    }

    /// Test that debugging IDs formats the generic and value as a newtype.
    #[test]
    fn test_debug() {
        let id = Id::<RoleMarker>::new(114_941_315_417_899_012).expect("non zero");

        assert_eq!("Id<RoleMarker>(114941315417899012)", format!("{:?}", id));
    }

    /// Test that display formatting an ID formats the value.
    #[test]
    fn test_display() {
        let id = Id::<GenericMarker>::new(114_941_315_417_899_012).expect("non zero");

        assert_eq!("114941315417899012", id.to_string());
    }

    /// Test that hashing an ID is equivalent to hashing only its inner value.
    #[test]
    fn test_hash() {
        let id = Id::<GenericMarker>::new(123).expect("non zero");

        let mut id_hasher = DefaultHasher::new();
        id.hash(&mut id_hasher);

        let mut value_hasher = DefaultHasher::new();
        123_u64.hash(&mut value_hasher);

        assert_eq!(id_hasher.finish(), value_hasher.finish());
    }

    /// Test that IDs are ordered exactly like their inner values.
    #[test]
    fn test_ordering() {
        let lesser = Id::<GenericMarker>::new(911_638_235_594_244_096).expect("non zero");
        let center = Id::<GenericMarker>::new(911_638_263_322_800_208).expect("non zero");
        let greater = Id::<GenericMarker>::new(911_638_287_939_166_208).expect("non zero");

        assert!(center.cmp(&greater).is_lt());
        assert!(center.cmp(&center).is_eq());
        assert!(center.cmp(&lesser).is_gt());
    }

    #[allow(clippy::too_many_lines)]
    #[test]
    fn test_serde() {
        serde_test::assert_tokens(
            &Id::<ApplicationMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::Str("114941315417899012"),
            ],
        );
        serde_test::assert_de_tokens(
            &Id::<ApplicationMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::U64(114_941_315_417_899_012),
            ],
        );
        serde_test::assert_tokens(
            &Id::<AttachmentMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::Str("114941315417899012"),
            ],
        );
        serde_test::assert_de_tokens(
            &Id::<AttachmentMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::U64(114_941_315_417_899_012),
            ],
        );
        serde_test::assert_tokens(
            &Id::<AuditLogEntryMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::Str("114941315417899012"),
            ],
        );
        serde_test::assert_de_tokens(
            &Id::<AuditLogEntryMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::U64(114_941_315_417_899_012),
            ],
        );
        serde_test::assert_tokens(
            &Id::<ChannelMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::Str("114941315417899012"),
            ],
        );
        serde_test::assert_de_tokens(
            &Id::<ChannelMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::U64(114_941_315_417_899_012),
            ],
        );
        serde_test::assert_tokens(
            &Id::<CommandMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::Str("114941315417899012"),
            ],
        );
        serde_test::assert_de_tokens(
            &Id::<CommandMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::U64(114_941_315_417_899_012),
            ],
        );
        serde_test::assert_tokens(
            &Id::<CommandVersionMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::Str("114941315417899012"),
            ],
        );
        serde_test::assert_de_tokens(
            &Id::<CommandVersionMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::U64(114_941_315_417_899_012),
            ],
        );
        serde_test::assert_tokens(
            &Id::<EmojiMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::Str("114941315417899012"),
            ],
        );
        serde_test::assert_de_tokens(
            &Id::<EmojiMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::U64(114_941_315_417_899_012),
            ],
        );
        serde_test::assert_tokens(
            &Id::<GenericMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::Str("114941315417899012"),
            ],
        );
        serde_test::assert_de_tokens(
            &Id::<GenericMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::U64(114_941_315_417_899_012),
            ],
        );
        serde_test::assert_tokens(
            &Id::<GuildMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::Str("114941315417899012"),
            ],
        );
        serde_test::assert_de_tokens(
            &Id::<GuildMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::U64(114_941_315_417_899_012),
            ],
        );
        serde_test::assert_tokens(
            &Id::<IntegrationMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::Str("114941315417899012"),
            ],
        );
        serde_test::assert_de_tokens(
            &Id::<IntegrationMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::U64(114_941_315_417_899_012),
            ],
        );
        serde_test::assert_tokens(
            &Id::<InteractionMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::Str("114941315417899012"),
            ],
        );
        serde_test::assert_de_tokens(
            &Id::<InteractionMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::U64(114_941_315_417_899_012),
            ],
        );
        serde_test::assert_tokens(
            &Id::<MessageMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::Str("114941315417899012"),
            ],
        );
        serde_test::assert_de_tokens(
            &Id::<MessageMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::U64(114_941_315_417_899_012),
            ],
        );
        serde_test::assert_tokens(
            &Id::<RoleMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::Str("114941315417899012"),
            ],
        );
        serde_test::assert_de_tokens(
            &Id::<RoleMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::U64(114_941_315_417_899_012),
            ],
        );
        serde_test::assert_tokens(
            &Id::<StageMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::Str("114941315417899012"),
            ],
        );
        serde_test::assert_de_tokens(
            &Id::<StageMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::U64(114_941_315_417_899_012),
            ],
        );
        serde_test::assert_tokens(
            &Id::<UserMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::Str("114941315417899012"),
            ],
        );
        serde_test::assert_de_tokens(
            &Id::<UserMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::U64(114_941_315_417_899_012),
            ],
        );
        serde_test::assert_tokens(
            &Id::<WebhookMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::Str("114941315417899012"),
            ],
        );
        serde_test::assert_de_tokens(
            &Id::<WebhookMarker>::new(114_941_315_417_899_012).expect("non zero"),
            &[
                Token::NewtypeStruct { name: "Id" },
                Token::U64(114_941_315_417_899_012),
            ],
        );
    }
}
