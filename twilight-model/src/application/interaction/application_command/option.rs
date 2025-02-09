use crate::{
    application::command::CommandOptionType,
    id::{
        marker::{AttachmentMarker, ChannelMarker, GenericMarker, RoleMarker, UserMarker},
        Id,
    },
};
use serde::{
    de::{Error as DeError, IgnoredAny, MapAccess, Unexpected, Visitor},
    ser::SerializeStruct,
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};

/// Data received when a user fills in a command option.
///
/// See [Discord Docs/Application Command Object].
///
/// [Discord Docs/Application Command Object]: https://discord.com/developers/docs/interactions/application-commands#application-command-object-application-command-interaction-data-option-structure
#[derive(Clone, Debug, PartialEq)]
pub struct CommandDataOption {
    /// Name of the option.
    pub name: String,
    /// Value of the option.
    pub value: CommandOptionValue,
}

impl Serialize for CommandDataOption {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let subcommand_is_empty = matches!(
            &self.value,
            CommandOptionValue::SubCommand(o)
            | CommandOptionValue::SubCommandGroup(o)
                if o.is_empty()
        );

        let focused = matches!(&self.value, CommandOptionValue::Focused(_, _));

        let len = 2 + usize::from(!subcommand_is_empty) + usize::from(focused);

        let mut state = serializer.serialize_struct("CommandDataOption", len)?;

        if focused {
            state.serialize_field("focused", &focused)?;
        }

        state.serialize_field("name", &self.name)?;

        state.serialize_field("type", &self.value.kind())?;

        match &self.value {
            CommandOptionValue::Attachment(a) => state.serialize_field("value", a)?,
            CommandOptionValue::Boolean(b) => state.serialize_field("value", b)?,
            CommandOptionValue::Channel(c) => state.serialize_field("value", c)?,
            CommandOptionValue::Focused(f, _) => state.serialize_field("value", f)?,
            CommandOptionValue::Integer(i) => state.serialize_field("value", i)?,
            CommandOptionValue::Mentionable(m) => state.serialize_field("value", m)?,
            CommandOptionValue::Number(n) => state.serialize_field("value", n)?,
            CommandOptionValue::Role(r) => state.serialize_field("value", r)?,
            CommandOptionValue::String(s) => state.serialize_field("value", s)?,
            CommandOptionValue::User(u) => state.serialize_field("value", u)?,
            CommandOptionValue::SubCommand(s) | CommandOptionValue::SubCommandGroup(s) => {
                if !subcommand_is_empty {
                    state.serialize_field("options", s)?
                }
            }
        }

        state.end()
    }
}

impl<'de> Deserialize<'de> for CommandDataOption {
    #[allow(clippy::too_many_lines)]
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Debug, Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Fields {
            Name,
            Type,
            Value,
            Options,
            Focused,
        }

        // An `Id` variant is purposely not present here to prevent wrongly
        // parsing string options as numbers, trimming leading zeroes.
        #[derive(Debug, Deserialize)]
        #[serde(untagged)]
        enum ValueEnvelope {
            Boolean(bool),
            Integer(i64),
            Number(f64),
            String(String),
        }

        impl ValueEnvelope {
            fn as_unexpected(&self) -> Unexpected<'_> {
                match self {
                    Self::Boolean(b) => Unexpected::Bool(*b),
                    Self::Integer(i) => Unexpected::Signed(*i),
                    Self::Number(f) => Unexpected::Float(*f),
                    Self::String(s) => Unexpected::Str(s),
                }
            }
        }

        impl Display for ValueEnvelope {
            fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
                match self {
                    Self::Boolean(b) => Display::fmt(b, f),
                    Self::Integer(i) => Display::fmt(i, f),
                    Self::Number(n) => Display::fmt(n, f),
                    Self::String(s) => Display::fmt(s, f),
                }
            }
        }

        struct CommandDataOptionVisitor;

        impl<'de> Visitor<'de> for CommandDataOptionVisitor {
            type Value = CommandDataOption;

            fn expecting(&self, formatter: &mut Formatter<'_>) -> FmtResult {
                formatter.write_str("CommandDataOption")
            }

            #[allow(clippy::too_many_lines)]
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let mut name_opt = None;
                let mut kind_opt = None;
                let mut options = Vec::new();
                let mut value_opt: Option<ValueEnvelope> = None;
                let mut focused = None;

                loop {
                    let key = match map.next_key() {
                        Ok(Some(key)) => key,
                        Ok(None) => break,
                        Err(_) => {
                            map.next_value::<IgnoredAny>()?;

                            continue;
                        }
                    };

                    match key {
                        Fields::Name => {
                            if name_opt.is_some() {
                                return Err(DeError::duplicate_field("name"));
                            }

                            name_opt = Some(map.next_value()?);
                        }
                        Fields::Type => {
                            if kind_opt.is_some() {
                                return Err(DeError::duplicate_field("type"));
                            }

                            kind_opt = Some(map.next_value()?);
                        }
                        Fields::Value => {
                            if value_opt.is_some() {
                                return Err(DeError::duplicate_field("value"));
                            }

                            value_opt = Some(map.next_value()?);
                        }
                        Fields::Options => {
                            if !options.is_empty() {
                                return Err(DeError::duplicate_field("options"));
                            }

                            options = map.next_value()?;
                        }
                        Fields::Focused => {
                            if focused.is_some() {
                                return Err(DeError::duplicate_field("focused"));
                            }

                            focused = map.next_value()?;
                        }
                    }
                }

                let focused = focused.unwrap_or_default();
                let name = name_opt.ok_or_else(|| DeError::missing_field("name"))?;
                let kind = kind_opt.ok_or_else(|| DeError::missing_field("type"))?;

                let value = if focused {
                    let val = value_opt.ok_or_else(|| DeError::missing_field("value"))?;

                    CommandOptionValue::Focused(val.to_string(), kind)
                } else {
                    match kind {
                        CommandOptionType::Attachment => {
                            let val = value_opt.ok_or_else(|| DeError::missing_field("value"))?;

                            if let ValueEnvelope::String(id) = &val {
                                CommandOptionValue::Attachment(id.parse().map_err(|_| {
                                    DeError::invalid_type(val.as_unexpected(), &"attachment id")
                                })?)
                            } else {
                                return Err(DeError::invalid_type(
                                    val.as_unexpected(),
                                    &"attachment id",
                                ));
                            }
                        }
                        CommandOptionType::Boolean => {
                            let val = value_opt.ok_or_else(|| DeError::missing_field("value"))?;

                            if let ValueEnvelope::Boolean(b) = val {
                                CommandOptionValue::Boolean(b)
                            } else {
                                return Err(DeError::invalid_type(val.as_unexpected(), &"boolean"));
                            }
                        }
                        CommandOptionType::Channel => {
                            let val = value_opt.ok_or_else(|| DeError::missing_field("value"))?;

                            if let ValueEnvelope::String(id) = &val {
                                CommandOptionValue::Channel(id.parse().map_err(|_| {
                                    DeError::invalid_type(val.as_unexpected(), &"channel id")
                                })?)
                            } else {
                                return Err(DeError::invalid_type(
                                    val.as_unexpected(),
                                    &"channel id",
                                ));
                            }
                        }
                        CommandOptionType::Integer => {
                            let val = value_opt.ok_or_else(|| DeError::missing_field("value"))?;

                            if let ValueEnvelope::Integer(i) = val {
                                CommandOptionValue::Integer(i)
                            } else {
                                return Err(DeError::invalid_type(val.as_unexpected(), &"integer"));
                            }
                        }
                        CommandOptionType::Mentionable => {
                            let val = value_opt.ok_or_else(|| DeError::missing_field("value"))?;

                            if let ValueEnvelope::String(id) = &val {
                                CommandOptionValue::Mentionable(id.parse().map_err(|_| {
                                    DeError::invalid_type(val.as_unexpected(), &"mentionable id")
                                })?)
                            } else {
                                return Err(DeError::invalid_type(
                                    val.as_unexpected(),
                                    &"mentionable id",
                                ));
                            }
                        }
                        CommandOptionType::Number => {
                            let val = value_opt.ok_or_else(|| DeError::missing_field("value"))?;

                            match val {
                                ValueEnvelope::Integer(i) => {
                                    // As json allows sending floating
                                    // points without the tailing decimals
                                    // it may be interpreted as a integer
                                    // but it is safe to cast as there can
                                    // not occur any loss.
                                    #[allow(clippy::cast_precision_loss)]
                                    CommandOptionValue::Number(i as f64)
                                }
                                ValueEnvelope::Number(f) => CommandOptionValue::Number(f),
                                other => {
                                    return Err(DeError::invalid_type(
                                        other.as_unexpected(),
                                        &"number",
                                    ));
                                }
                            }
                        }
                        CommandOptionType::Role => {
                            let val = value_opt.ok_or_else(|| DeError::missing_field("value"))?;

                            if let ValueEnvelope::String(id) = &val {
                                CommandOptionValue::Role(id.parse().map_err(|_| {
                                    DeError::invalid_type(val.as_unexpected(), &"role id")
                                })?)
                            } else {
                                return Err(DeError::invalid_type(val.as_unexpected(), &"role id"));
                            }
                        }
                        CommandOptionType::String => {
                            let val = value_opt.ok_or_else(|| DeError::missing_field("value"))?;

                            if let ValueEnvelope::String(s) = val {
                                CommandOptionValue::String(s)
                            } else {
                                return Err(DeError::invalid_type(val.as_unexpected(), &"string"));
                            }
                        }
                        CommandOptionType::SubCommand => CommandOptionValue::SubCommand(options),
                        CommandOptionType::SubCommandGroup => {
                            CommandOptionValue::SubCommandGroup(options)
                        }
                        CommandOptionType::User => {
                            let val = value_opt.ok_or_else(|| DeError::missing_field("value"))?;

                            if let ValueEnvelope::String(id) = &val {
                                CommandOptionValue::User(id.parse().map_err(|_| {
                                    DeError::invalid_type(val.as_unexpected(), &"user id")
                                })?)
                            } else {
                                return Err(DeError::invalid_type(val.as_unexpected(), &"user id"));
                            }
                        }
                    }
                };

                Ok(CommandDataOption { name, value })
            }
        }

        deserializer.deserialize_map(CommandDataOptionVisitor)
    }
}

/// Combined value and value type for a [`CommandDataOption`].
#[derive(Clone, Debug, PartialEq)]
pub enum CommandOptionValue {
    /// Attachment option.
    Attachment(Id<AttachmentMarker>),
    /// Boolean option.
    Boolean(bool),
    /// Channel option.
    Channel(Id<ChannelMarker>),
    /// Focused option.
    ///
    /// Since Discord does not validate focused fields, they are sent as strings.
    /// This means that you will not necessarily get a valid number from number options.
    ///
    /// See [Discord Docs/Autocomplete].
    ///
    /// The actual [`CommandOptionType`] is available through the second tuple value.
    ///
    /// [Discord Docs/Autocomplete]: https://discord.com/developers/docs/interactions/application-commands#autocomplete
    /// [`CommandOptionType`]: crate::application::command::CommandOptionType
    Focused(String, CommandOptionType),
    /// Integer option.
    Integer(i64),
    /// Mentionable option.
    Mentionable(Id<GenericMarker>),
    /// Number option.
    Number(f64),
    /// Role option.
    Role(Id<RoleMarker>),
    /// String option.
    String(String),
    /// Subcommand option.
    SubCommand(Vec<CommandDataOption>),
    /// Subcommand group option.
    SubCommandGroup(Vec<CommandDataOption>),
    /// User option.
    User(Id<UserMarker>),
}

impl From<Id<AttachmentMarker>> for CommandOptionValue {
    fn from(value: Id<AttachmentMarker>) -> Self {
        CommandOptionValue::Attachment(value)
    }
}

impl From<bool> for CommandOptionValue {
    fn from(value: bool) -> Self {
        CommandOptionValue::Boolean(value)
    }
}

impl From<Id<ChannelMarker>> for CommandOptionValue {
    fn from(value: Id<ChannelMarker>) -> Self {
        CommandOptionValue::Channel(value)
    }
}

impl From<i64> for CommandOptionValue {
    fn from(value: i64) -> Self {
        CommandOptionValue::Integer(value)
    }
}

impl From<f64> for CommandOptionValue {
    fn from(value: f64) -> Self {
        CommandOptionValue::Number(value)
    }
}

impl From<Id<RoleMarker>> for CommandOptionValue {
    fn from(value: Id<RoleMarker>) -> Self {
        CommandOptionValue::Role(value)
    }
}

impl From<String> for CommandOptionValue {
    fn from(value: String) -> Self {
        CommandOptionValue::String(value)
    }
}

impl From<Id<UserMarker>> for CommandOptionValue {
    fn from(value: Id<UserMarker>) -> Self {
        CommandOptionValue::User(value)
    }
}

impl CommandOptionValue {
    pub const fn kind(&self) -> CommandOptionType {
        match self {
            CommandOptionValue::Attachment(_) => CommandOptionType::Attachment,
            CommandOptionValue::Boolean(_) => CommandOptionType::Boolean,
            CommandOptionValue::Channel(_) => CommandOptionType::Channel,
            CommandOptionValue::Focused(_, t) => *t,
            CommandOptionValue::Integer(_) => CommandOptionType::Integer,
            CommandOptionValue::Mentionable(_) => CommandOptionType::Mentionable,
            CommandOptionValue::Number(_) => CommandOptionType::Number,
            CommandOptionValue::Role(_) => CommandOptionType::Role,
            CommandOptionValue::String(_) => CommandOptionType::String,
            CommandOptionValue::SubCommand(_) => CommandOptionType::SubCommand,
            CommandOptionValue::SubCommandGroup(_) => CommandOptionType::SubCommandGroup,
            CommandOptionValue::User(_) => CommandOptionType::User,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        application::{
            command::{CommandOptionType, CommandType},
            interaction::application_command::{
                CommandData, CommandDataOption, CommandOptionValue,
            },
        },
        id::Id,
    };
    use serde_test::Token;

    #[test]
    fn no_options() {
        let value = CommandData {
            guild_id: Some(Id::new(2)),
            id: Id::new(1),
            name: "permissions".to_owned(),
            kind: CommandType::ChatInput,
            options: Vec::new(),
            resolved: None,
            target_id: None,
        };
        serde_test::assert_tokens(
            &value,
            &[
                Token::Struct {
                    name: "CommandData",
                    len: 4,
                },
                Token::Str("guild_id"),
                Token::Some,
                Token::NewtypeStruct { name: "Id" },
                Token::Str("2"),
                Token::Str("id"),
                Token::NewtypeStruct { name: "Id" },
                Token::Str("1"),
                Token::Str("name"),
                Token::Str("permissions"),
                Token::Str("type"),
                Token::U8(CommandType::ChatInput.into()),
                Token::StructEnd,
            ],
        )
    }

    #[test]
    fn with_option() {
        let value = CommandData {
            guild_id: Some(Id::new(2)),
            id: Id::new(1),
            name: "permissions".to_owned(),
            kind: CommandType::ChatInput,
            options: Vec::from([CommandDataOption {
                name: "cat".to_owned(),
                value: CommandOptionValue::Integer(42),
            }]),
            resolved: None,
            target_id: None,
        };

        serde_test::assert_tokens(
            &value,
            &[
                Token::Struct {
                    name: "CommandData",
                    len: 5,
                },
                Token::Str("guild_id"),
                Token::Some,
                Token::NewtypeStruct { name: "Id" },
                Token::Str("2"),
                Token::Str("id"),
                Token::NewtypeStruct { name: "Id" },
                Token::Str("1"),
                Token::Str("name"),
                Token::Str("permissions"),
                Token::Str("type"),
                Token::U8(CommandType::ChatInput.into()),
                Token::Str("options"),
                Token::Seq { len: Some(1) },
                Token::Struct {
                    name: "CommandDataOption",
                    len: 3,
                },
                Token::Str("name"),
                Token::Str("cat"),
                Token::Str("type"),
                Token::U8(CommandOptionType::Integer as u8),
                Token::Str("value"),
                Token::I64(42),
                Token::StructEnd,
                Token::SeqEnd,
                Token::StructEnd,
            ],
        )
    }

    #[test]
    fn with_normal_option_and_autocomplete() {
        let value = CommandData {
            guild_id: Some(Id::new(2)),
            id: Id::new(1),
            name: "permissions".to_owned(),
            kind: CommandType::ChatInput,
            options: Vec::from([
                CommandDataOption {
                    name: "cat".to_owned(),
                    value: CommandOptionValue::Integer(42),
                },
                CommandDataOption {
                    name: "dog".to_owned(),
                    value: CommandOptionValue::Focused(
                        "Shiba".to_owned(),
                        CommandOptionType::String,
                    ),
                },
            ]),
            resolved: None,
            target_id: None,
        };

        serde_test::assert_de_tokens(
            &value,
            &[
                Token::Struct {
                    name: "CommandData",
                    len: 5,
                },
                Token::Str("guild_id"),
                Token::Some,
                Token::NewtypeStruct { name: "Id" },
                Token::Str("2"),
                Token::Str("id"),
                Token::NewtypeStruct { name: "Id" },
                Token::Str("1"),
                Token::Str("name"),
                Token::Str("permissions"),
                Token::Str("type"),
                Token::U8(CommandType::ChatInput.into()),
                Token::Str("options"),
                Token::Seq { len: Some(2) },
                Token::Struct {
                    name: "CommandDataOption",
                    len: 3,
                },
                Token::Str("name"),
                Token::Str("cat"),
                Token::Str("type"),
                Token::U8(CommandOptionType::Integer as u8),
                Token::Str("value"),
                Token::I64(42),
                Token::StructEnd,
                Token::Struct {
                    name: "CommandDataOption",
                    len: 4,
                },
                Token::Str("focused"),
                Token::Some,
                Token::Bool(true),
                Token::Str("name"),
                Token::Str("dog"),
                Token::Str("type"),
                Token::U8(CommandOptionType::String as u8),
                Token::Str("value"),
                Token::String("Shiba"),
                Token::StructEnd,
                Token::SeqEnd,
                Token::StructEnd,
            ],
        )
    }

    #[test]
    fn subcommand_without_option() {
        let value = CommandData {
            guild_id: None,
            id: Id::new(1),
            name: "photo".to_owned(),
            kind: CommandType::ChatInput,
            options: Vec::from([CommandDataOption {
                name: "cat".to_owned(),
                value: CommandOptionValue::SubCommand(Vec::new()),
            }]),
            resolved: None,
            target_id: None,
        };

        serde_test::assert_tokens(
            &value,
            &[
                Token::Struct {
                    name: "CommandData",
                    len: 4,
                },
                Token::Str("id"),
                Token::NewtypeStruct { name: "Id" },
                Token::Str("1"),
                Token::Str("name"),
                Token::Str("photo"),
                Token::Str("type"),
                Token::U8(CommandType::ChatInput.into()),
                Token::Str("options"),
                Token::Seq { len: Some(1) },
                Token::Struct {
                    name: "CommandDataOption",
                    len: 2,
                },
                Token::Str("name"),
                Token::Str("cat"),
                Token::Str("type"),
                Token::U8(CommandOptionType::SubCommand as u8),
                Token::StructEnd,
                Token::SeqEnd,
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn numbers() {
        let value = CommandDataOption {
            name: "opt".to_string(),
            value: CommandOptionValue::Number(5.0),
        };

        serde_test::assert_de_tokens(
            &value,
            &[
                Token::Struct {
                    name: "CommandDataOption",
                    len: 3,
                },
                Token::Str("name"),
                Token::Str("opt"),
                Token::Str("type"),
                Token::U8(CommandOptionType::Number as u8),
                Token::Str("value"),
                Token::I64(5),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn autocomplete() {
        let value = CommandDataOption {
            name: "opt".to_string(),
            value: CommandOptionValue::Focused(
                "not a number".to_owned(),
                CommandOptionType::Number,
            ),
        };

        serde_test::assert_de_tokens(
            &value,
            &[
                Token::Struct {
                    name: "CommandDataOption",
                    len: 4,
                },
                Token::Str("focused"),
                Token::Some,
                Token::Bool(true),
                Token::Str("name"),
                Token::Str("opt"),
                Token::Str("type"),
                Token::U8(CommandOptionType::Number as u8),
                Token::Str("value"),
                Token::String("not a number"),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn autocomplete_number() {
        let value = CommandDataOption {
            name: "opt".to_string(),
            value: CommandOptionValue::Focused("1".to_owned(), CommandOptionType::Number),
        };

        serde_test::assert_de_tokens(
            &value,
            &[
                Token::Struct {
                    name: "CommandDataOption",
                    len: 4,
                },
                Token::Str("focused"),
                Token::Some,
                Token::Bool(true),
                Token::Str("name"),
                Token::Str("opt"),
                Token::Str("type"),
                Token::U8(CommandOptionType::Number as u8),
                Token::Str("value"),
                Token::String("1"),
                Token::StructEnd,
            ],
        );
    }

    #[test]
    fn leading_zeroes_string_option_value() {
        let value = CommandDataOption {
            name: "opt".to_string(),
            value: CommandOptionValue::String("0001".to_owned()),
        };

        serde_test::assert_de_tokens(
            &value,
            &[
                Token::Struct {
                    name: "CommandDataOption",
                    len: 3,
                },
                Token::Str("name"),
                Token::Str("opt"),
                Token::Str("type"),
                Token::U8(CommandOptionType::String as u8),
                Token::Str("value"),
                Token::String("0001"),
                Token::StructEnd,
            ],
        );
    }
}
