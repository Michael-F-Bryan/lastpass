use std::{ops::Deref, str::FromStr};

/// A unique resource identifier.
#[derive(Debug, Clone, PartialEq, Hash, Eq, PartialOrd, Ord)]
pub struct Id(String);

impl<S: Into<String>> From<S> for Id {
    fn from(other: S) -> Id { Id(other.into()) }
}

impl Deref for Id {
    type Target = str;

    fn deref(&self) -> &str { &self.0 }
}

impl FromStr for Id {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Id, Self::Err> { Ok(Id::from(s)) }
}
