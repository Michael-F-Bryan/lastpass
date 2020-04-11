use std::str::FromStr;

#[derive(Debug, Clone, PartialEq)]
pub struct PrivateKey(Vec<u8>);

impl FromStr for PrivateKey {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<PrivateKey, Self::Err> {
        hex::decode(s).map(PrivateKey)
    }
}
