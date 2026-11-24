use crate::error::ValidationError;
use crate::types::{CredentialValues, MakeCredentialValues};
use crate::utils::validation::Validatable;
use std::collections::HashMap;
use zeroize::Zeroize;

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct CredentialSubject(pub HashMap<String, CredentialAttributeValue>);

#[cfg(feature = "zeroize")]
impl Drop for CredentialSubject {
    fn drop(&mut self) {
        self.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for CredentialSubject {
    fn zeroize(&mut self) {
        for attr in self.0.values_mut() {
            if let CredentialAttributeValue::String(attr) = attr {
                attr.zeroize()
            }
        }
    }
}

impl Validatable for CredentialSubject {
    fn validate(&self) -> std::result::Result<(), ValidationError> {
        if self.0.is_empty() {
            return Err(
                "CredentialAttributes validation failed: empty list has been passed".into(),
            );
        }
        Ok(())
    }
}

impl CredentialAttributeValue {
    /// A raw value is a number only when writing the number back gives the raw value, so a value
    /// with leading zeros, such as "00123", stays a string as issued.
    pub(crate) fn from_raw(raw: &str) -> Self {
        match raw.parse::<i32>() {
            Ok(number) if number.to_string() == raw => CredentialAttributeValue::Number(number),
            _ => CredentialAttributeValue::String(raw.to_string()),
        }
    }
}

impl From<&CredentialValues> for CredentialSubject {
    fn from(values: &CredentialValues) -> Self {
        CredentialSubject(
            values
                .0
                .iter()
                .map(|(attribute, values)| {
                    (
                        attribute.to_string(),
                        CredentialAttributeValue::from_raw(&values.raw),
                    )
                })
                .collect(),
        )
    }
}

impl CredentialSubject {
    pub(crate) fn add_attribute(&mut self, attribute: String, value: CredentialAttributeValue) {
        self.0.insert(attribute, value);
    }

    pub(crate) fn add_predicate(&mut self, attribute: String) -> crate::Result<()> {
        match self.0.get(&attribute) {
            Some(value) => {
                match value {
                    CredentialAttributeValue::String(_) | CredentialAttributeValue::Number(_) => {
                        Err(err_msg!("Predicate cannot be added for revealed attribute"))
                    }
                    CredentialAttributeValue::Bool(_) => {
                        // predicate already exists
                        Ok(())
                    }
                }
            }
            None => {
                self.0
                    .insert(attribute, CredentialAttributeValue::Bool(true));
                Ok(())
            }
        }
    }

    pub(crate) fn encode(&self) -> crate::Result<CredentialValues> {
        let mut cred_values = MakeCredentialValues::default();
        for (attribute, raw_value) in self.0.iter() {
            match raw_value {
                CredentialAttributeValue::String(raw_value) => {
                    cred_values.add_raw(attribute, raw_value)?
                }
                CredentialAttributeValue::Number(raw_value) => {
                    cred_values.add_raw(attribute, raw_value.to_string())?
                }
                value => {
                    return Err(err_msg!(
                        "Encoding is not supported for credential value {:?}",
                        value
                    ));
                }
            }
        }
        Ok(cred_values.into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CredentialAttributeValue {
    // attribute representation
    String(String),
    Number(i32),
    // predicates representation
    Bool(bool),
}

impl ToString for CredentialAttributeValue {
    fn to_string(&self) -> String {
        match self {
            CredentialAttributeValue::String(string) => string.to_owned(),
            CredentialAttributeValue::Number(number) => number.to_string(),
            CredentialAttributeValue::Bool(bool) => bool.to_string(),
        }
    }
}
