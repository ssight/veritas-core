use serde::{Deserialize, Serialize};
use zbus::{DBusError, zvariant::Type};

#[derive(Debug, DBusError, Serialize, Deserialize, Type)]
pub enum GenericError {
    KeyRead(String),
    SigInfo(String),
    SignError(String),
    VerifyFailed(String),
    ImgLoad(String),
    DBus(String),
}

impl From<zbus::Error> for GenericError {
    fn from(value: zbus::Error) -> Self {
        GenericError::DBus(value.to_string())
    }
}

#[derive(Serialize, Deserialize, Type)]
pub struct PkInfo {
    pub id: String,
    pub authority: String,
    pub device_model: String,
    pub issued: u64,
}

#[derive(Serialize, Deserialize, Type)]
pub struct SigInfo {
    pub cert_id: String,
}
