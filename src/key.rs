use crate::{TPM_DATA_ADDR, tpm::TpmModule};
use anyhow::Result;
use bitcode::{Decode, Encode};
use rsa::{RsaPrivateKey, pkcs1::EncodeRsaPublicKey, pkcs8::EncodePrivateKey};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

#[derive(Encode, Decode)]
pub struct SigningPublicKey {
    pub(super) key_bytes: Vec<u8>,
    pub(super) uuid: [u8; 16],
    pub authority: String,
    pub device_model: String,
    pub issued: u128,
}

pub struct PkInfo {
    pub authority: String,
    pub device_model: String,
}

impl SigningPublicKey {
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(bitcode::decode(&bytes)?)
    }

    pub fn gen_new(info: PkInfo) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048)?;

        {
            let key_bytes = private_key.to_pkcs8_der()?.to_bytes();

            let mut tpm = TpmModule::new()?;
            tpm.write_data(TPM_DATA_ADDR, &key_bytes)?;
        }

        let public_key = private_key.to_public_key();

        Ok(SigningPublicKey {
            key_bytes: public_key.to_pkcs1_der()?.as_bytes().to_vec(),
            uuid: *Uuid::new_v4().as_bytes(),
            authority: info.authority,
            device_model: info.device_model,
            issued: SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
        })
    }

    pub fn uuid(&self) -> Uuid {
        Uuid::from_bytes(self.uuid)
    }
}
