use anyhow::Result;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs1v15::{Signature, SigningKey, VerifyingKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;

pub struct CryptoSigner {
    key: SigningKey<Sha256>,
}

impl CryptoSigner {
    pub fn new(private_key: &[u8]) -> Result<Self> {
        let key = RsaPrivateKey::from_pkcs8_der(private_key)?;
        Ok(CryptoSigner {
            key: SigningKey::<Sha256>::new(key),
        })
    }

    pub fn sign(&self, data: Vec<u8>) -> Result<Vec<u8>> {
        Ok(self.key.try_sign(&data)?.to_vec())
    }
}

pub struct CryptoVerifier {
    key: VerifyingKey<Sha256>,
}

impl CryptoVerifier {
    pub fn new(pub_key: &[u8]) -> Result<Self> {
        let key = RsaPublicKey::from_pkcs1_der(pub_key)?;
        Ok(CryptoVerifier {
            key: VerifyingKey::<Sha256>::new(key),
        })
    }

    pub fn verify(&self, data: &[u8], sig: &[u8]) -> Result<()> {
        self.key.verify(data, &Signature::try_from(sig)?)?;
        Ok(())
    }
}
