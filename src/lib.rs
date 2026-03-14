mod crypto;
pub mod imgproc;
pub mod key;
mod tpm;

use anyhow::Result;
use crypto::{CryptoSigner, CryptoVerifier};
use imgproc::{ImageProcessor, ImgHeader};
use key::SigningPublicKey;
use tpm::TpmModule;
use uuid::Uuid;

pub const TPM_DATA_ADDR: u32 = 0x01500001;

pub struct SecureKernel {
    signer: CryptoSigner,
}

impl SecureKernel {
    pub fn new() -> Result<Self> {
        Ok(SecureKernel {
            signer: SecureKernel::load_private_key()?,
        })
    }

    fn load_private_key() -> Result<CryptoSigner> {
        let mut tpm = TpmModule::new()?;
        let key_bytes = tpm.read_data(TPM_DATA_ADDR)?;
        let signer = CryptoSigner::new(&key_bytes)?;

        Ok(signer)
    }

    pub fn sign_image(&self, img: &mut ImageProcessor, pub_key_id: Uuid) -> Result<()> {
        let header = ImgHeader {
            cert_id: pub_key_id,
            sig: self.signer.sign(img.hash())?,
        };

        img.sign_header(header)?;

        Ok(())
    }
}

pub struct VerifierCtx {
    verifier: CryptoVerifier,
}

impl VerifierCtx {
    pub fn new(key: SigningPublicKey) -> Result<Self> {
        Ok(VerifierCtx {
            verifier: CryptoVerifier::new(&key.key_bytes)?,
        })
    }

    pub fn verify_image(&self, mut img: ImageProcessor) -> Result<()> {
        let header = img.read_header()?;
        self.verifier.verify(&img.hash(), &header.sig)?;

        Ok(())
    }
}
