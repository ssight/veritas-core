mod crypto;
mod imgproc;
pub mod key;
mod tpm;

use anyhow::Result;
use crypto::{CryptoSigner, CryptoVerifier};
use imgproc::ImageProcessor;
use tpm::TpmModule;

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

    pub fn sign_image(&self, mut img: ImageProcessor) -> Result<()> {
        let sig = self.signer.sign(img.hash())?;
        img.sign_header(sig)?;

        img.write("signed.jpg")?;

        Ok(())
    }
}

pub struct VerifierCtx {
    verifier: CryptoVerifier,
}

impl VerifierCtx {
    pub fn new() -> Result<Self> {
        let key_bytes = std::fs::read("key.dump")?;
        Ok(VerifierCtx {
            verifier: CryptoVerifier::new(&key_bytes)?,
        })
    }

    pub fn verify_image(&self, mut img: ImageProcessor) -> Result<bool> {
        let sig = img.read_header()?;
        self.verifier.verify(&img.hash(), &sig)?;

        Ok(true)
    }
}
