use shared::{GenericError, PkInfo, SigInfo};
use std::fs;
use std::future;
use std::str::FromStr;
use uuid::Uuid;
use veritas_core::imgproc::ImageProcessor;
use veritas_core::key::SigningPublicKey;
use veritas_core::{SecureKernel, VerifierCtx};
use zbus::{connection, interface};

struct Service;

#[interface(name = "com.veritas.PrimaryService1")]
impl Service {
    fn keyread(&mut self, keypath: &str) -> Result<PkInfo, GenericError> {
        let bytes = fs::read(keypath).map_err(|e| GenericError::KeyRead(e.to_string()))?;
        let key = SigningPublicKey::try_from_bytes(&bytes)
            .map_err(|e| GenericError::KeyRead(e.to_string()))?;

        Ok(PkInfo {
            id: key.uuid().to_string(),
            authority: key.authority,
            device_model: key.device_model,
            issued: key.issued as u64,
        })
    }

    fn siginfo(&mut self, path: &str) -> Result<SigInfo, GenericError> {
        let image = ImageProcessor::load(path).map_err(|e| GenericError::SigInfo(e.to_string()))?;
        let header = image
            .read_header()
            .map_err(|e| GenericError::SigInfo(e.to_string()))?;

        Ok(SigInfo {
            cert_id: header.cert_id.to_string(),
        })
    }

    fn sign(&self, imgpath: &str, key_id: &str, newpath: &str) -> Result<(), GenericError> {
        let mut image =
            ImageProcessor::load(imgpath).map_err(|e| GenericError::ImgLoad(e.to_string()))?;
        let kernel = SecureKernel::new().map_err(|e| GenericError::SignError(e.to_string()))?;

        kernel
            .sign_image(
                &mut image,
                Uuid::from_str(key_id).map_err(|e| GenericError::KeyRead(e.to_string()))?,
            )
            .map_err(|e| GenericError::SignError(e.to_string()))?;

        image
            .write(newpath)
            .map_err(|e| GenericError::SignError(e.to_string()))?;

        Ok(())
    }

    fn verify(&self, imgpath: &str, keypath: &str) -> Result<bool, GenericError> {
        let key = {
            let bytes = fs::read(keypath).map_err(|e| GenericError::KeyRead(e.to_string()))?;
            SigningPublicKey::try_from_bytes(&bytes)
                .map_err(|e| GenericError::KeyRead(e.to_string()))?
        };
        let image =
            ImageProcessor::load(imgpath).map_err(|e| GenericError::ImgLoad(e.to_string()))?;

        let verifier = VerifierCtx::new(key).map_err(|e| GenericError::SignError(e.to_string()))?;

        match verifier.verify_image(image) {
            Ok(()) => Ok(true),
            Err(err) => Err(GenericError::VerifyFailed(err.to_string())),
        }
    }
}

#[tokio::main]
async fn main() {
    let _conn = connection::Builder::session()
        .unwrap()
        .name("com.veritas.PrimaryService")
        .unwrap()
        .serve_at("/com/veritas/PrimaryService", Service)
        .unwrap()
        .build()
        .await
        .unwrap();

    println!("Service is running.");

    future::pending::<()>().await;
}
