use shared::{GenericError, PkInfo, SigInfo};
use zbus::proxy;

#[proxy(
    interface = "com.veritas.PrimaryService1",
    default_service = "com.veritas.PrimaryService",
    default_path = "/com/veritas/PrimaryService"
)]
pub trait Service {
    async fn keyread(&self, keypath: &str) -> Result<PkInfo, GenericError>;
    async fn siginfo(&self, path: &str) -> Result<SigInfo, GenericError>;
    async fn sign(&self, imgpath: &str, key_id: &str, newpath: &str) -> Result<(), GenericError>;
    async fn verify(&self, imgpath: &str, keypath: &str) -> Result<bool, GenericError>;
}
