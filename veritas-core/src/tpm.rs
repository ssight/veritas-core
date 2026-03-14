use anyhow::Result;
use tss_esapi::attributes::NvIndexAttributesBuilder;
use tss_esapi::handles::{NvIndexHandle, NvIndexTpmHandle};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::resource_handles::{NvAuth, Provision};
use tss_esapi::structures::{Digest, MaxNvBuffer, NvPublicBuilder};
use tss_esapi::tcti_ldr::DeviceConfig;
use tss_esapi::{Context, TctiNameConf};

pub struct TpmModule {
    ctx: Context,
}

impl TpmModule {
    pub fn new() -> Result<Self> {
        Ok(TpmModule {
            ctx: Context::new(TctiNameConf::Device(DeviceConfig::default()))?,
        })
    }

    pub fn write_data(&mut self, addr: u32, data: &[u8]) -> Result<()> {
        let tpm_handle = NvIndexTpmHandle::new(addr)?;

        let nv_public = NvPublicBuilder::new()
            .with_nv_index(tpm_handle)
            .with_index_name_algorithm(HashingAlgorithm::Sha256)
            .with_index_auth_policy(Digest::try_from(Vec::new())?)
            .with_data_area_size(data.len())
            .with_index_attributes(
                NvIndexAttributesBuilder::new()
                    .with_owner_write(true)
                    .with_owner_read(true)
                    .with_pp_read(true)
                    .build()?,
            )
            .build()?;

        let nv_handle = self.ctx.execute_with_nullauth_session(|ctx| {
            ctx.nv_define_space(Provision::Owner, None, nv_public)
        })?;

        let data = MaxNvBuffer::try_from(data)?;

        self.ctx
            .execute_with_nullauth_session(|ctx| ctx.nv_write(NvAuth::Owner, nv_handle, data, 0))?;

        Ok(())
    }

    pub fn read_data(&mut self, addr: u32) -> Result<Vec<u8>> {
        let tpm_handle = NvIndexTpmHandle::new(addr)?;
        let esys_handle = self.ctx.tr_from_tpm_public(tpm_handle.into())?;

        let (nv_public, _) = self.ctx.nv_read_public(NvIndexHandle::from(esys_handle))?;

        let data = self.ctx.execute_with_nullauth_session(|ctx| {
            ctx.nv_read(
                NvAuth::Owner,
                NvIndexHandle::from(esys_handle),
                nv_public.data_size() as u16,
                0,
            )
        })?;

        Ok(data.to_vec())
    }
}
