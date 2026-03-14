use anyhow::{Context, Result};
use image::ImageReader;
use img_parts::Bytes;
use img_parts::jpeg::{Jpeg, JpegSegment, markers};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::path::Path;

pub struct ImageProcessor {
    jpeg: Jpeg,
    data_bytes: Vec<u8>,
}

impl ImageProcessor {
    pub fn load<T: AsRef<Path>>(path: T) -> Result<Self> {
        Ok(ImageProcessor {
            jpeg: Jpeg::from_bytes(fs::read(&path)?.into())?,
            data_bytes: ImageReader::open(&path)?
                .with_guessed_format()?
                .decode()?
                .into_rgb8()
                .into_vec(),
        })
    }

    pub fn hash(&mut self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&self.data_bytes);
        let bytes = hasher.finalize();
        bytes.to_vec()
    }

    pub fn sign_header(&mut self, sig: Vec<u8>) -> Result<()> {
        let segment = JpegSegment::new_with_contents(markers::COM, Bytes::from(sig));
        self.jpeg.segments_mut().insert(1, segment);

        Ok(())
    }

    pub fn write<T: AsRef<Path>>(self, path: T) -> Result<()> {
        let file = File::create(path)?;
        self.jpeg.encoder().write_to(file)?;
        Ok(())
    }

    pub fn read_header(&self) -> Result<Vec<u8>> {
        let sig = self
            .jpeg
            .segment_by_marker(markers::COM)
            .context("No valid signature in header")?;

        Ok(sig.contents().to_vec())
    }
}
