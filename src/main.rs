use std::io::{self, Write};
use std::{env, fs, process};
use veritas_core::imgproc::ImageProcessor;
use veritas_core::key::{PkInfo, SigningPublicKey};
use veritas_core::{SecureKernel, VerifierCtx};

macro_rules! read_line {
    ($msg: expr) => {{
        print!($msg);
        io::stdout().flush().unwrap();
        io::stdin().lines().next().unwrap().unwrap()
    }};
}

fn main() {
    let Some(cmd) = env::args().nth(1) else {
        eprintln!(
            "USAGE:
    keygen - Generate a new public/private key pair
    keyread [keypath] - Read information about a public key
    siginfo [imgpath] - Read the signature information of a given image
    sign [imgpath] [keypath] - Sign an image with the current private key and public key ID
    verify [imgpath] [keypath] - Verify an image with a given public key"
        );

        process::exit(-1);
    };

    match cmd.as_str() {
        "keygen" => {
            let info = PkInfo {
                authority: read_line!("Enter Authority Name> "),
                device_model: read_line!("Enter Device Model> "),
            };

            let key = SigningPublicKey::gen_new(info).unwrap();
            fs::write("pubkey.vpk", &bitcode::encode(&key)).unwrap();

            println!("Private key attested by and saved to TPM chip");
            println!("Public key successfully written to pubkey.vpk file");
        }

        "keyread" => {
            let path = env::args().nth(2).unwrap();
            let key = SigningPublicKey::try_from_bytes(&fs::read(path).unwrap()).unwrap();

            println!(
                "Key Info:
  > Certificate ID: {}
  > Authority Name: {}
  > Device Model: {}
  > Issued: {}",
                key.uuid(),
                key.authority,
                key.device_model,
                key.issued,
            );
        }

        "siginfo" => {
            let path = env::args().nth(2).unwrap();
            let image = ImageProcessor::load(path).unwrap();
            let header = image.read_header().unwrap();
            println!(
                "Image has valid header.
Public key certificate ID: {}",
                header.cert_id
            );
        }

        "sign" => {
            let imgpath = env::args().nth(2).unwrap();
            let keypath = env::args().nth(3).unwrap();

            let key = SigningPublicKey::try_from_bytes(&fs::read(keypath).unwrap()).unwrap();
            let mut image = ImageProcessor::load(imgpath).unwrap();

            let kernel = SecureKernel::new().unwrap();
            kernel.sign_image(&mut image, key.uuid()).unwrap();

            image.write("signed.jpg").unwrap();
            println!("Image attested and saved to signed.jpg");
        }

        "verify" => {
            let img_path = env::args().nth(2).unwrap();
            let pubkey_path = env::args().nth(3).unwrap();

            let key = SigningPublicKey::try_from_bytes(&fs::read(pubkey_path).unwrap()).unwrap();
            let image = ImageProcessor::load(img_path).unwrap();

            let success_txt = format!(
                "Image successfully verified with specified public key.
Image has been signed by Authority '{}' with Device '{}'",
                key.authority, key.device_model
            );

            let verifier = VerifierCtx::new(key).unwrap();
            match verifier.verify_image(image) {
                Ok(()) => println!("{success_txt}"),
                Err(err) => eprintln!("Verification failed: {}", err),
            }
        }

        _ => eprintln!("Invalid command. Run without args for help."),
    }
}
