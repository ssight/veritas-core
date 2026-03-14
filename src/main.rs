use std::io::{self, Write};
use std::{env, fs, process};
use veritas_core::key::{PkInfo, SigningPublicKey};

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
    keyread [path] - Read information about a public key"
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
            let key: SigningPublicKey = bitcode::decode(&fs::read(path).unwrap()).unwrap();

            println!(
                "Key Info:
    > Authority Name: {}
    > Device Model: {}
    > Issued: {}",
                key.authority, key.device_model, key.issued
            );
        }

        _ => eprintln!("Invalid command. Run without args for help."),
    }
}
