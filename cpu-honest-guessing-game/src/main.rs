use ansi_term::Colour::{Blue, Red};
use merlin::Transcript;
use rand::thread_rng;
use rand::Rng;
use schnorrkel::{
    vrf::{VRFInOut, VRFPreOut, VRFProof},
    Keypair, PublicKey,
};
use std::cmp::Ordering;
use std::io;
use std::process;

const MAX_SECRET_NUMBER: u8 = 10;

fn main() {
    println!("Welcome to Honest guessing game.");
    let prng = rand_core::OsRng;
    let keypair = Keypair::generate_with(prng);

    loop {
        println!(
            "{}: {:?}",
            Blue.paint("Public key"),
            keypair.public.to_bytes()
        );
        let vrf_seed = get_random_seed();
        println!("{}: {:?}", Blue.paint("Seed"), vrf_seed);

        let (secret_number, signature) = vrf(&keypair, &vrf_seed);
        println!("{}: {:?}", Blue.paint("Signature"), signature);

        #[cfg(debug_assertions)]
        println!("{} {}", Red.paint("DEBUG: secret_number ="), secret_number);

        let mut count = 0;
        loop {
            println!();
            let mut guess = String::new();
            println!("Enter your guess between 0 and {}: ", MAX_SECRET_NUMBER - 1);
            if let Err(e) = io::stdin().read_line(&mut guess) {
                eprintln!("Error: {}", e);
                process::exit(1);
            }

            let guess = match guess.trim().parse::<u8>() {
                Ok(nb) => nb,
                Err(e) => {
                    println!("Error: {}", e);
                    continue;
                }
            };

            count += 1;

            match guess.cmp(&secret_number) {
                Ordering::Greater => println!("Too big."),
                Ordering::Less => println!("Too small."),
                Ordering::Equal => {
                    println!(
                        "Congratulations you found {} in {} tries",
                        secret_number, count
                    );
                    break;
                }
            }
        }

        println!("Please verify signature by yourself");
        let verified_secret = verify(&keypair.public, &signature, &vrf_seed).unwrap();
        if verified_secret == secret_number {
            println!("Verification done, i am an honest cpu");
        } else {
            println!(
                "Verfication failed, {} != {}",
                secret_number, verified_secret
            );
        }
    }
}

fn get_random_seed() -> [u8; 32] {
    let mut seed = [0u8; 32];
    thread_rng()
        .try_fill(&mut seed[..])
        .expect("Error: can't generate seed");
    seed
}

fn vrf(keypair: &Keypair, vrf_seed: &[u8]) -> (u8, [u8; 96]) {
    let mut t = Transcript::new(b"Secret Number Transcript");
    t.append_message(b"seed", &vrf_seed);
    let (io, proof, _) = keypair.vrf_sign(t);
    let b: [u8; 8] = io.make_bytes(b"secret");
    let secret_number = (u64::from_le_bytes(b) % (MAX_SECRET_NUMBER as u64)) as u8;
    let mut signature = [0u8; 96];
    // the first 32 bytes are io
    signature[..32].copy_from_slice(&io.to_preout().to_bytes()[..]);
    // the next 64 bytes are the proof
    signature[32..96].copy_from_slice(&proof.to_bytes()[..]);
    (secret_number, signature)
}

// TODO: redundant code with vrf cuntion, please factor
fn verify(public: &PublicKey, vrf_signature: &[u8; 96], vrf_seed: &[u8; 32]) -> Option<u8> {
    let mut t = Transcript::new(b"Secret Number Transcript");
    t.append_message(b"seed", vrf_seed);
    let out = VRFPreOut::from_bytes(&vrf_signature[..32]).ok()?;
    let proof = VRFProof::from_bytes(&vrf_signature[32..96]).ok()?;
    let (io, _) = public.vrf_verify(t, &out, &proof).ok()?;
    let b: [u8; 8] = io.make_bytes(b"secret");
    let secret_number = (u64::from_le_bytes(b) % (MAX_SECRET_NUMBER as u64)) as u8;
    Some(secret_number)
}
