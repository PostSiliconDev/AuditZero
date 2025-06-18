use ark_ec::CurveGroup;
use ark_ed_on_bn254::{Fq, Fr};
use ark_ff::{Field, UniformRand};
use rand::rngs::OsRng;

use crate::config::generator;

mod config;

fn main() {
    let sk = Fr::rand(&mut OsRng);

    let base8 = generator();

    println!("base8 is on curve: {}", base8.is_on_curve());

    let pk = base8 * sk;

    let pk = pk.into_affine();

    let a = Fq::from(168700u64);
    let d = Fq::from(168696u64);
    let x2 = pk.x.square();
    let y2 = pk.y.square();
    let left = a * x2 + y2;
    let right = Fq::ONE + d * x2 * y2;
    println!("Check: {} == {} => {}", left, right, left == right);

    println!("Private key (Fr) : {}", sk);
    println!("Public key (x): {}", pk.x);
    println!("Public key (y): {}", pk.y);
}
