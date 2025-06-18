use ark_bn254::Bn254;
use ark_circom::CircomBuilder;
use ark_circom::CircomConfig;
use ark_groth16::{Groth16, prepare_verifying_key};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use num_bigint::BigInt;
use rand::SeedableRng;
use rand::rngs::StdRng;

#[tokio::main]
async fn main() {
    // Load the WASM and R1CS for witness and proof generation
    let cfg = CircomConfig::<ark_bn254::Fr>::new(
        "./target/circuits/UTXOChecker_js/UTXOChecker.wasm",
        "./target/circuits/UTXOChecker.r1cs",
    )
    .unwrap();
    let mut builder = CircomBuilder::new(cfg);

    // Private inputs: A factorisation of a number
    let in_assets = vec![BigInt::from(1); 10];

    let in_amount = vec![BigInt::from(10000); 10];
    let mut in_blinding = vec![];
    let mut in_secret_keys = vec![];

    for i in 0..10 {
        in_secret_keys.push(BigInt::from(i + 1212531253));
        in_blinding.push(BigInt::from(i + 2131231253));
    }

    builder.inputs.insert("in_assets".into(), in_assets);
    builder.inputs.insert("in_amounts".into(), in_amount);
    builder.inputs.insert("in_blinding".into(), in_blinding);
    builder
        .inputs
        .insert("in_secret_keys".into(), in_secret_keys);

    let out_asset = vec![BigInt::from(1); 5];
    let out_amount = vec![BigInt::from(20000); 5];
    let mut out_blinding = vec![];

    for i in 0..5 {
        out_blinding.push(BigInt::from(i + 215531253));
    }

    builder.inputs.insert("out_asset".into(), out_asset);
    builder.inputs.insert("out_amount".into(), out_amount);
    builder.inputs.insert("out_blinding".into(), out_blinding);

    let circuit = builder.setup();

    // Generate a random proving key. WARNING: This is not secure. A proving key generated from a ceremony should be used in production.
    let mut rng: StdRng = SeedableRng::from_seed([0; 32]);
    let pk =
        Groth16::<Bn254>::generate_random_parameters_with_reduction(circuit, &mut rng).unwrap();

    let circuit = builder.build().unwrap();
    let public_inputs = circuit.get_public_inputs().unwrap();

    // Create proof
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();

    // Verify proof
    let pvk = prepare_verifying_key(&pk.vk);
    let verified =
        Groth16::<Bn254>::verify_with_processed_vk(&pvk, &public_inputs, &proof).unwrap();
    assert!(verified);

    // Print verifying key
    let mut pk_bytes = Vec::new();
    pk.vk.serialize_compressed(&mut pk_bytes).unwrap();
    println!("Verifying key: {}", hex::encode(pk_bytes));

    // Print proof
    let mut proof_serialized = Vec::new();
    proof.serialize_compressed(&mut proof_serialized).unwrap();
    println!("Proof: {}", hex::encode(proof_serialized));

    // Print public inputs. Note that they are concatenated.
    let mut public_inputs_serialized = Vec::new();
    public_inputs.iter().for_each(|input| {
        input
            .serialize_compressed(&mut public_inputs_serialized)
            .unwrap();
    });
    println!("Public inputs: {}", hex::encode(public_inputs_serialized));
}
