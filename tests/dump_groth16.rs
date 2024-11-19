use ark_circom::{CircomBuilder, CircomConfig};
use ark_std::rand::thread_rng;
use color_eyre::Result;

use ark_bn254::{Bn254, Fr};
use ark_crypto_primitives::snark::SNARK;
use ark_groth16::Groth16;
use ark_circom::utils::write_to_file;

type GrothBn = Groth16<Bn254>;

#[tokio::test]
async fn dump_groth16_proof() -> Result<()> {
    let cfg = CircomConfig::<Fr>::new(
        "./test-vectors/mycircuit.wasm",
        "./test-vectors/mycircuit.r1cs",
    )?;
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", 3);
    builder.push_input("b", 11);

    // create an empty instance for setting it up
    let circom = builder.setup();

    let mut rng = thread_rng();
    let params = GrothBn::generate_random_parameters_with_reduction(circom, &mut rng)?;

    let circom = builder.build()?;

    let inputs = circom.get_public_inputs().unwrap();

    let proof = GrothBn::prove(&params, circom, &mut rng)?;

    let pvk = GrothBn::process_vk(&params.vk).unwrap();

    let verified = GrothBn::verify_with_processed_vk(&pvk, &inputs, &proof)?;

    assert!(verified);

    // dump data
    write_to_file("circom_bn254_groth16.vk", &params.vk);
    write_to_file("circom_bn254_groth16.proof", &proof);
    write_to_file("circom_bn254_groth16.pi", &inputs);

    Ok(())
}

#[tokio::test]
#[cfg(feature = "circom-2")]
async fn dump_groth16_proof_circom2() -> Result<()> {
    let cfg = CircomConfig::<Fr>::new(
        "./test-vectors/circom2_multiplier2.wasm",
        "./test-vectors/circom2_multiplier2.r1cs",
    )?;
    let mut builder = CircomBuilder::new(cfg);
    builder.push_input("a", 3);
    builder.push_input("b", 11);

    // create an empty instance for setting it up
    let circom = builder.setup();

    let mut rng = thread_rng();
    let params = GrothBn::generate_random_parameters_with_reduction(circom, &mut rng)?;

    let circom = builder.build()?;

    let inputs = circom.get_public_inputs().unwrap();

    let proof = GrothBn::prove(&params, circom, &mut rng)?;

    let pvk = GrothBn::process_vk(&params.vk).unwrap();

    let verified = GrothBn::verify_with_processed_vk(&pvk, &inputs, &proof)?;

    assert!(verified);
    // dump data
    write_to_file("circom2_bn254_groth16.vk", &params.vk);
    write_to_file("circom2_bn254_groth16.proof", &proof);
    write_to_file("circom2_bn254_groth16.pi", &inputs);

    Ok(())
}

