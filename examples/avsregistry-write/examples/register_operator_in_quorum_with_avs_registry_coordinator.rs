//! register operator in quorum with avs registry coordinator
use alloy_primitives::U256;
use alloy_primitives::{Bytes, FixedBytes};
use alloy_provider::Provider;
use alloy_signer_wallet::LocalWallet;
use ark_bn254::{Fq, Fr, G1Affine};
use ark_ff::fields::PrimeField;
use ark_ff::UniformRand;
use ark_ff::{BigInt, BigInteger};
use ark_std::{ops::Mul, test_rng};
use eigen_chainio_utils::convert_to_bn254_g1_point;
use eigen_client_avsregistry::writer::AvsRegistryChainWriter;
use eigen_client_elcontracts::reader::ELChainReader;
use eigen_crypto_bls::attestation::KeyPair;
use eigen_testing_utils::m2_holesky_constants::{
    AVS_DIRECTORY_ADDRESS, BLS_APK_REGISTRY, DELEGATION_MANAGER_ADDRESS, OPERATOR_STATE_RETRIEVER,
    REGISTRY_COORDINATOR, SERVICE_MANAGER_ADDRESS, SLASHER_ADDRESS, STAKE_REGISTRY,
};
use eigen_utils::get_provider;
use eyre::Result;
use std::str::FromStr;
#[tokio::main]
async fn main() -> Result<()> {
    let holesky_provider = "https://holesky.drpc.org";
    let pvt_key = "8368c0eaa43b1d954c991c77c72585f661e5a626a2070355b2df2b0cefb658ae";
    let el_chain_reader: ELChainReader = ELChainReader::new(
        SLASHER_ADDRESS,
        DELEGATION_MANAGER_ADDRESS,
        AVS_DIRECTORY_ADDRESS,
        holesky_provider.to_string(),
    );
    let avs_registry_writer = AvsRegistryChainWriter::new(
        SERVICE_MANAGER_ADDRESS,
        REGISTRY_COORDINATOR,
        OPERATOR_STATE_RETRIEVER,
        STAKE_REGISTRY,
        BLS_APK_REGISTRY,
        el_chain_reader,
        holesky_provider.to_string(),
        pvt_key.to_string(),
    )
    .await;

    let mut rng = ark_std::test_rng();
    let sk = Fr::rand(&mut rng);

    let fixed_bls_key = Fr::from(BigInt([9016117505638758543, 352751388875653018, 14946620785396285244, 211688466542070544]));

    let key_pair: KeyPair = KeyPair::new(fixed_bls_key).unwrap();
    println!(
        "check if operator address is within the prime field : {:?}",
        U256::from_be_bytes(*LocalWallet::from_str(pvt_key).unwrap().to_bytes())
            < U256::from_str(
                "21888242871839275222246405745257275088696311157297823662689037894645226208583"
            )
            .unwrap()
    );
    let digest_hash: FixedBytes<32> = FixedBytes::from([
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
        0x02, 0x02,
    ]);
    let provider = get_provider(&holesky_provider.to_string());
    let current_block_number = provider.get_block_number().await?;
    let sig_expiry: U256 = U256::from(current_block_number + 20);
    let quorum_nums = Bytes::from([0x01]);
    println!("quorum nums : {:?}", quorum_nums);
    let tx_hash = avs_registry_writer
        .register_operator_in_quorum_with_avs_registry_coordinator(
            key_pair,
            digest_hash,
            U256::from(1719564571),
            quorum_nums,
            "65.109.158.181:33078;31078".to_string(),
        )
        .await
        .unwrap();
    println!("tx hash :{:?}", tx_hash);
    Ok(())
}

pub fn deserialize_montgomery_elements(data: &[Fr], buffer: &mut Vec<u8>) {
    let mut temp_buffer: Vec<u8> = data
        .iter()
        .rev()
        .flat_map(|elem| elem.into_bigint().to_bytes_le())
        .collect();

    temp_buffer.reverse();
    buffer.extend(temp_buffer);
}

// #[tokio::main]
// async fn main() {}
