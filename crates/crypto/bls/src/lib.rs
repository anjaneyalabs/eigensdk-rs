#![doc(
    html_logo_url = "https://github.com/supernovahs/eigensdk-rs/assets/91280922/bd13caec-3c00-4afc-839a-b83d2890beb5",
    issue_tracker_base_url = "https://github.com/supernovahs/eigen-rs/issues/"
)]
#![cfg_attr(not(test), warn(unused_crate_dependencies))]

pub mod attestation;

pub mod error;

use ark_bn254::{Fq, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{
    fields::{Field, PrimeField},
    BigInt, BigInteger, One,
};
use eigen_utils::
    binding::BLSApkRegistry::{G1Point, G2Point};
use ethers::{
    core::types::{H256},
    types::Address,
    utils::keccak256,
};
use num_bigint::BigUint;

pub type PrivateKey = Fr;
pub type PublicKey = G1Affine;
pub type BlsSignature = G1Affine;
pub type OperatorId = H256;

#[derive(Debug)]
pub struct BlsKeypair {
    pub private: PrivateKey,
    pub public: PublicKey,
}

impl From<BlsKeypair> for Option<G1Point> {
    fn from(val: BlsKeypair) -> Self {
        if let Some((x, y)) = val.public.xy() {
            Some(G1Point {
                X: alloy_primitives::U256::from_le_slice(&x.into_bigint().to_bytes_le()[..]),
                Y: alloy_primitives::U256::from_le_slice(&y.into_bigint().to_bytes_le()[..]),
            })
        } else {
            None
        }
    }
}

impl From<BlsKeypair> for Option<G2Point> {
    fn from(val: BlsKeypair) -> Self {
        let g2 = val.public_g2();
        if let Some((x, y)) = g2.xy() {
            Some(G2Point {
                X: [
                    alloy_primitives::U256::from_le_slice(&x.c0.into_bigint().to_bytes_le()[..]),
                    alloy_primitives::U256::from_le_slice(&x.c1.into_bigint().to_bytes_le()[..]),
                ],
                Y: [
                    alloy_primitives::U256::from_le_slice(&y.c0.into_bigint().to_bytes_le()[..]),
                    alloy_primitives::U256::from_le_slice(&y.c1.into_bigint().to_bytes_le()[..]),
                ],
            })
        } else {
            None
        }
    }
}

impl BlsKeypair {
    pub fn public_g2(&self) -> G2Affine {
        (G2Affine::generator() * self.private).into_affine()
    }

    pub fn operator_id(&self) -> OperatorId {
        let xy = self.public.xy().expect("should have public");
        keccak256(
            [
                xy.0.into_bigint().to_bytes_be(),
                xy.1.into_bigint().to_bytes_be(),
            ]
            .concat()
        ).into()
    }

    pub fn make_pubkey_registration_data(
        &self,
        operator_addr: Address,
        bls_pubkey_comp_addr: Address,
        chain_id: u64,
    ) -> eyre::Result<BlsSignature> {
        let bytes = [
            operator_addr.as_bytes(),
            bls_pubkey_comp_addr.as_bytes(),
            &[0_u8; 24],
            &chain_id.to_be_bytes(),
            b"EigenLayer_BN254_Pubkey_Registration",
        ]
        .concat();
        let hash: H256 = keccak256(&bytes).into();
        self.sign(hash.as_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> eyre::Result<BlsSignature> {
        let h = Self::map_to_curve(msg)?;
        let sig = h * self.private;

        Ok(sig.into_affine())
    }

    pub fn sign_hashed(&self, msg: G1Affine) -> eyre::Result<BlsSignature> {
        let sig = msg * self.private;

        Ok(sig.into_affine())
    }
    /// implements BN254 map to curve from
    /// contracts/lib/eigenlayer-middleware/lib/eigenlayer-contracts/src/contracts/libraries/BN254.sol
    /// for a hash, maps to a point on curve
    /// y^2 = x^3 + b
    fn map_to_curve(hash: &[u8]) -> eyre::Result<PublicKey> {
        let mut x: Fq = Fq::from_be_bytes_mod_order(hash);
        let b = BigInt::<4>::from(3_u32);

        loop {
            let beta = x.pow(b) + Fq::from(3_u32);
            if let Some(y) = beta.sqrt() {
                return Ok(PublicKey::new(x, y));
            } else {
                x += Fq::one()
            }
        }
    }
}


pub struct EthConvert;
impl EthConvert {
    pub fn to_u256(p: &Fq) -> alloy_primitives::U256 {
        alloy_primitives::U256::from_le_slice(&p.into_bigint().to_bytes_le()[..])
    }

    pub fn to_g1(xy: G1Affine) -> Option<G1Point> {
        xy.xy().map(|(x, y)| G1Point {
            X: EthConvert::to_u256(x),
            Y: EthConvert::to_u256(y),
        })
    }

    pub fn to_g2(xy: G2Affine) -> Option<G2Point> {
        xy.xy().map(|(x, y)| G2Point {
            X: [EthConvert::to_u256(&x.c1), EthConvert::to_u256(&x.c0)],
            Y: [EthConvert::to_u256(&y.c1), EthConvert::to_u256(&y.c0)],
        })
    }

    pub fn from_g1(xy: G1Point) -> G1Affine {
        let x = BigUint::from_bytes_le(&xy.X.to_le_bytes::<32>()[..]);
        let y = BigUint::from_bytes_le(&xy.Y.to_le_bytes::<32>()[..]);
        G1Affine::new(x.into(), y.into())
    }
}


#[test]
fn test_map_parity() {
    use std::str::FromStr;
    // taken from golang impl
    let x = Fq::from_str(
        "21808877952123445795107598745041753552237365029343566086488416315631580963384",
    )
    .unwrap();
    let y = Fq::from_str(
        "11638128931416599220980524115187668264422283409187640152391635080130668110949",
    )
    .unwrap();
    let expected = PublicKey::new(x, y);
    let msg = b"07c2ee97b7ae54ffe597b9db97ede3b7";
    let r = BlsKeypair::map_to_curve(msg).unwrap();
    assert_eq!(r, expected);
}