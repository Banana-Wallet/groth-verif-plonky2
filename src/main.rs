use anyhow::Result;
use ark_ec::AffineRepr;
use ark_ec::short_weierstrass::Affine;
use ark_std::UniformRand;
use plonky2::field::extension::Extendable;
// use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{Target, BoolTarget, self};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::PrimeField64},
};
use core::num::ParseIntError;
use std::char::from_digit;
// use pairing::G1Point;

use ark_bn254::{Fq12, G1Affine, G2Affine, Config};
use ark_ff::fields::Field;
use itertools::Itertools;

use plonky2_bn254_pairing::pairing::pairing;

use ark_bn254::{Fq2, Fr, G2Projective};


#[allow(non_snake_case)]
pub fn inner_product(A: &[G1Affine], B: &[G2Affine]) -> Fq12 {
    assert_eq!(A.len(), B.len());
    let r_vec = A
        .iter()
        .zip(B.iter())
        .map(|(a, b)| pairing(*a, *b))
        .collect_vec();
    r_vec.iter().fold(Fq12::ONE, |acc, x| acc * x)
}

fn main() {
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    let log_n = 2;
    let n = 1 << log_n;
    println!("Aggregating {} pairings into 1", n);
    let mut rng = rand::thread_rng();
    let A = (0..n).map(|_| G1Affine::rand(&mut rng)).collect_vec();
    let B = (0..n).map(|_| G2Affine::rand(&mut rng)).collect_vec();
    // let sipp_proof = sipp_prove_native(&A, &B);
    let aa = A[0];
    let ax = aa.x();
    println!("A[0] = {:?}", A[0]);
    println!("B[0] = {:?}", B[0]);
    // let sipp_statement = sipp_verify_native(&A, &B, &sipp_proof).unwrap();
    let prod = inner_product(&A, &B);
    println!("prod = {:?}", prod);

    let new_pt = Affine::<F>::from({
        
    })

    // G1Affine::from(Affine;
    // verify_proof()
}
