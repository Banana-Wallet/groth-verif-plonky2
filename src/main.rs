use anyhow::Result;
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, CurveConfig, CurveGroup};
use ark_ec::short_weierstrass::Affine;
use ark_ff::{MontFp, QuadExtConfig};
use ark_std::UniformRand;
use num_bigint::ToBigInt;
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
use plonky2_ecdsa::curve::curve_types::Curve;
use rayon::str;
use core::num::ParseIntError;
use std::char::from_digit;
use std::ops::{Add, Neg};
// use pairing::G1Point;

use ark_bn254::{Fq12, G1Affine, G2Affine, Config, Fq, fr};
use ark_bn254::{Fq2, Fr, G2Projective};
// use ark_bls12_381::{Fq, Fq2, Fr, Fq12, G1Affine, G2Affine, G1Projective, G2Projective};
use ark_ff::fields::Field;

use itertools::Itertools;

use plonky2_bn254_pairing::pairing::pairing;


pub struct VerificationKey {
    pub alpha1: G1Affine,
    pub beta2: G2Affine,
    pub gamma2: G2Affine,
    pub delta2: G2Affine,
    pub ic: Vec<G1Affine>,

}

pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine
}


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

fn get_verification_key() -> VerificationKey {
    VerificationKey {
        alpha1: G1Affine::new(
            Fq::from(1),
            Fq::from(2),
        ),
        beta2: G2Affine::new(
            Fq2::new(
                MontFp!("10857046999023057135944570762232829481370756359578518086990519993285655852781"),

                MontFp!("11559732032986387107991004021392285783925812861821192530917403151452391805634"),
            ),
            Fq2::new(
                MontFp!("8495653923123431417604973247489272438418190587263600148770280649306958101930"),
                MontFp!("4082367875863433681332203403145435568316851327593401208105741076214120093531"),

            )
        ),
        gamma2: G2Affine::new(
            Fq2::new(
                MontFp!("10857046999023057135944570762232829481370756359578518086990519993285655852781"),

                MontFp!("11559732032986387107991004021392285783925812861821192530917403151452391805634"),
            ),
            Fq2::new(
                MontFp!("8495653923123431417604973247489272438418190587263600148770280649306958101930"),
                MontFp!("4082367875863433681332203403145435568316851327593401208105741076214120093531"),

            )
        ),
        delta2: G2Affine::new(
            Fq2::new(
                MontFp!("10857046999023057135944570762232829481370756359578518086990519993285655852781"),

                MontFp!("11559732032986387107991004021392285783925812861821192530917403151452391805634"),
            ),
            Fq2::new(
                MontFp!("8495653923123431417604973247489272438418190587263600148770280649306958101930"),
                MontFp!("4082367875863433681332203403145435568316851327593401208105741076214120093531"),

            )
        ),
        ic: vec![G1Affine::new(
            Fq::from(1),
            Fq::from(2),
        )],
    }
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
    // println!("A[0] = {:?}", A[0]);
    // println!("B[0] = {:?}", B[0]);
    // let sipp_statement = sipp_verify_native(&A, &B, &sipp_proof).unwrap();
    // let prod = inner_product(&A, &B);
    // println!("prod = {:?}", prod);

    let g1 = G1Affine::new(Fq::from(1), Fq::from(2));
    println!("g1 point loaded");
    let g2 = 
        G2Affine::new(
            Fq2::new(
                MontFp!("10857046999023057135944570762232829481370756359578518086990519993285655852781"),

                MontFp!("11559732032986387107991004021392285783925812861821192530917403151452391805634"),
            ),
            Fq2::new(
                MontFp!("8495653923123431417604973247489272438418190587263600148770280649306958101930"),
                MontFp!("4082367875863433681332203403145435568316851327593401208105741076214120093531"),

            )
        );



    println!("g1 = {:?}", g1);
    println!("g2 = {:?}", g2);



    // println!("Fr = {:?}", Fq::from("21888242871839275222246405745257275088696311157297823662689037894645226208583"));

    

    // assert!(vk.ic.len() == )



    // G1Affine::from(Affine;
    // verify_proof()
}


fn verify<F: RichField+ Extendable<D>, const D: usize>(
    input: Vec<u64>,
    proof: Proof,
) {



    let vk = get_verification_key();

    let mut vk_x = G1Affine::new(Fq::from(0), Fq::from(0));

    for i in 0..input.len() {
        //TODO
        // assert!(input[i] < )
        vk_x = vk_x.add(vk.ic[i+1].mul_bigint(&[input[i]; 1])).into_affine();

    }

    vk_x = vk_x.add(vk.ic[0]).into_affine();
    ;
    
    pairing_prod(proof.a.into_group().neg().into_affine(), proof.b, vk.alpha1, vk.beta2, vk_x, vk.gamma2, proof.c, vk.delta2);
    

    println!("vk_x = {:?}", vk_x);

}

fn pairing_prod<>(a1: G1Affine, a2: G2Affine, b1: G1Affine, b2: G2Affine, c1: G1Affine, c2: G2Affine, d1: G1Affine, d2: G2Affine) -> bool {
    // let mut res = Fq12::one();
    let mut p1: Vec<G1Affine> = Vec::new();
    let mut p2: Vec<G2Affine> = Vec::new();

    p1.push(a1);
    p1.push(b1);
    p1.push(c1);
    p1.push(d1);
    p2.push(a2);
    p2.push(b2);
    p2.push(c2);
    p2.push(d2);
    
    true
}

fn pairing_check(p1: Vec<G1Affine>, p2: Vec<G2Affine>) -> bool {
    // TODO
    let elements = p1.len();
    let input_size = elements * 6;
    // let mut input = Vec::new()[input_size];
    // for i in 0..elements {
    //     input[i * 6 + 0] = p1[i].x();

    // }

    let e1 = pairing(p1[0], p2[0]);
    let e2 = pairing(p1[1], p2[1]);

    
    true
}


// fn/


