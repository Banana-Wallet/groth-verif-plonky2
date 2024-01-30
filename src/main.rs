use anyhow::Result;
use ark_ec::pairing::Pairing;
use ark_ec::short_weierstrass::Affine;
use ark_ec::*;
use ark_ec::{AffineRepr, CurveConfig, CurveGroup};
use ark_ff::{Fp, MontFp, QuadExtConfig};
use ark_std::str::FromStr;
use ark_std::UniformRand;
use num_bigint::{BigUint, ToBigInt};
use num_traits::{One, Zero};
use plonky2::field::extension::Extendable;
use plonky2::fri::proof;
// use plonky2::field::types::Field;
use core::num::ParseIntError;
use plonky2::field::{goldilocks_field::GoldilocksField, types::PrimeField64};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{self, BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig};
use plonky2_bn254::fields::debug_tools::{print_ark_fq, print_fq_target};
use plonky2_bn254::fields::fq2_target::Fq2Target;
use plonky2_bn254::fields::fq_target::FqTarget;
use plonky2_bn254_pairing::miller_loop_native::SIX_U_PLUS_2_NAF;
use plonky2_ecdsa::curve::curve_types::Curve;
use rayon::str;
use std::char::from_digit;
use std::fmt::Debug;
use std::ops::{Add, Neg, Sub};
use std::time::Instant;

use ark_bn254::{fr, Config, Fq, Fq12, G1Affine, G2Affine};
use ark_bn254::{Fq2, Fr, G2Projective};
use ark_ff::fields::Field;

use itertools::Itertools;

use plonky2_bn254::{
    curves::{g1curve_target::G1Target, g2curve_target::G2Target},
    fields::fq12_target::Fq12Target,
};
use plonky2_bn254_pairing::final_exp_native::final_exp_native;
use plonky2_bn254_pairing::miller_loop_native::miller_loop_native;
use plonky2_bn254_pairing::pairing::{pairing, pairing_circuit};

// pub mod utils;

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
    pub c: G1Affine,
}

pub struct ProofTarget<F: RichField + Extendable<D>, const D: usize> {
    pub a: G1Target<F, D>,
    pub b: G2Target<F, D>,
    pub c: G1Target<F, D>,
}

pub struct VerificationKeyTarget<F: RichField + Extendable<D>, const D: usize> {
    pub alpha1: G1Target<F, D>,
    pub beta2: G2Target<F, D>,
    pub gamma2: G2Target<F, D>,
    pub delta2: G2Target<F, D>,
    pub ic: Vec<G1Target<F, D>>,
}



// ! Native pairing check
fn verify<F: RichField + Extendable<D>, const D: usize>(input: Vec<u64>, proof: Proof) -> bool {
    let vk = get_verification_key();

    let mut vk_x = vk.ic[0];

    for i in 0..input.len() {
        //TODO
        vk_x = vk_x
            .add(vk.ic[i + 1].mul_bigint(&[input[i]; 1]))
            .into_affine();
    }
    println!("vk_x {:?}", vk_x);
    //TODO negate check
    pairing_prod(
        proof.a.into_group().neg().into_affine(),
        proof.b,
        vk.alpha1,
        vk.beta2,
        vk_x,
        vk.gamma2,
        proof.c,
        vk.delta2,
    )
}

fn pairing_prod(
    a1: G1Affine,
    a2: G2Affine,
    b1: G1Affine,
    b2: G2Affine,
    c1: G1Affine,
    c2: G2Affine,
    d1: G1Affine,
    d2: G2Affine,
) -> bool {
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

    pairing_check(p1, p2)
}

fn pairing_check(p1: Vec<G1Affine>, p2: Vec<G2Affine>) -> bool {
    // TODO

    let mut res = pairing(p1[0], p2[0]);
    println!("Pairing check #0 points");
    for i in 1..p1.len() {
        let temp_e = pairing(p1[i], p2[i]);
        println!("Pairing check #{} points", i);
        res = res * temp_e;
    }
    res.c0.is_one() && res.c1.is_zero()
}

fn get_verification_key() -> VerificationKey {
    VerificationKey {
        alpha1: G1Affine::new(
            Fq::from(MontFp!(
                "6763126530687886999315782887200758703366235230289874831627658839515656330867"
            )),
            Fq::from(MontFp!(
                "12297948670392550312636836114470404429657568989657927437959695771502446445179"
            )),
        ),
        beta2: G2Affine::new(
            Fq2::new(
                MontFp!(
                    "15362786867599176251482538547160991918100063526460909721657878971551583339657"
                ),
                MontFp!(
                    "3804423004921008809819632629079723167970572551072432396497601916259815496626"
                ),
            ),
            Fq2::new(
                MontFp!(
                    "21885719103633717693283841528133243510750001708857084897139570082577218850374"
                ),
                MontFp!(
                    "2076817281717432063622727433912740683541778328445173073030513609350245776784"
                ),
            ),
        ),
        gamma2: G2Affine::new(
            Fq2::new(
                MontFp!(
                    "1505558511994093266228972967760414664043255115544025409518939393775943607863"
                ),
                MontFp!(
                    "21131173266568468249589649137903719095480044620502529067534622738225157042304"
                ),
            ),
            Fq2::new(
                MontFp!(
                    "4008759115482693545406793535591568078300615151288108694080317738431649117177"
                ),
                MontFp!(
                    "18835856718271757625037377080288624550370480296914695806777038708085497610013"
                ),
            ),
        ),
        delta2: G2Affine::new(
            Fq2::new(
                MontFp!(
                    "1497911744463986566314308077983046202449361313910668647770797503379177516252"
                ),
                MontFp!(
                    "10829154948357654897792444316512827659620136273388886760324770466776134105520"
                ),
            ),
            Fq2::new(
                MontFp!(
                    "10850392992008761830625471778404650447428083833210258292805429019728339148884"
                ),
                MontFp!(
                    "12593805385728178657844996215584371401133999503150901444097670307277076679963"
                ),
            ),
        ),
        ic: vec![
            G1Affine::new(
                Fq::from(MontFp!(
                    "20417302999686518463947604254824206482787540497747166602791183033521164889663"
                )),
                Fq::from(MontFp!(
                    "13070739245581256634078674103787887995405997871287223137308760941168103411852"
                )),
            ),
            G1Affine::new(
                Fq::from(MontFp!(
                    "7134628694475811382742267026042639323743922548568185680200196927023443639137"
                )),
                Fq::from(MontFp!(
                    "9624761392337090719715532152667200620426657721236517270124636244477804835035"
                )),
            ),
        ],
    }
}

const XI_0: usize = 9;

fn main() {
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    let config = CircuitConfig::standard_ecc_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let proof = Proof {
        a: G1Affine::new(
            Fq::from(MontFp!(
                "12887163950774589848429612384269252267879103641214292968732875014481055665029"
            )),
            Fq::from(MontFp!(
                "21622722808554299809135926587843590844306004439941801858752721909447067565676"
            )),
        ),
        b: G2Affine::new(
            Fq2::new(
                MontFp!(
                    "19252399014017622041717411504172796635144662505041726695471440307521907621323"
                ),
                MontFp!(
                    "11302764088468560462334032644947221757922107890363805071604206102241252698616"
                ),
            ),
            Fq2::new(
                MontFp!(
                    "226455389767104611295930017850538586277567900474601688185243021343711813551"
                ),
                MontFp!(
                    "18768786825809469978354139019891648686066930676359588724933329715343055477839"
                ),
            ),
        ),
        c: G1Affine::new(
            Fq::from(MontFp!(
                "16716067220884575876883941674457042090348240918922797664931133638121340220774"
            )),
            Fq::from(MontFp!(
                "19465170897811434280250972276398658394224541760713812318242639282725837098749"
            )),
        ),
    };

    println!("Started to constraint defination circuit #1");
    // let output = pairing(p, q);
    // ! started building circuit
    let config = CircuitConfig::standard_ecc_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let num_inputs = 1; // ! this will be passed
                        // let inputs_builder =
                        // let num_inputs = FqTarget::empty(&mut builder);
    let vk_alpha1 = G1Target::empty(&mut builder);
    let vk_beta2 = G2Target::empty(&mut builder);
    let vk_gamma2 = G2Target::empty(&mut builder);
    let vk_delta2 = G2Target::empty(&mut builder);
    let vk_ic = (0..num_inputs + 1)
        .map(|_| G1Target::empty(&mut builder))
        .collect_vec();

    let input_target = (0..num_inputs)
        .map(|_| FqTarget::empty(&mut builder))
        .collect_vec();

    let proof_a = G1Target::empty(&mut builder);
    let proof_b = G2Target::empty(&mut builder);
    let proof_c = G1Target::empty(&mut builder);

    let mut vk_x = vk_ic[0].clone();

    for i in 0..num_inputs {
        let mut single_vk_1_affine = G1Target::new(vk_ic[i + 1].x.clone(), vk_ic[i + 1].y.clone());
        let twice_vk_1_affine = single_vk_1_affine.double(&mut builder);
        let fourth_vk_1_affine = twice_vk_1_affine.double(&mut builder);
        let eight_vk_1_affine = fourth_vk_1_affine.double(&mut builder);
        let twentith_vk_1_affine = eight_vk_1_affine
            .double(&mut builder)
            .add(&mut builder, &fourth_vk_1_affine);
        //TODO had to fix below method
        // let twentith_vk_1_affine = utils::affine_mul_g1_target(
        //     &mut single_vk_1_affine,
        //     input_target[i],
        //     &mut builder,
        // );

        vk_x = vk_x.add(&mut builder, &twentith_vk_1_affine);
    }
    let neg_a = proof_a.neg(&mut builder);

    println!("Completed constraint defination circuit #1");

    let vk = get_verification_key();

    println!("loaded verification key");
    let mut pw = PartialWitness::<F>::new();
    let (vk_alpha_x, vk_alpha_y) = vk.alpha1.xy().unwrap();
    let (vk_beta2_x, vk_beta2_y) = vk.beta2.xy().unwrap();
    let (vk_gamma_x, vk_gamma_y) = vk.gamma2.xy().unwrap();
    let (vk_delta2_x, vk_delta2_y) = vk.delta2.xy().unwrap();
    // let vk_ic_0 = vk.ic.xy().unwrap();
    let (vk_ic_0_x, vk_ic_0_y) = vk.ic[0].xy().unwrap();
    let (vk_ic_1_x, vk_ic_1_y) = vk.ic[1].xy().unwrap();

    let (proof_a_x, proof_a_y) = proof.a.xy().unwrap();
    let (proof_b_x, proof_b_y) = proof.b.xy().unwrap();
    let (proof_c_x, proof_c_y) = proof.c.xy().unwrap();

    println!("Setting witnesses");
    let start_setting_witness = Instant::now();
    vk_alpha1.x.set_witness(&mut pw, vk_alpha_x);
    vk_alpha1.y.set_witness(&mut pw, vk_alpha_y);

    vk_beta2.x.set_witness(&mut pw, vk_beta2_x);
    vk_beta2.y.set_witness(&mut pw, vk_beta2_y);

    vk_gamma2.x.set_witness(&mut pw, vk_gamma_x);
    vk_gamma2.y.set_witness(&mut pw, vk_gamma_y);

    vk_delta2.x.set_witness(&mut pw, vk_delta2_x);
    vk_delta2.y.set_witness(&mut pw, vk_delta2_y);

    vk_ic[0].x.set_witness(&mut pw, vk_ic_0_x);
    vk_ic[0].y.set_witness(&mut pw, vk_ic_0_y);
    vk_ic[1].x.set_witness(&mut pw, vk_ic_1_x);
    vk_ic[1].y.set_witness(&mut pw, vk_ic_1_y);

    // let vk_ic = (0..num_inputs).map(|_| G1Target::empty(&mut builder)).collect_vec();
    proof_a.x.set_witness(&mut pw, proof_a_x);
    proof_a.y.set_witness(&mut pw, proof_a_y);
    proof_b.x.set_witness(&mut pw, proof_b_x);
    proof_b.y.set_witness(&mut pw, proof_b_y);
    proof_c.x.set_witness(&mut pw, proof_c_x);
    proof_c.y.set_witness(&mut pw, proof_c_y);

    // num_inputs = 0;
    input_target[0].set_witness(&mut pw, &Fq::from(20u64));

    let end_setting_witness = Instant::now();
    let elapsed_time_witness = end_setting_witness.duration_since(start_setting_witness);
    println!(
        "Time Taken to set circuit witnesses {} seconds",
        elapsed_time_witness.as_secs_f64()
    );

    println!("Witnesses set");
    println!("Started building circuit");
    let start_build_time = Instant::now();
    let data = builder.build::<C>();
    let end_build_time = Instant::now();
    let elapsed_time_build = end_build_time.duration_since(start_build_time);
    println!("Circuit built");

    println!(
        "Time Taken to build circuit {} seconds",
        elapsed_time_build.as_secs_f64()
    );
    println!("Started proving....");
    // dbg!(data.common.degree_bits());
    let start_time = Instant::now();
    let _proof = data.prove(pw).unwrap();
    let end_time = Instant::now();
    println!("Proving completed...");
    println!("proof generated");
    println!("{}", _proof.clone().to_bytes().len());
    let elapsed_time = end_time.duration_since(start_time);
    println!("Time Taken {} seconds", elapsed_time.as_secs_f64());
}

