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

// use pairing::G1Point;

use ark_bn254::{fr, Config, Fq, Fq12, G1Affine, G2Affine};
use ark_bn254::{Fq2, Fr, G2Projective};
// use ark_bls12_381::{Fq, Fq2, Fr, Fq12, G1Affine, G2Affine, G1Projective, G2Projective};
use ark_ff::fields::Field;

use itertools::Itertools;

use plonky2_bn254::{
    curves::{g1curve_target::G1Target, g2curve_target::G2Target},
    fields::fq12_target::Fq12Target,
};
use plonky2_bn254_pairing::final_exp_native::final_exp_native;
use plonky2_bn254_pairing::miller_loop_native::miller_loop_native;
use plonky2_bn254_pairing::pairing::{pairing, pairing_circuit};

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

fn sparse_line_function_unequal<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    Q: (&G2Target<F, D>, &G2Target<F, D>),
    P: &G1Target<F, D>,
) -> Vec<Option<Fq2Target<F, D>>> {
    let (x_1, y_1) = (&Q.0.x, &Q.0.y);
    let (x_2, y_2) = (&Q.1.x, &Q.1.y);
    let (x, y) = (&P.x, &P.y);
    let y1_minus_y2 = y_1.sub(builder, &y_2);
    let x2_minus_x1 = x_2.sub(builder, &x_1);
    let x1y2 = x_1.mul(builder, &y_2);
    let x2y1 = x_2.mul(builder, &y_1);
    let out3 = y1_minus_y2.mul_scalar(builder, &x);
    let out2 = x2_minus_x1.mul_scalar(builder, &y);
    let out5 = x1y2.sub(builder, &x2y1);

    vec![None, None, Some(out2), Some(out3), None, Some(out5)]
}

fn sparse_line_function_equal<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    Q: &G2Target<F, D>,
    P: &G1Target<F, D>,
) -> Vec<Option<Fq2Target<F, D>>> {
    let (x, y) = (&Q.x, &Q.y);
    let x_sq = x.mul(builder, &x);
    let x_cube = x_sq.mul(builder, &x);
    let three_x_cu = x_cube.mul_scalar_const(builder, &Fq::from(3));
    let y_sq = y.mul(builder, &y);
    let two_y_sq = y_sq.mul_scalar_const(builder, &Fq::from(2));
    let out0_left = three_x_cu.sub(builder, &two_y_sq);
    let out0 = out0_left.mul_w6::<XI_0>(builder);
    let x_sq_px = x_sq.mul_scalar(builder, &P.x);
    let out4 = x_sq_px.mul_scalar_const(builder, &Fq::from(-3));
    let y_py = y.mul_scalar(builder, &P.y);
    let out3 = y_py.mul_scalar_const(builder, &Fq::from(2));

    vec![Some(out0), None, None, Some(out3), Some(out4), None]
}

fn sparse_fp12_multiply<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &Fq12Target<F, D>,
    b: Vec<Option<Fq2Target<F, D>>>,
) -> Fq12Target<F, D> {
    let mut a_fp2_coeffs = Vec::with_capacity(6);
    for i in 0..6 {
        a_fp2_coeffs.push(Fq2Target {
            coeffs: [a.coeffs[i].clone(), a.coeffs[i + 6].clone()],
        });
    }
    let mut prod_2d: Vec<Option<Fq2Target<F, D>>> = vec![None; 11];
    for i in 0..6 {
        for j in 0..6 {
            prod_2d[i + j] = match (prod_2d[i + j].clone(), &a_fp2_coeffs[i], b[j].as_ref()) {
                (a, _, None) => a,
                (None, a, Some(b)) => {
                    let ab = a.mul(builder, b);
                    Some(ab)
                }
                (Some(a), b, Some(c)) => {
                    let bc = b.mul(builder, c);
                    let out = a.add(builder, &bc);
                    Some(out)
                }
            };
        }
    }
    let mut out_fp2 = Vec::with_capacity(6);
    for i in 0..6 {
        let prod = if i != 5 {
            let eval_w6 = prod_2d[i + 6].as_ref().map(|a| a.mul_w6::<XI_0>(builder));
            match (prod_2d[i].as_ref(), eval_w6) {
                (None, b) => b.unwrap(), // Our current use cases of 235 and 034 sparse multiplication always result in non-None value
                (Some(a), None) => a.clone(),
                (Some(a), Some(b)) => a.add(builder, &b),
            }
        } else {
            prod_2d[i].clone().unwrap()
        };
        out_fp2.push(prod);
    }
    let mut out_coeffs = Vec::with_capacity(12);
    for fp2_coeff in &out_fp2 {
        out_coeffs.push(fp2_coeff.coeffs[0].clone());
    }
    for fp2_coeff in &out_fp2 {
        out_coeffs.push(fp2_coeff.coeffs[1].clone());
    }

    Fq12Target {
        coeffs: out_coeffs.try_into().unwrap(),
    }
}

fn fp12_multiply_with_line_unequal<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    g: &Fq12Target<F, D>,
    Q: (&G2Target<F, D>, &G2Target<F, D>),
    P: &G1Target<F, D>,
) -> Fq12Target<F, D> {
    let line = sparse_line_function_unequal(builder, Q, P);
    sparse_fp12_multiply(builder, g, line)
}

fn fp12_multiply_with_line_equal<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    g: &Fq12Target<F, D>,
    Q: &G2Target<F, D>,
    P: &G1Target<F, D>,
) -> Fq12Target<F, D> {
    let line = sparse_line_function_equal(builder, Q, P);
    sparse_fp12_multiply(builder, g, line)
}

fn miller_loop_BN<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    Q: &G2Target<F, D>,
    P: &G1Target<F, D>,
    pseudo_binary_encoding: &[i8],
) -> Fq12Target<F, D> {
    let mut i = pseudo_binary_encoding.len() - 1;
    while pseudo_binary_encoding[i] == 0 {
        i -= 1;
    }
    let last_index = i;
    assert!(pseudo_binary_encoding[i] == 1 || pseudo_binary_encoding[i] == -1);
    let mut R = if pseudo_binary_encoding[i] == 1 {
        Q.clone()
    } else {
        Q.neg(builder)
    };
    i -= 1;

    // initialize the first line function into Fq12 point
    let sparse_f = sparse_line_function_equal(builder, &R, P);
    assert_eq!(sparse_f.len(), 6);

    let zero_fp = FqTarget::constant(builder, Fq::ZERO);
    let mut f_coeffs = Vec::with_capacity(12);
    for coeff in &sparse_f {
        if let Some(fp2_point) = coeff {
            f_coeffs.push(fp2_point.coeffs[0].clone());
        } else {
            f_coeffs.push(zero_fp.clone());
        }
    }
    for coeff in &sparse_f {
        if let Some(fp2_point) = coeff {
            f_coeffs.push(fp2_point.coeffs[1].clone());
        } else {
            f_coeffs.push(zero_fp.clone());
        }
    }

    let mut f = Fq12Target {
        coeffs: f_coeffs.try_into().unwrap(),
    };
    loop {
        print_fq_target(builder, &f.coeffs[0], "final_f".to_string());

        if i != last_index - 1 {
            let f_sq = f.mul(builder, &f);
            f = fp12_multiply_with_line_equal(builder, &f_sq, &R, P);
        }
        R = R.double(builder);

        assert!(pseudo_binary_encoding[i] <= 1 && pseudo_binary_encoding[i] >= -1);
        if pseudo_binary_encoding[i] != 0 {
            let sign_Q = if pseudo_binary_encoding[i] == 1 {
                Q.clone()
            } else {
                Q.neg(builder)
            };
            f = fp12_multiply_with_line_unequal(builder, &f, (&R, &sign_Q), P);
            R = R.add(builder, &sign_Q);
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }

    // let neg_one: BigUint = Fq::from(-1).into();
    // let k = neg_one / BigUint::from(6u32);
    // let expected_c = Fq2::new(Fq::from(9), Fq::one()).pow(k.to_u64_digits());
    // let c2 = expected_c * expected_c;
    // let c3 = c2 * expected_c;
    // let c2 = Fq2Target::constant(builder, c2);
    // let c3 = Fq2Target::constant(builder, c3);

    // let Q_1 = twisted_frobenius(builder, Q, c2.clone(), c3.clone());
    // let neg_Q_2 = neg_twisted_frobenius(builder, &Q_1, c2.clone(), c3.clone());
    // f = fp12_multiply_with_line_unequal(builder, &f, (&R, &Q_1), P);
    // R = R.add(builder, &Q_1);
    // f = fp12_multiply_with_line_unequal(builder, &f, (&R, &neg_Q_2), P);

    // print_fq_target(builder, &f.coeffs[0], "final_f".to_string());

    f
}

fn multi_miller_loop_BN<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    pairs: Vec<(&G1Target<F, D>, &G2Target<F, D>)>,
    pseudo_binary_encoding: &[i8],
) -> Fq12Target<F, D> {
    let mut i = pseudo_binary_encoding.len() - 1;
    while pseudo_binary_encoding[i] == 0 {
        i -= 1;
    }
    let last_index = i;
    assert_eq!(pseudo_binary_encoding[last_index], 1);

    let neg_b: Vec<G2Target<F, D>> = pairs.iter().map(|pair| pair.1.neg(builder)).collect();

    // initialize the first line function into Fq12 point
    let mut f = {
        let sparse_f = sparse_line_function_equal(builder, pairs[0].1, pairs[0].0);
        assert_eq!(sparse_f.len(), 6);

        let zero_fp = FqTarget::constant(builder, Fq::ZERO);
        let mut f_coeffs = Vec::with_capacity(12);
        for coeff in &sparse_f {
            if let Some(fp2_point) = coeff {
                f_coeffs.push(fp2_point.coeffs[0].clone());
            } else {
                f_coeffs.push(zero_fp.clone());
            }
        }
        for coeff in &sparse_f {
            if let Some(fp2_point) = coeff {
                f_coeffs.push(fp2_point.coeffs[1].clone());
            } else {
                f_coeffs.push(zero_fp.clone());
            }
        }
        Fq12Target {
            coeffs: f_coeffs.try_into().unwrap(),
        }
    };

    for &(a, b) in pairs.iter().skip(1) {
        f = fp12_multiply_with_line_equal(builder, &f, b, a);
    }

    i -= 1;
    let mut r = pairs.iter().map(|pair| pair.1.clone()).collect::<Vec<_>>();
    loop {
        if i != last_index - 1 {
            f = f.mul(builder, &f);
            for (r, &(a, _)) in r.iter().zip(pairs.iter()) {
                f = fp12_multiply_with_line_equal(builder, &f, r, a);
            }
        }
        for r in r.iter_mut() {
            *r = r.double(builder);
        }

        assert!(pseudo_binary_encoding[i] <= 1 && pseudo_binary_encoding[i] >= -1);
        if pseudo_binary_encoding[i] != 0 {
            for ((r, neg_b), &(a, b)) in r.iter_mut().zip(neg_b.iter()).zip(pairs.iter()) {
                let sign_b = if pseudo_binary_encoding[i] == 1 {
                    b
                } else {
                    neg_b
                };
                f = fp12_multiply_with_line_unequal(builder, &f, (r, sign_b), a);
                *r = r.add(builder, &sign_b);
            }
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }

    let neg_one: BigUint = Fq::from(-1).into();
    let k = neg_one / BigUint::from(6u32);
    let expected_c = Fq2::new(Fq::from(9), Fq::one()).pow(k.to_u64_digits());

    let c2 = expected_c * expected_c;
    let c3 = c2 * expected_c;
    let c2 = Fq2Target::constant(builder, c2);
    let c3 = Fq2Target::constant(builder, c3);

    // finish multiplying remaining line functions outside the loop
    for (r, &(a, b)) in r.iter_mut().zip(pairs.iter()) {
        let b_1 = twisted_frobenius(builder, &b, c2.clone(), c3.clone());
        let neg_b_2 = neg_twisted_frobenius(builder, &b_1, c2.clone(), c3.clone());
        f = fp12_multiply_with_line_unequal(builder, &f, (r, &b_1), a);
        // *r = (r.clone() + b_1).into();
        *r = r.add(builder, &b_1);
        f = fp12_multiply_with_line_unequal(builder, &f, (r, &neg_b_2), a);
    }
    f
}

fn twisted_frobenius<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    Q: &G2Target<F, D>,
    c2: Fq2Target<F, D>,
    c3: Fq2Target<F, D>,
) -> G2Target<F, D> {
    let frob_x = Q.x.conjugate(builder);
    let frob_y = Q.y.conjugate(builder);
    let out_x = c2.mul(builder, &frob_x);
    let out_y = c3.mul(builder, &frob_y);
    G2Target::new(out_x, out_y)
}

fn neg_twisted_frobenius<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    Q: &G2Target<F, D>,
    c2: Fq2Target<F, D>,
    c3: Fq2Target<F, D>,
) -> G2Target<F, D> {
    let frob_x = Q.x.conjugate(builder);
    let neg_frob_y = Q.y.neg_conjugate(builder);
    let out_x = c2.mul(builder, &frob_x);
    let out_y = c3.mul(builder, &neg_frob_y);
    G2Target::new(out_x, out_y)
}

pub fn miller_loop_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    Q: &G2Target<F, D>,
    P: &G1Target<F, D>,
) -> Fq12Target<F, D> {
    println!("printing");
    miller_loop_BN(builder, Q, P, &SIX_U_PLUS_2_NAF)
}

pub fn multi_miller_loop_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    pairs: Vec<(&G1Target<F, D>, &G2Target<F, D>)>,
) -> Fq12Target<F, D> {
    multi_miller_loop_BN(builder, pairs, &SIX_U_PLUS_2_NAF)
}

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

    // let proof_2 = Proof {
    //     a: G1Affine::new(
    //         Fq::from(MontFp!("12887163950774589848429612384269252267879103641214292968732875014481055665029")),
    //         Fq::from(MontFp!("21622722808554299809135926587843590844306004439941801858752721909447067565676")),
    //     ),
    //     b: G2Affine::new(
    //         Fq2::new(
    //             MontFp!("19252399014017622041717411504172796635144662505041726695471440307521907621323"),
    //             MontFp!("11302764088468560462334032644947221757922107890363805071604206102241252698616"),
    //         ),
    //         Fq2::new(
    //             MontFp!("226455389767104611295930017850538586277567900474601688185243021343711813551"),
    //             MontFp!("18768786825809469978354139019891648686066930676359588724933329715343055477839"),
    //         ),
    //     ),
    //     c: G1Affine::new(
    //         Fq::from(MontFp!("16716067220884575876883941674457042090348240918922797664931133638121340220774")),
    //         Fq::from(MontFp!("19465170897811434280250972276398658394224541760713812318242639282725837098749")),
    //     ),
    // };

    // let res = make_verification_circuit(&mut builder);

    let proof_target = ProofTarget {
        a: G1Target::constant(&mut builder, proof.a),
        b: G2Target::constant(&mut builder, proof.b),
        c: G1Target::constant(&mut builder, proof.c),
    };

    // println!("proof correct points");

    // let input_target =

    // println!("Normal verification without circuit started");
    // let input = vec![20];
    // let res = verify::<F, D>(input, proof_2);

    // let rng = &mut rand::thread_rng();
    // let p = G1Affine::rand(rng);
    // let q = G2Affine::rand(rng);
    // let r_expected = miller_loop_native(&q, &p);
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

    let vk_x = vk_ic[0].clone();
    // vk.ic.length would be 2

    for i in 0..num_inputs {
        // vk_x = vk_x.add(vk_ic[i+1].mul_bigint(&[input[i];1])).into_affine();
        let (x, y) = (vk_ic[i + 1].x.clone(), vk_ic[i + 1].y.clone());
        let (x_ic_mul_input) = x.mul(&mut builder, &input_target[i]);
        let (y_ic_mul_input) = y.mul(&mut builder, &input_target[i]);
        let (x_ic_mul_input_plus_x) = x_ic_mul_input.add(&mut builder, &vk_ic[i].x);
        let (y_ic_mul_input_plus_y) = y_ic_mul_input.add(&mut builder, &vk_ic[i].y);
        let temp_affine = G1Target::new(x_ic_mul_input_plus_x, y_ic_mul_input_plus_y);
        vk_x.add(&mut builder, &temp_affine);
    }
    // print all the points

    let neg_a = proof_a.neg(&mut builder);
    // print_fq_target(&mut builder, &proof_b.x, "Pairing check #1".to_string());

    let mut res1 = pairing_circuit::<F, C, D>(&mut builder, neg_a, proof_b.clone());
    let mut res2 = pairing_circuit::<F, C, D>(&mut builder, vk_alpha1.clone(), vk_beta2.clone());
    let res3 = pairing_circuit::<F, C, D>(&mut builder, vk_x, vk_gamma2.clone());
    let res4 = pairing_circuit::<F, C, D>(&mut builder, proof_c.clone(), vk_delta2.clone());

    let res1_res2 = res1.mul(&mut builder, &res2);
    let res3_res4 = res3.mul(&mut builder, &res4);
    let res = res1_res2.mul(&mut builder, &res3_res4);
    let res_expected = Fq12Target::constant(&mut builder, Fq12::one());

    println!("Completed constraint defination circuit #1");
    println!("Started constraint defination circuit #2");

    let vk_alpha1_c2 = G1Target::empty(&mut builder);
    let vk_beta2_c2 = G2Target::empty(&mut builder);
    let vk_gamma2_c2 = G2Target::empty(&mut builder);
    let vk_delta2_c2 = G2Target::empty(&mut builder);
    let vk_ic_c2 = (0..num_inputs + 1)
        .map(|_| G1Target::empty(&mut builder))
        .collect_vec();

    let input_target_c2 = (0..num_inputs)
        .map(|_| FqTarget::empty(&mut builder))
        .collect_vec();

    let proof_a_c2 = G1Target::empty(&mut builder);
    let proof_b_c2 = G2Target::empty(&mut builder);
    let proof_c_c2 = G1Target::empty(&mut builder);

    let vk_x_c2 = vk_ic_c2[0].clone();
    // vk.ic.length would be 2

    for i in 0..num_inputs {
        // vk_x = vk_x.add(vk_ic[i+1].mul_bigint(&[input[i];1])).into_affine();
        let (x, y) = (vk_ic_c2[i + 1].x.clone(), vk_ic_c2[i + 1].y.clone());
        let (x_ic_mul_input) = x.mul(&mut builder, &input_target_c2[i]);
        let (y_ic_mul_input) = y.mul(&mut builder, &input_target_c2[i]);
        let (x_ic_mul_input_plus_x) = x_ic_mul_input.add(&mut builder, &vk_ic_c2[i].x);
        let (y_ic_mul_input_plus_y) = y_ic_mul_input.add(&mut builder, &vk_ic_c2[i].y);
        let temp_affine = G1Target::new(x_ic_mul_input_plus_x, y_ic_mul_input_plus_y);
        vk_x_c2.add(&mut builder, &temp_affine);
    }
    // print all the points

    let neg_a_c2 = proof_a_c2.neg(&mut builder);
    // print_fq_target(&mut builder, &proof_b.x, "Pairing check #1".to_string());

    let mut res1_c2 = pairing_circuit::<F, C, D>(&mut builder, neg_a_c2, proof_b_c2.clone());
    let mut res2_c2 =
        pairing_circuit::<F, C, D>(&mut builder, vk_alpha1_c2.clone(), vk_beta2_c2.clone());
    let res3_c2 = pairing_circuit::<F, C, D>(&mut builder, vk_x_c2, vk_gamma2_c2.clone());
    let res4_c2 =
        pairing_circuit::<F, C, D>(&mut builder, proof_c_c2.clone(), vk_delta2_c2.clone());

    let res1_res2_c2 = res1_c2.mul(&mut builder, &res2_c2);
    let res3_res4_c2 = res3_c2.mul(&mut builder, &res4_c2);
    let res_c2 = res1_res2_c2.mul(&mut builder, &res3_res4_c2);
    let res_expected_c2 = Fq12Target::constant(&mut builder, Fq12::one());

    println!("Completed constraint defination circuit #2");

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

    vk_alpha1_c2.x.set_witness(&mut pw, vk_alpha_x);
    vk_alpha1_c2.y.set_witness(&mut pw, vk_alpha_y);

    vk_beta2_c2.x.set_witness(&mut pw, vk_beta2_x);
    vk_beta2_c2.y.set_witness(&mut pw, vk_beta2_y);

    vk_gamma2_c2.x.set_witness(&mut pw, vk_gamma_x);
    vk_gamma2_c2.y.set_witness(&mut pw, vk_gamma_y);

    vk_delta2_c2.x.set_witness(&mut pw, vk_delta2_x);
    vk_delta2_c2.y.set_witness(&mut pw, vk_delta2_y);

    vk_ic_c2[0].x.set_witness(&mut pw, vk_ic_0_x);
    vk_ic_c2[0].y.set_witness(&mut pw, vk_ic_0_y);
    vk_ic_c2[1].x.set_witness(&mut pw, vk_ic_1_x);
    vk_ic_c2[1].y.set_witness(&mut pw, vk_ic_1_y);

    // let vk_ic = (0..num_inputs).map(|_| G1Target::empty(&mut builder)).collect_vec();
    proof_a_c2.x.set_witness(&mut pw, proof_a_x);
    proof_a_c2.y.set_witness(&mut pw, proof_a_y);
    proof_b_c2.x.set_witness(&mut pw, proof_b_x);
    proof_b_c2.y.set_witness(&mut pw, proof_b_y);
    proof_c_c2.x.set_witness(&mut pw, proof_c_x);
    proof_c_c2.y.set_witness(&mut pw, proof_c_y);
    input_target_c2[0].set_witness(&mut pw, &Fq::from(20u64));

    let end_setting_witness = Instant::now();
    let elapsed_time_witness = end_setting_witness.duration_since(start_setting_witness);
    println!("Time Taken to set circuit witnesses {} seconds", elapsed_time_witness.as_secs_f64());

    println!("Witnesses set");
    println!("Started building circuit");
    let start_build_time = Instant::now();
    let data = builder.build::<C>();
    let end_build_time = Instant::now();
    let elapsed_time_build = end_build_time.duration_since(start_build_time);
    println!("Circuit built");

    println!("Time Taken to build circuit {} seconds", elapsed_time_build.as_secs_f64());
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

    // for i in 0..1 {
    //     // vk_x = vk_x.add(vk_ic[i+1].mul_bigint(&[input[i];1])).into_affine();
    //     let (x, y) = (vk_ic[i+1].x.clone(), vk_ic[i+1].y.clone());
    //     let (x_ic_mul_input) = x.mul(&input_target[i]);
    //     let (y_ic_mul_input) = y.mul(&mut builder, &input_target[i]);
    //     let (x_ic_mul_input_plus_x) = x_ic_mul_input.add(&mut builder, &vk_ic[i].x);
    //     let (y_ic_mul_input_plus_y) = y_ic_mul_input.add(&mut builder, &vk_ic[i].y);
    //     let temp_affine = G1Target::new(x_ic_mul_input_plus_x, y_ic_mul_input_plus_y);
    //     vk_x.add(&mut builder, &temp_affine);
    // }

    // for i in 0..1 {
    //     let (x,y) = (vk.ic[i + 1].x.clone(), vk.ic[i+1].y.clone());
    //     // let (x_ic_mul_input) = x.mul()
    //     // MontFp!(x, y)
    // }

    // let mut vk_x = vk.ic[0];

    // let input = vec![20];

    // for i in 0..input.len() {
    //     vk_x = vk_x.add(vk.ic[i+1].mul_bigint(&[input[i];1])).into_affine();
    // }

    // //TODO negate check
    // pairing_prod(proof.a.into_group().neg().into_affine(), proof.b, vk.alpha1, vk.beta2, vk_x, vk.gamma2, proof.c, vk.delta2)

    // let res = make_verification_circuit::<F, C, D>(&mut builder, vec![20], 20);
    // let p_t = G1Target::constant(&mut builder, p);
    // let q_t = G2Target::constant(&mut builder, q);

    // let f_t = miller_loop_circuit(&mut builder, &q_t, &p_t);
    // let output_t = pairing_circuit::<F, C, D>(&mut builder, p_t, q_t);

    // // let r_t = miller_loop_circuit(&mut builder, &q_t, &p_t);
    // let r_expected_t = Fq12Target::constant(&mut builder, r_expected.into());

    // // Fq12Target::connect(&mut builder, &r_t, &r_expected_t);

    // let pw = PartialWitness::<F>::new();
    // let data = builder.build::<C>();
    // dbg!(data.common.degree_bits());
    // let _proof = data.prove(pw).unwrap();
    // println!("proof generated");
    // println!("{}",_proof.clone().to_bytes().len());
    // // let _proof = data.prove(pw).unwrap();

    // let res1 = data.verify(_proof);
}

// fn make_verification_circuit<
//     F: RichField + Extendable<D>,
//     C: GenericConfig<D, F = F> + 'static,
//     const D: usize>
// (
//     builder: &mut CircuitBuilder<F, D>,
//     input: Vec<u64>,
//     num_inputs: usize,
// ) -> Fq12Target<F, D>
// where
//     <C as GenericConfig<D>>::Hasher: AlgebraicHasher<F>,
// {
//     let vk_alpha1 = G1Target::empty( builder);
//     let vk_beta2 = G2Target::empty( builder);
//     let vk_gamma2 = G2Target::empty( builder);
//     let vk_delta2 = G2Target::empty( builder);
//     let  vk_ic = (0..num_inputs).map(|_| G1Target::empty(builder)).collect_vec();

//     let input_target = (0..num_inputs).map(|_| FqTarget::empty(builder)).collect_vec();

//     let proof_a = G1Target::empty( builder);
//     let proof_b = G2Target::empty( builder);
//     let proof_c = G1Target::empty( builder);

//     let vk_x = vk_ic[0].clone();

//     for i in 0..num_inputs {
//         // vk_x = vk_x.add(vk_ic[i+1].mul_bigint(&[input[i];1])).into_affine();
//         let (x, y) = (vk_ic[i+1].x.clone(), vk_ic[i+1].y.clone());
//         let (x_ic_mul_input) = x.mul(builder, &input_target[i]);
//         let (y_ic_mul_input) = y.mul(builder, &input_target[i]);
//         let (x_ic_mul_input_plus_x) = x_ic_mul_input.add(builder, &vk_ic[i].x);
//         let (y_ic_mul_input_plus_y) = y_ic_mul_input.add(builder, &vk_ic[i].y);
//         let temp_affine = G1Target::new(x_ic_mul_input_plus_x, y_ic_mul_input_plus_y);
//         vk_x.add(builder, &temp_affine);
//     }

//     let neg_a = proof_a.neg(builder);
//     let mut res1 = pairing_circuit::<F, C, D>( builder, neg_a, proof_b);
//     let mut res2 = pairing_circuit::<F, C, D>( builder, vk_alpha1, vk_beta2);
//     let res3 = pairing_circuit::<F, C, D>( builder, vk_x, vk_gamma2);
//     let res4 = pairing_circuit::<F, C, D>( builder, proof_c, vk_delta2);

//     let res1_res2 = res1.mul(builder, &res2);
//     let res3_res4 = res3.mul(builder, &res4);
//     let res = res1_res2.mul(builder, &res3_res4);
//     res
//     // let one = Fq12Target::constant(builder, Fq12::one());
// }

fn verify<F: RichField + Extendable<D>, const D: usize>(input: Vec<u64>, proof: Proof) -> bool {
    let vk = get_verification_key();

    println!("loaded verification key");

    let mut vk_x = vk.ic[0];

    for i in 0..input.len() {
        //TODO
        // assert!(input[i] < )
        vk_x = vk_x
            .add(vk.ic[i + 1].mul_bigint(&[input[i]; 1]))
            .into_affine();
    }
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
    // res.c0.is_one() && res.c1.is_zero()
    true
}

// fn/
#[cfg(test)]
mod test {
    use ark_bn254::{G1Affine, G2Affine};
    use ark_std::UniformRand;
    use plonky2::field::extension::Extendable;
    use plonky2::hash::hash_types::RichField;
    use plonky2::{
        field::goldilocks_field::GoldilocksField,
        iop::witness::PartialWitness,
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            config::PoseidonGoldilocksConfig,
        },
    };
    use plonky2_bn254::{
        curves::{g1curve_target::G1Target, g2curve_target::G2Target},
        fields::fq12_target::Fq12Target,
    };

    use plonky2_bn254_pairing::{
        miller_loop_target::miller_loop_circuit,
        pairing::{pairing, pairing_circuit},
    };
    use rayon::vec;

    use plonky2_bn254_pairing::miller_loop_native::miller_loop_native;

    #[test]
    fn test_pairing_circuit() {
        type F = GoldilocksField;
        type C = PoseidonGoldilocksConfig;
        const D: usize = 2;

        let rng = &mut rand::thread_rng();
        let p = G1Affine::rand(rng);
        let q = G2Affine::rand(rng);
        let r_expected = miller_loop_native(&q, &p);
        // let output = pairing(p, q);

        let config = CircuitConfig::standard_ecc_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let p_t = G1Target::constant(&mut builder, p);
        let q_t = G2Target::constant(&mut builder, q);
        // let f_t = miller_loop_circuit(&mut builder, &q_t, &p_t);
        // let output_t = pairing_circuit::<F, C, D>(&mut builder, p_t, q_t);

        let r_t = miller_loop_circuit(&mut builder, &q_t, &p_t);
        let r_expected_t = Fq12Target::constant(&mut builder, r_expected.into());

        Fq12Target::connect(&mut builder, &r_t, &r_expected_t);

        let pw = PartialWitness::<F>::new();
        let data = builder.build::<C>();
        dbg!(data.common.degree_bits());
        let _proof = data.prove(pw);
        // let data = builder.build::<C>();
        // let mut pw = PartialWitness::<F>::new();
        // f_t.set_witness(&mut pw, &f);
        // let _proof = data.prove(pw).unwrap();
    }
}
