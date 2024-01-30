use plonky2::field::{goldilocks_field::GoldilocksField, types::PrimeField64};
use plonky2_bn254::{
    curves::{g1curve_target::G1Target, g2curve_target::G2Target},
    fields::fq12_target::Fq12Target,
};
use plonky2::plonk::circuit_builder::CircuitBuilder;

pub fn affine_mul_g1_target<'a>(mut g1_target: &'a mut G1Target<GoldilocksField, 2>, times: u64, builder: &'a mut CircuitBuilder<GoldilocksField, 2>) -> &'a mut G1Target<GoldilocksField, 2> {
    for _ in 0..times {
        let int_target: &'a mut G1Target<GoldilocksField, 2> = &mut(g1_target.add(builder, &g1_target));
        g1_target = int_target;
    }
    g1_target
}

pub fn affine_mul_g2_target<'a>(mut g2_target: &'a mut G2Target<GoldilocksField, 2>, times: u64, builder: &'a mut CircuitBuilder<GoldilocksField, 2>) -> &'a mut G2Target<GoldilocksField, 2> {
    for _ in 0..times {
        let int_target: &'a mut G2Target<GoldilocksField, 2> = &mut(g2_target.add(builder, &g2_target));
        g2_target = int_target;
    }
    g2_target
}
