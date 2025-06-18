use ark_ec::{
    CurveConfig,
    twisted_edwards::{Affine, MontCurveConfig, TECurveConfig},
};
use ark_ed_on_bn254::{Fq, Fr};
use ark_ff::MontFp;

#[derive(Clone, Default, PartialEq, Eq)]
pub struct EdwardsConfig;

impl CurveConfig for EdwardsConfig {
    type BaseField = Fq;
    type ScalarField = Fr;

    /// COFACTOR = 8
    const COFACTOR: &'static [u64] = &[8];

    /// COFACTOR^(-1) mod r =
    /// 2394026564107420727433200628387514462817212225638746351800188703329891451411
    const COFACTOR_INV: Fr =
        MontFp!("2394026564107420727433200628387514462817212225638746351800188703329891451411");
}

impl TECurveConfig for EdwardsConfig {
    const COEFF_A: Fq = MontFp!("168700");

    const COEFF_D: Fq = MontFp!("168696");

    /// AFFINE_GENERATOR_COEFFS = (GENERATOR_X, GENERATOR_Y)
    const GENERATOR: Affine<EdwardsConfig> =
        Affine::<EdwardsConfig>::new_unchecked(GENERATOR_X, GENERATOR_Y);

    type MontCurveConfig = EdwardsConfig;
}

impl MontCurveConfig for EdwardsConfig {
    /// COEFF_A = 168698
    const COEFF_A: Fq = MontFp!("168700");
    /// COEFF_B = 168700
    const COEFF_B: Fq = MontFp!("168696");

    type TECurveConfig = EdwardsConfig;
}

pub const GENERATOR_X: Fq =
    MontFp!("5299619240641551281634865583518297030282874472190772894086521144482721001553");

pub const GENERATOR_Y: Fq =
    MontFp!("16950150798460657717958625567821834550301663161624707787222815936182638968203");

pub fn generator() -> Affine<EdwardsConfig> {
    Affine::<EdwardsConfig>::new_unchecked(GENERATOR_X, GENERATOR_Y)
}
