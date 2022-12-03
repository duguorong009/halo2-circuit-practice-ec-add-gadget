use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    plonk::*,
};

fn main() {
    println!("Hello, world!");
}

// This gadget helps to check if the given point is
// valid EC point of Pallas curve
#[derive(Debug, Clone)]
pub struct ValidECPointConfig<F> {
    pub x: Column<Advice>,
    pub y: Column<Advice>,
    pub is_valid_expr: Expression<F>,
}

pub struct ValidECPointChip<F> {
    config: ValidECPointConfig<F>,
}

impl<F: FieldExt> ValidECPointChip<F> {
    pub fn construct(config: ValidECPointConfig<F>) -> Self {
        ValidECPointChip { config }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> ValidECPointConfig<F> {
        todo!()
    }

    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        x: Value<F>,
        y: Value<F>,
        offset: usize,
    ) -> Result<(), Error> {
        todo!()
    }
}
