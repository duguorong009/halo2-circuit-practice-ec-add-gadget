use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Region, Value},
    plonk::*,
    poly::Rotation,
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

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_enable: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        x: Column<Advice>,
        y: Column<Advice>,
    ) -> ValidECPointConfig<F> {
        let mut is_valid_expr = Expression::Constant(F::zero());

        meta.create_gate("is_valid_pasta_ec_point", |meta| {
            //
            // valid | x_value |  y_value  |   y^2 = x^3 + 5   |
            // -------------------------------------------------
            //  yes  |   x     |     y     |          0        |
            //   no  |   x     |     y     |          1        |
            //

            let q_enable = q_enable(meta);
            let x = meta.query_advice(x, Rotation::cur());
            let y = meta.query_advice(y, Rotation::cur());

            is_valid_expr =
                y.square() - (x.clone() * x.square()) - Expression::Constant(F::from_u128(5));

            vec![q_enable * is_valid_expr.clone()]
        });

        ValidECPointConfig {
            x,
            y,
            is_valid_expr,
        }
    }

    pub fn assign(
        &self,
        region: &mut Region<'_, F>,
        x: Value<F>,
        y: Value<F>,
        offset: usize,
    ) -> Result<(), Error> {
        region.assign_advice(|| "Assign x", self.config.x, offset, || x)?;
        region.assign_advice(|| "Assign y", self.config.y, offset, || y)?;

        Ok(())
    }
}
