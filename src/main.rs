use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{Layouter, Region, Value},
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

#[derive(Debug)]
pub struct ECPointsAddConfig {
    pub x: Column<Advice>,
    pub y: Column<Advice>,

    pub q_enable: Selector,
}

pub struct ECPointsAddChip<F> {
    pub config: ECPointsAddConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt> ECPointsAddChip<F> {
    pub fn construct(config: ECPointsAddConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        x: Column<Advice>,
        y: Column<Advice>,
    ) -> ECPointsAddConfig {
        let q_enable = meta.selector();

        let is_valid_ec_point =
            ValidECPointChip::configure(meta, |meta| meta.query_selector(q_enable), x, y);

        meta.create_gate("(x, y) belongs to EC?", |meta| {
            //
            //   q_add_enable  |  q_valid_check_enable |   x   |   y   |   offset   |
            //  ---------------------------------------------------------------------
            //        1        |         1             |  p_x  |  p_y  |     0      |
            //        0        |         1             |  q_x  |  q_y  |     1      |
            //        0        |         1             |  r_x  |  r_y  |     2      |
            //

            let q_enable = meta.query_selector(q_enable);

            let x = meta.query_advice(x, Rotation(0));
            let y = meta.query_advice(y, Rotation(0));

            todo!();

            // vec![q_enable * (is_valid_ec_point.is_valid_expr)]
        });

        ECPointsAddConfig { x, y, q_enable }
    }

    pub fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        x: Value<F>,
        y: Value<F>,
        offset: usize,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "Assign P point",
            |mut region| {
                // self.config.q_enable.enable(&mut region, offset)?;
                // region.assign_advice(|| "x", self.config.x, offset, || x)?;
                // region.assign_advice(|| "y", self.config.y, offset, || y)?;

                Ok(())
            },
        )
    }
}
