use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{floor_planner::V1, Layouter, Region, Value},
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
        offset: usize,
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
            let x = meta.query_advice(x, Rotation(offset as i32));
            let y = meta.query_advice(y, Rotation(offset as i32));

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

#[derive(Debug, Clone)]
pub struct ECPointsAddConfig {
    pub x: Column<Advice>,
    pub y: Column<Advice>,

    pub q_add_enable: Selector,
    pub q_valid_check_enable: Column<Fixed>,
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
        let q_add_enable = meta.selector();
        let q_valid_check_enable = meta.fixed_column();

        let valid_0 = ValidECPointChip::configure(
            meta,
            |meta| meta.query_fixed(q_valid_check_enable, Rotation(0)),
            x,
            y,
            0,
        );
        let valid_1 = ValidECPointChip::configure(
            meta,
            |meta| meta.query_fixed(q_valid_check_enable, Rotation(1)),
            x,
            y,
            1,
        );
        let valid_2 = ValidECPointChip::configure(
            meta,
            |meta| meta.query_fixed(q_valid_check_enable, Rotation(2)),
            x,
            y,
            2,
        );

        meta.create_gate("P(x, y) + Q(x, y) = R(x, y)", |meta| {
            //
            //   q_add_enable  |  q_valid_check_enable |   x   |   y   |   offset   |
            //  ---------------------------------------------------------------------
            //        1        |         1             |  p_x  |  p_y  |     0      |
            //        0        |         1             |  q_x  |  q_y  |     1      |
            //        0        |         1             |  r_x  |  r_y  |     2      |
            //

            let q_add_enable = meta.query_selector(q_add_enable);

            let q_valid_check_enable_0 = meta.query_fixed(q_valid_check_enable, Rotation(0));
            let q_valid_check_enable_1 = meta.query_fixed(q_valid_check_enable, Rotation(1));
            let q_valid_check_enable_2 = meta.query_fixed(q_valid_check_enable, Rotation(2));

            let p_x = meta.query_advice(x, Rotation(0));
            let p_y = meta.query_advice(y, Rotation(0));
            let q_x = meta.query_advice(x, Rotation(1));
            let q_y = meta.query_advice(y, Rotation(1));
            let r_x = meta.query_advice(x, Rotation(2));
            let r_y = meta.query_advice(y, Rotation(2));

            // EC point add formula: https://trustica.cz/en/2018/03/15/elliptic-curves-point-addition/
            //      d = (q_y - p_y) / (q_x - p_x)
            //      r_x = d^2 - p_x - q_x
            //      r_y = -p_y - d(r_x - p_x)

            // Derived version: https://zcash.github.io/halo2/design/gadgets/ecc/addition.html#incomplete-addition
            //      q_add_enable * ((r_x + q_x + p_x) * (p_x - q_x) ^ 2 - (p_y - q_y)^2) = 0
            //      q_add_enable * ((r_y + q_y)*(p_x - q_x) - (p_y - q_y)*(q_x - r_x)) = 0
            vec![
                q_valid_check_enable_0 * valid_0.is_valid_expr,
                q_valid_check_enable_1 * valid_1.is_valid_expr,
                q_valid_check_enable_2 * valid_2.is_valid_expr,
                q_add_enable.clone()
                    * ((r_x.clone() + q_x.clone() + p_x.clone())
                        * (p_x.clone() - q_x.clone()).square()
                        - (p_y.clone() - q_y.clone()).square()),
                q_add_enable
                    * ((r_y + q_y.clone()) * (p_x - q_x.clone()) - (p_y - q_y) * (q_x - r_x)),
            ]
        });

        ECPointsAddConfig {
            x,
            y,
            q_add_enable,
            q_valid_check_enable,
        }
    }

    pub fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        p_x: Value<F>,
        p_y: Value<F>,
        q_x: Value<F>,
        q_y: Value<F>,
        r_x: Value<F>,
        r_y: Value<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "Assign points",
            |mut region| {
                self.config.q_add_enable.enable(&mut region, 0)?;

                region.assign_advice(|| "p_x", self.config.x, 0, || p_x)?;
                region.assign_advice(|| "p_y", self.config.y, 0, || p_y)?;
                region.assign_fixed(
                    || "check if P(x, y) is valid EC point",
                    self.config.q_valid_check_enable,
                    0,
                    || Value::known(F::one()),
                )?;

                region.assign_advice(|| "q_x", self.config.x, 1, || q_x)?;
                region.assign_advice(|| "q_y", self.config.y, 1, || q_y)?;
                region.assign_fixed(
                    || "check if Q(x, y) is valid EC point",
                    self.config.q_valid_check_enable,
                    1,
                    || Value::known(F::one()),
                )?;

                region.assign_advice(|| "r_x", self.config.x, 2, || r_x)?;
                region.assign_advice(|| "r_y", self.config.y, 2, || r_y)?;
                region.assign_fixed(
                    || "check if R(x, y) is valid EC point",
                    self.config.q_valid_check_enable,
                    2,
                    || Value::known(F::one()),
                )?;

                Ok(())
            },
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct TestCircuit<F: FieldExt> {
    pub p_x: Value<F>,
    pub p_y: Value<F>,
    pub q_x: Value<F>,
    pub q_y: Value<F>,
    pub r_x: Value<F>,
    pub r_y: Value<F>,
}

impl<F: FieldExt> Circuit<F> for TestCircuit<F> {
    type Config = ECPointsAddConfig;

    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let x = meta.advice_column();
        let y = meta.advice_column();

        ECPointsAddChip::configure(meta, x, y)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let cs = ECPointsAddChip::construct(config);

        cs.assign(
            layouter.namespace(|| "assign points"),
            self.p_x,
            self.p_y,
            self.q_x,
            self.q_y,
            self.r_x,
            self.r_y,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{dev::MockProver, pasta::Fp as F};

    #[test]
    fn test_ec_points_add() {
        let k = 4;

        let circuit = TestCircuit {
            p_x: Value::known(F::from(5)),
            p_y: Value::known(F::from(11)),
            q_x: Value::known(F::from(5)),
            q_y: Value::known(F::from(11)),
            r_x: Value::known(F::from(15)),
            r_y: Value::known(F::from(5)),
        };

        let public_input = vec![];

        let prover = MockProver::run(k, &circuit, public_input).unwrap();
        prover.assert_satisfied();
    }
}
