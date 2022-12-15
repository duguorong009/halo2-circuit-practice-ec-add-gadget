use std::marker::PhantomData;

use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{floor_planner::V1, Layouter, Region, Value},
    plonk::*,
    poly::Rotation,
};

mod is_valid_ec_point_gadget;
use is_valid_ec_point_gadget::ValidECPointChip;

fn main() {
    println!("Hello, world!");
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

        let valid_p = ValidECPointChip::configure(
            meta,
            |meta| meta.query_fixed(q_valid_check_enable, Rotation::prev()),
            x,
            y,
            -1,
        );
        let valid_q = ValidECPointChip::configure(
            meta,
            |meta| meta.query_fixed(q_valid_check_enable, Rotation::cur()),
            x,
            y,
            0,
        );
        let valid_r = ValidECPointChip::configure(
            meta,
            |meta| meta.query_fixed(q_valid_check_enable, Rotation::next()),
            x,
            y,
            1,
        );

        meta.create_gate("P(x, y) + Q(x, y) = R(x, y)", |meta| {
            //
            //   q_add_enable  |  q_valid_check_enable |   x   |   y   |   offset   |
            //  ---------------------------------------------------------------------
            //        0        |         1             |  p_x  |  p_y  |     -1     |
            //        1        |         1             |  q_x  |  q_y  |     0      |
            //        0        |         1             |  r_x  |  r_y  |     1      |
            //

            let q_add_enable = meta.query_selector(q_add_enable);

            let q_valid_check_enable_p = meta.query_fixed(q_valid_check_enable, Rotation::prev());
            let q_valid_check_enable_q = meta.query_fixed(q_valid_check_enable, Rotation::cur());
            let q_valid_check_enable_r = meta.query_fixed(q_valid_check_enable, Rotation::next());

            let p_x = meta.query_advice(x, Rotation::prev());
            let p_y = meta.query_advice(y, Rotation::prev());
            let q_x = meta.query_advice(x, Rotation::cur());
            let q_y = meta.query_advice(y, Rotation::cur());
            let r_x = meta.query_advice(x, Rotation::next());
            let r_y = meta.query_advice(y, Rotation::next());

            // EC point add formula: https://trustica.cz/en/2018/03/15/elliptic-curves-point-addition/
            //      d = (q_y - p_y) / (q_x - p_x)
            //      r_x = d^2 - p_x - q_x
            //      r_y = -p_y - d(r_x - p_x)

            // Derived version: https://zcash.github.io/halo2/design/gadgets/ecc/addition.html#incomplete-addition
            //      q_add_enable * ((r_x + q_x + p_x) * (p_x - q_x) ^ 2 - (p_y - q_y)^2) = 0
            //      q_add_enable * ((r_y + q_y)*(p_x - q_x) - (p_y - q_y)*(q_x - r_x)) = 0
            vec![
                q_valid_check_enable_p * valid_p.is_valid_expr,
                q_valid_check_enable_q * valid_q.is_valid_expr,
                q_valid_check_enable_r * valid_r.is_valid_expr,
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
                self.config.q_add_enable.enable(&mut region, 1)?;

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
    use halo2_proofs::{
        arithmetic::CurveAffine,
        dev::MockProver,
        pasta::{group::Group, pallas, EpAffine},
    };

    #[test]
    fn test_ec_points_add() {
        let k = 4;

        let generator = pallas::Point::generator();
        let generator_affine = EpAffine::from(generator);
        let double_gen_affine = EpAffine::from(generator.double());

        let x_val = generator_affine
            .coordinates()
            .map(|v| v.x().clone())
            .unwrap();
        let y_val = generator_affine
            .coordinates()
            .map(|v| v.y().clone())
            .unwrap();

        let _2x_val = double_gen_affine
            .coordinates()
            .map(|v| v.x().clone())
            .unwrap();
        let _2y_val = double_gen_affine
            .coordinates()
            .map(|v| v.y().clone())
            .unwrap();

        let circuit = TestCircuit {
            p_x: Value::known(x_val),
            p_y: Value::known(y_val),

            q_x: Value::known(x_val),
            q_y: Value::known(y_val),

            r_x: Value::known(_2x_val),
            r_y: Value::known(_2y_val),
        };

        let public_input = vec![];

        let prover = MockProver::run(k, &circuit, public_input).unwrap();
        prover.assert_satisfied();

        // Plot the circuit
        use plotters::prelude::*;
        let root = BitMapBackend::new("EC-points-add-layout.png", (1024, 1024)).into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root
            .titled("EC points add circuit test Layout", ("sans-serif", 60))
            .unwrap();
        halo2_proofs::dev::CircuitLayout::default()
            .render(k, &circuit, &root)
            .unwrap();
    }
}
