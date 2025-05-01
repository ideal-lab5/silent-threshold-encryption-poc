use std::env;
use std::path::PathBuf;

// build.rs
fn main() -> Result<(), Box<dyn std::error::Error>> {
        // todo: kzg param gen?
            // println!("ARGS: {:?}", args);
    // let n = 3;
    // println!("Setting up KZG parameters");
    // let tau = Fr::rand(&mut OsRng);
    // let kzg_params = KZG10::<E, UniPoly381>::setup(n, tau.clone()).unwrap();

    // println!("Preprocessing lagrange powers");
    // let lagrange_params = LagrangePowers::<E>::new(tau, n);

        tonic_build::compile_protos("src/hello.proto")?;
        Ok(())
    }