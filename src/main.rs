use anyhow::Result;
use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::rngs::OsRng, UniformRand};
use clap::{Parser, Subcommand};
use core::net::SocketAddr;
use core::str::FromStr;
use futures::prelude::*;
use iroh::{NodeAddr, PublicKey as IrohPublicKey};
use iroh_gossip::proto::TopicId;
use silent_threshold_encryption::setup::{AggregateKey, LagrangePowers, PublicKey, SecretKey};
use std::io::prelude::*;
use std::{fs, fs::OpenOptions};
use std::sync::Arc;
use tokio::sync::Mutex;

// use tarpc::{
//     client, context,
//     server::{self, Channel as _},
//     tokio_serde::formats::Json,
// };

// use tarpc::server::incoming::Incoming;

use serde::Deserialize;
use tonic::transport::Server;

mod node;
mod rpc;
mod types;

use crate::hello::world_server::WorldServer;
use crate::node::*;
use crate::rpc::*;
use crate::types::*;

type E = ark_bls12_381::Bls12_381;
type G2 = <E as Pairing>::G2;
type Fr = <E as Pairing>::ScalarField;
type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;

// https://hackmd.io/3968Gr5hSSmef-nptg2GRw
// https://hackmd.io/xqYBrigYQwyKM_0Sn5Xf4w
// https://eprint.iacr.org/2024/263.pdf

#[derive(Parser, Debug)]
#[command(name = "STE", version = "1.0")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

/// Define available subcommands
#[derive(Subcommand, Debug)]
enum Commands {
    Setup {
        /// The kzg commitment size
        #[arg(long)]
        size: usize,
        /// The outpur directory (relative path)
        #[arg(long)]
        out_dir: String,
    },
    Run {
        /// Port to bind for incoming connections
        #[arg(long)]
        bind_port: u16,
        /// Port for the RPC interface
        #[arg(long)]
        rpc_port: u16,
        /// The file containg kzg + lagrange params
        #[arg(long)]
        config_dir: String,

        #[arg(long, default_value=None)]
        bootstrap_pubkey: Option<String>,

        #[arg(long, default_value=None)]
        bootstrap_ip: Option<String>,
    },
    // Encrypt {

    // },
    // Decrypt {

    // },
}

#[derive(Debug, CanonicalDeserialize, CanonicalSerialize)]
struct Config {
    dummy: PublicKey<E>,
    tau: Fr,
}

impl Config {
    fn rand(size: usize) -> Self {
        let tau = Fr::rand(&mut OsRng);
        let sk = SecretKey::<E>::new(&mut OsRng);

        let lagrange_params = LagrangePowers::<E>::new(tau, size);

        let dummy = sk.lagrange_get_pk(0, &lagrange_params, size);
        Self { dummy, tau }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    match &args.command {
        Some(Commands::Setup { size, out_dir }) => {
            println!("Running Setup.");
            println!("> Computing tau and dummy key");

            let config = Config::rand(*size);
            let mut bytes = Vec::new();
            config.serialize_compressed(&mut bytes).unwrap();

            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(out_dir)
                .unwrap();
            write!(&mut file, "0x{}", hex::encode(bytes));
            println!("> saved to disk");
        }
        Some(Commands::Run {
            bind_port,
            rpc_port,
            config_dir,
            bootstrap_pubkey,
            bootstrap_ip,
        }) => {
            let config_hex =
                fs::read_to_string(config_dir).expect("you must provide a valid config file!");
            // TODO: could confirm is 0x
            let config_bytes = hex::decode(&config_hex[2..]).unwrap();
            let config = Config::deserialize_compressed(&config_bytes[..]).unwrap();

            let topic = TopicId::from_bytes(*b"silent-threshold-encryption-test");

            // build bootstrap nodeaddr if provided
            let mut bootstrap: Option<Vec<NodeAddr>> = None;
            let mut bootstrap_addrs: Vec<NodeAddr> = Vec::new();
            if let Some(pubkey) = bootstrap_pubkey {
                if let Some(ip) = bootstrap_ip {
                    let pubkey = IrohPublicKey::from_str(&pubkey).unwrap();
                    let socket: SocketAddr = ip.parse().unwrap();
                    bootstrap_addrs.push(NodeAddr::from((pubkey, None, vec![socket].as_slice())));

                    if bootstrap_addrs.len() > 0 {
                        bootstrap = Some(bootstrap_addrs);
                    }
                }
            }

            // build the node
            // let mut node = 
            Node::build(StartNodeParams::<E>::rand(
                topic,
                *bind_port,
                *rpc_port,
                config.tau,
                config.dummy,
                3,
                bootstrap,
            ))
            .await;

            // imposes a perpetual lock 
            // node.listen().await;

            // // setup the RPC server
            // let shared_node = Arc::new(Mutex::new(node));
            // let addr_str = format!("127.0.0.1:{}", rpc_port);
            // let addr = addr_str.parse().unwrap();
            // let world = MyWorld(shared_node.clone());
            // // Spawn gRPC server in a separate task
            // let server_handle = n0_future::task::spawn(async move {
            //     Server::builder()
            //         .add_service(WorldServer::new(world))
            //         .serve(addr)
            //         .await
            //         .unwrap()
            // });

            // let listener_handler = n0_future::task::spawn(async move {
            //     loop {
            //         let mut node = shared_node.lock().await;
            //         node.process_available_events().await;
            //     }
            // });

            // server_handle.await;

            // println!("> Server listening on {}", addr);
            // tokio::try_join!(server_handle, listener_handler).unwrap();
        }
        None => {
            // do nothing
        }
    }

    Ok(())
}
