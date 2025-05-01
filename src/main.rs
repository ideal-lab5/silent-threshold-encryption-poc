mod node;
// mod rpc;

use crate::node::{Node, StartNodeParams};
use anyhow::Result;
use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_std::{
    rand::{rngs::OsRng, thread_rng},
    UniformRand, Zero,
};
use clap::{Parser, Subcommand};
use core::net::SocketAddr;
use core::str::FromStr;
use futures::{future, prelude::*};
use iroh::{NodeAddr, NodeId, PublicKey as IrohPublicKey, RelayUrl, SecretKey as IrohSecretKey};
use iroh_gossip::proto::TopicId;
use n0_future::{time, time::Duration};
use rand::distr::Uniform;
use silent_threshold_encryption::{
    decryption::agg_dec,
    encryption::encrypt,
    kzg::KZG10,
    setup::{AggregateKey, LagrangePowers, PublicKey, SecretKey},
};
use std::net::{IpAddr, Ipv6Addr};
use tarpc::{
    client, context,
    server::{self, Channel as _},
    tokio_serde::formats::Json,
};

use tarpc::server::incoming::Incoming;

use serde::Deserialize;

type E = ark_bls12_381::Bls12_381;
type G2 = <E as Pairing>::G2;
type Fr = <E as Pairing>::ScalarField;
type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;

// https://hackmd.io/3968Gr5hSSmef-nptg2GRw
// https://hackmd.io/xqYBrigYQwyKM_0Sn5Xf4w
// https://eprint.iacr.org/2024/263.pdf

// use tonic::{transport::Server, Request, Response, Status};

// pub mod hello {
//     tonic::include_proto!("hello");
// }
// use hello::world_server::{World, WorldServer};
// use hello::{HelloReply, HelloRequest};

// #[derive(Default)]
// pub struct MyWorld {

// }

// #[tonic::async_trait]
// impl World for MyWorld {
//     async fn hello(&self, request: Request<HelloRequest>) -> Result<Response<HelloReply>, Status> {
//         let name = request.into_inner().name;

//         // publish to gossipsub topic

//         let reply = HelloReply {
//             message: format!("Hello, {name}!"),
//         };
//         Ok(Response::new(reply))
//     }
// }

#[derive(Parser, Debug)]
#[command(name = "STE", version = "1.0")]
struct Cli {
    /// Port to bind for incoming connections
    #[arg(long)]
    bind_port: u16,

    /// Port for the RPC interface
    #[arg(long)]
    rpc_port: u16,

    #[command(subcommand)]
    command: Option<Commands>,
}

/// Define available subcommands
#[derive(Subcommand, Debug)]
enum Commands {
    /// Add a new item
    Bootstrap {
        bootstrap_pubkey: String,
        bootstrap_ip: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();
    // println!("ARGS: {:?}", args);
    // let n = 3;
    // println!("Setting up KZG parameters");
    // let tau = Fr::rand(&mut OsRng);
    // let kzg_params = KZG10::<E, UniPoly381>::setup(n, tau.clone()).unwrap();

    // println!("Preprocessing lagrange powers");
    // let lagrange_params = LagrangePowers::<E>::new(tau, n);

    let topic = TopicId::from_bytes(*b"silent-threshold-encryption-test");

    // build bootstrap nodeaddr if provide
    // TODO: for now assumes if bootstrap node id provided then all are
    let mut bootstrap: Option<Vec<NodeAddr>> = None;
    let mut bootstrap_addrs: Vec<NodeAddr> = Vec::new();

    match &args.command {
        Some(Commands::Bootstrap {
            bootstrap_pubkey,
            bootstrap_ip,
        }) => {
            let pubkey = IrohPublicKey::from_str(&bootstrap_pubkey).unwrap();
            let socket: SocketAddr = bootstrap_ip.parse().unwrap();
            bootstrap_addrs.push(NodeAddr::from((pubkey, None, vec![socket].as_slice())));
        }
        None => {
            // do nothing
        }
    }

    if bootstrap_addrs.len() > 0 {
        bootstrap = Some(bootstrap_addrs);
    }
    
    // run the node
    let _ = Node::run(StartNodeParams::<E>::rand(topic, args.bind_port, args.rpc_port, bootstrap)).await;

    Ok(())
}
