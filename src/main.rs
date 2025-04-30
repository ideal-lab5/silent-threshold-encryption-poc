mod node;
use crate::node::{Node, StartNodeParams};
use anyhow::Result;
use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_std::{rand::rngs::OsRng, UniformRand, Zero};
use clap::{Parser, Subcommand};
use core::net::SocketAddr;
use core::str::FromStr;
use iroh::{NodeAddr, NodeId, PublicKey as IrohPublicKey, RelayUrl, SecretKey as IrohSecretKey};
use iroh_gossip::proto::TopicId;
use silent_threshold_encryption::{
    decryption::agg_dec,
    encryption::encrypt,
    kzg::KZG10,
    setup::{AggregateKey, LagrangePowers, PublicKey, SecretKey},
};

type E = ark_bls12_381::Bls12_381;
type G2 = <E as Pairing>::G2;
type Fr = <E as Pairing>::ScalarField;
type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;

// https://hackmd.io/3968Gr5hSSmef-nptg2GRw
// https://hackmd.io/xqYBrigYQwyKM_0Sn5Xf4w
// https://eprint.iacr.org/2024/263.pdf

/// Chat over iroh-gossip
///
/// This broadcasts signed messages over iroh-gossip and verifies signatures
/// on received messages.
///
/// By default a new node id is created when starting the example. To reuse your identity,
/// set the `--secret-key` flag with the secret key printed on a previous invocation.
///
/// By default, the relay server run by n0 is used. To use a local relay server, run
///     cargo run --bin iroh-relay --features iroh-relay -- --dev
/// in another terminal and then set the `-d http://localhost:3340` flag on this example.
#[derive(Parser, Debug)]
#[command(name = "STE", version = "1.0")]
struct Cli {
    /// Set the bind port for our socket. By default, a random port will be used.
    // #[arg(short, long, default_value = "9944")]
    port: u16,
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

    // start the RPC server
    let (client_transport, server_transport) = tarpc::transport::channel::unbounded();
    n0_future::task::spawn(

    );

    // run the node
    // let bootstrap = bootstrap.clone();
    let _ = Node::run(StartNodeParams::<E>::rand(topic, args.port, bootstrap)).await;

    Ok(())
}
