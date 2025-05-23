use anyhow::Result;
use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use clap::{Parser, Subcommand};
use codec::{Decode, Encode};
use core::net::SocketAddr;
use core::str::FromStr;
use futures::prelude::*;
use hello::{world_client::WorldClient, world_server::WorldServer, PartDecRequest};
use iroh::{NodeAddr, PublicKey as IrohPublicKey};
use iroh_docs::{
    engine::LiveEvent,
    rpc::{
        client::docs::{Doc, ShareMode},
        proto::{Request, Response},
    },
    store::{FlatQuery, QueryBuilder},
    DocTicket,
};
use quic_rpc::transport::flume::FlumeConnector;
use silent_threshold_encryption::{
    decryption::agg_dec,
    encryption::encrypt,
    kzg::KZG10,
    setup::{AggregateKey, LagrangePowers, PublicKey, SecretKey},
};
use std::io::prelude::*;
use std::sync::Arc;
use std::{fs, fs::OpenOptions, thread, time::Duration};
use tokio::sync::Mutex;
use tonic::transport::Server;

mod node;
mod rpc;
mod types;

use crate::node::*;
use crate::rpc::*;
use crate::types::*;

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
type E = ark_bls12_381::Bls12_381;
type G2 = <E as Pairing>::G2;
type Fr = <E as Pairing>::ScalarField;
type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;

// https://hackmd.io/3968Gr5hSSmef-nptg2GRw
// https://hackmd.io/xqYBrigYQwyKM_0Sn5Xf4w
// https://eprint.iacr.org/2024/263.pdf

// hardcoded and arbitrary for now...
const MAX_COMMITTEE_SIZE: usize = 12;

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
        /// The output directory (relative path)
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

        #[arg(long)]
        index: usize,

        #[arg(long)]
        is_bootstrap: bool,

        #[arg(long, default_value = "")]
        ticket: String,

        #[arg(long, default_value=None)]
        bootstrap_pubkey: Option<String>,

        #[arg(long, default_value=None)]
        bootstrap_ip: Option<String>,
    },
    Encrypt {
        #[arg(long)]
        message: String,
        #[arg(long)]
        preprocess_dir: String,
        #[arg(long)]
        kzg_params_dir: String,
    },
    Decrypt {
        #[arg(long)]
        ciphertext_dir: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    match &args.command {
        Some(Commands::Setup { size, out_dir }) => {
            // TODO: keygen
            println!("> Nothing happened");
        }
        Some(Commands::Encrypt {
            message,
            preprocess_dir,
            kzg_params_dir,
        }) => {
            println!("> (1/2) Running encryption using AES_GCM");
            // keygen
            let key = Aes256Gcm::generate_key(OsRng);
            // encryption
            let cipher = Aes256Gcm::new(&key);
            // 96-bits, unique per message
            let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
            let ciphertext: Vec<u8> = cipher.encrypt(&nonce, message.as_bytes()).unwrap();

            println!("> (2/2) Running threshold encryption");
            // read aggregate key from preprocess_dir (no hex - should make consistent...)
            let aggr_hex = fs::read_to_string(preprocess_dir)
                .expect("you must provide a valid encryption key.");
            let aggr_bytes = hex::decode(&aggr_hex[2..]).unwrap();
            let aggr = AggregateKey::<E>::deserialize_compressed(&aggr_bytes[..]).unwrap();
            // // read kzg params from a file (hex encoded)
            let kzg_hex = fs::read_to_string(kzg_params_dir)
                .expect("you must provide a valid kzg params file.");
            let kzg_bytes = hex::decode(&kzg_hex[2..]).unwrap();
            let config = Config::<E>::deserialize_compressed(&kzg_bytes[..]).unwrap();

            let kzg_params = KZG10::<E, UniPoly381>::setup(config.size, config.tau).unwrap();
            // encryption
            let key_ciphertext = encrypt::<E>(&aggr, MAX_COMMITTEE_SIZE - 1, &kzg_params);
            let mut ciphertext_bytes = Vec::new();
            key_ciphertext
                .serialize_compressed(&mut ciphertext_bytes)
                .unwrap();

            let bundle = CiphertextBundle {
                message_ciphertext: ciphertext,
                key_ciphertext: ciphertext_bytes,
            };

            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open("ciphertext.txt")
                .unwrap();

            let _ = write!(&mut file, "0x{}", hex::encode(bundle.encode())).unwrap();
            println!("> saved ciphertext to disk");
        }
        Some(Commands::Decrypt { ciphertext_dir }) => {
            let mut partial_decryptions = Vec::new();

            // read aggregate key from preprocess_dir
            let ciphertext_hex = fs::read_to_string(ciphertext_dir)
                .expect("you must provide a valid encryption key.");
            // then get partial decryptions for the key_ct (hardcoded for now)
            let request = tonic::Request::new(PartDecRequest { ciphertext_hex });
            let mut client = WorldClient::connect("http://127.0.0.1:30333")
                .await
                .unwrap();
            let response = client.partdec(request).await.unwrap();
            let part_dec_0 = response.into_inner().hex_serialized_decryption
            partial_decryptions.push(part_dec_0);

            // get a part dec from the second node
            let mut client = WorldClient::connect("http://127.0.0.1:30334")
                .await
                .unwrap();
            let response = client.partdec(request).await.unwrap();
            let part_dec_1 = response.into_inner().hex_serialized_decryption
            partial_decryptions.push(part_dec_1);
            println!("> Collected enough partial decryptions, attempting to decrypt the ciphertext");

            // extract the key ciphertext
            // get the kzg params
            // get the selector
            // then combine and decrypt!
            let dec_key = agg_dec(&partial_decryptions, &ct, &selector, &agg_key, &kzg_params);
            // then use it to recover the plaintext (AES GCM decryption)
        }
        Some(Commands::Run {
            bind_port,
            rpc_port,
            index,
            bootstrap_pubkey,
            bootstrap_ip,
            is_bootstrap,
            ticket,
        }) => {
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

            // a channel for sending and receiving doc announcements
            let (tx, rx) = flume::unbounded();
            let params =
                StartNodeParams::<E>::rand(*bind_port, *rpc_port, index.clone(), bootstrap.clone());
            // a state for storing config and hints
            let mut state = State::<E>::empty(params.secret_key.clone());
            let arc_state = Arc::new(Mutex::new(state));
            let arc_state_clone = Arc::clone(&arc_state.clone());
            // build the node
            let mut node = Node::build(params, rx, arc_state).await;
            node.try_connect_peers(bootstrap).await.unwrap();

            // get the document stream
            let doc_stream = if *is_bootstrap {
                // if you are a bootstrap node then you must generate the kzg params
                // and build the initial 'ticket'
                println!("Initial Startup: Running KZG param generation");
                let config_bytes: Vec<u8> = kzg_setup(MAX_COMMITTEE_SIZE);

                let doc = node.docs().create().await.unwrap();
                let ticket = doc
                    .share(
                        ShareMode::Write,
                        iroh_docs::rpc::AddrInfoOptions::RelayAndAddresses,
                    )
                    .await
                    .unwrap();
                println!("Entry ticket: {}", ticket.to_string());
                // load the doc
                let doc_stream = node.docs().import(ticket.clone()).await.unwrap();

                let kzg_config_announcement = Announcement {
                    tag: Tag::Config,
                    data: config_bytes,
                };
                // send yourself the config
                // tx.send(kzg_config_announcement.clone()).unwrap();
                let _ = doc_stream
                    .set_bytes(
                        node.docs().authors().default().await.unwrap(),
                        KZG_CONFIG_KEY,
                        kzg_config_announcement.encode(),
                    )
                    .await
                    .unwrap();
                doc_stream
            } else {
                let ticket = DocTicket::from_str(&ticket).unwrap();
                // load the doc
                node.docs().import(ticket.clone()).await.unwrap()
            };

            // start the state sync loop
            n0_future::task::spawn(run_state_sync(doc_stream.clone(), node.clone(), tx.clone()));
            // wait a few secs for the doc to sync
            thread::sleep(Duration::from_secs(3));

            let kzg_query = QueryBuilder::<FlatQuery>::default()
                .key_exact(KZG_CONFIG_KEY)
                .limit(1);
            // there must be a better way to do this, but I want to ignore author for now
            let kzg_entry = doc_stream.get_many(kzg_query.build()).await.unwrap();
            let kzg = kzg_entry.collect::<Vec<_>>().await;
            let hash = kzg[0].as_ref().unwrap().content_hash();
            let mut content = node.blobs().read_to_bytes(hash).await.unwrap();
            // try to decode an announcement
            let a = Announcement::decode(&mut content.slice(..).to_vec().as_slice()).unwrap();
            // send it
            tx.send(a).unwrap();
            // now load all previously published hints
            // for now we can do this really simply by just looking at all indices less than our
            for i in 0..(*index) as u32 {
                // get the entry and extract the announcement
                let hint_query = QueryBuilder::<FlatQuery>::default()
                    .key_exact(i.to_string())
                    .limit(1);
                let entry_list = doc_stream.get_many(hint_query.build()).await.unwrap();
                let entry = entry_list.collect::<Vec<_>>().await;
                let hash = entry[0].as_ref().unwrap().content_hash();
                let mut content = node.blobs().read_to_bytes(hash).await.unwrap();
                let announcement =
                    Announcement::decode(&mut content.slice(..).to_vec().as_slice()).unwrap();
                tx.send(announcement).unwrap();
            }

            thread::sleep(Duration::from_secs(1));
            // write your pubkey and hint and index
            let pk = node
                .lagrange_get_pk(*index, MAX_COMMITTEE_SIZE)
                .await
                .unwrap();
            println!("Computed the hint");
            let mut pk_bytes = Vec::new();
            pk.serialize_compressed(&mut pk_bytes).unwrap();
            let hint_announcement = Announcement {
                tag: Tag::Hint,
                data: pk_bytes,
            };
            // finally send the hint
            let _ = doc_stream
                .set_bytes(
                    node.docs().authors().default().await.unwrap(),
                    index.to_string(),
                    hint_announcement.encode(),
                )
                .await
                .unwrap();
            // send yourself your hitn
            tx.send(hint_announcement).unwrap();
            // setup the RPC server
            let addr_str = format!("127.0.0.1:{}", rpc_port);
            let addr = addr_str.parse().unwrap();
            let world = MyWorld {
                state: arc_state_clone,
            };
            // the handle to run the RPC server, runs forever
            n0_future::task::spawn(async move {
                Server::builder()
                    .add_service(WorldServer::new(world))
                    .serve(addr)
                    .await
                    .unwrap()
            });

            println!("> RPC listening on {}", addr);

            loop {}
        }
        None => {
            // do nothing
        }
    }

    Ok(())
}

async fn run_state_sync<C: Pairing>(
    doc_stream: Doc<FlumeConnector<Response, Request>>,
    node: Node<C>,
    tx: flume::Sender<Announcement>,
) {
    // sync the doc with peers? we need to read the state of the doc and load it
    doc_stream.start_sync(vec![]).await.unwrap();

    // subscribe to changes to the doc
    let mut sub = doc_stream.subscribe().await.unwrap();
    let blobs = node.blobs().clone();

    while let Ok(event) = sub.try_next().await {
        if let Some(evt) = event {
            println!("{:?}", evt);
            if let LiveEvent::InsertRemote { from, entry, .. } = evt {
                let msg_body = blobs.read_to_bytes(entry.content_hash()).await;
                match msg_body {
                    Ok(msg) => {
                        let bytes = msg.to_vec();
                        let announcement = Announcement::decode(&mut &bytes[..]).unwrap();
                        tx.send(announcement).unwrap();
                    }
                    Err(e) => {
                        println!("{:?}", e);
                        // may still be syncing so try again (3x)
                        for _ in 0..3 {
                            thread::sleep(Duration::from_secs(1));
                            let message_content = blobs.read_to_bytes(entry.content_hash()).await;
                            if let Ok(msg) = message_content {
                                let bytes = msg.to_vec();
                                let announcement = Announcement::decode(&mut &bytes[..]).unwrap();
                                tx.send(announcement).unwrap();
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}

fn kzg_setup(size: usize) -> Vec<u8> {
    let config = Config::<E>::rand(size);
    let mut bytes = Vec::new();
    config.serialize_compressed(&mut bytes).unwrap();
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("kzg.txt")
        .unwrap();
    let _ = write!(&mut file, "0x{}", hex::encode(bytes.clone())).unwrap();
    println!("> saved to disk");
    bytes
}
