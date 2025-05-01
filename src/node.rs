//! Very basic example to showcase how to use iroh's APIs.
//!
//! This example implements a simple protocol that echos any data sent to it in the first stream.
//!
//! ## Usage
//!
//!     cargo run --example echo --features=examples

use anyhow::Result;
use iroh::{
    endpoint::Connection,
    protocol::{ProtocolHandler, Router},
    Endpoint, NodeAddr, NodeId, SecretKey as IrohSecretKey,
};
use iroh_gossip::{
    net::{Event, Gossip, GossipEvent, GossipReceiver, GossipSender, GossipTopic},
    proto::TopicId,
    ALPN as GOSSIP_ALPN,
};
use n0_future::{task, StreamExt};

use ark_ec::pairing::Pairing;
use ark_poly::univariate::DensePolynomial;
use ark_std::{rand::rngs::OsRng, UniformRand, Zero};
use silent_threshold_encryption::{
    decryption::agg_dec,
    encryption::encrypt,
    kzg::KZG10,
    setup::{AggregateKey, LagrangePowers, PublicKey, SecretKey},
};
use std::{
    collections::HashMap,
    fmt,
    net::{Ipv4Addr, SocketAddrV4},
    str::FromStr,
};

type E = ark_bls12_381::Bls12_381;
type G2 = <E as Pairing>::G2;
type Fr = <E as Pairing>::ScalarField;
type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;
use rand::{seq::IteratorRandom, thread_rng};

pub struct Node<C: Pairing> {
    endpoint: Endpoint,
    router: Router,
    // the iroh-gossip communication layer
    gossip: Gossip,
    gossip_sender: GossipSender,
    gossip_receiver: GossipReceiver,
    iroh_secret_key: IrohSecretKey,
    secret_key: SecretKey<C>,
    known_hints: Option<Vec<u8>>,
}

pub struct StartNodeParams<C: Pairing> {
    iroh_secret_key: IrohSecretKey,
    secret_key: SecretKey<C>,
    topic: TopicId,
    bind_port: u16,
    rpc_port: u16,
    bootstrap_peers: Option<Vec<NodeAddr>>,
}

impl<C: Pairing> StartNodeParams<C> {
    pub fn rand(
        topic: TopicId,
        bind_port: u16,
        rpc_port: u16,
        bootstrap_peers: Option<Vec<NodeAddr>>,
    ) -> Self {
        Self {
            iroh_secret_key: IrohSecretKey::generate(OsRng),
            secret_key: SecretKey::<C>::new(&mut OsRng),
            topic,
            bind_port,
            rpc_port,
            bootstrap_peers,
        }
    }
}

pub enum Command {
    Hint,
    Preprocess,
}

use tonic::{transport::Server, Request, Response, Status};

pub mod hello {
    tonic::include_proto!("hello");
}
use hello::world_server::{World, WorldServer};
use hello::{HelloReply, HelloRequest};

// #[derive(Default)]
pub struct MyWorld {
    sender: GossipSender,
}   

impl MyWorld {
    fn new(sender: GossipSender) -> Self {
        Self { sender }
    }
}

#[tonic::async_trait]
impl World for MyWorld {
    async fn hello(&self, request: Request<HelloRequest>) -> Result<Response<HelloReply>, Status> {
        let name = request.into_inner().name;
        let encoded = postcard::to_stdvec(&name).unwrap();
        // publish to gossipsub topic
        self.sender.broadcast(encoded.into()).await.unwrap();
        let reply = HelloReply {
            message: format!("Broadcasted message to gossipsub topic: {name}"),
        };
        Ok(Response::new(reply))
    }
}

impl<C: Pairing> Node<C> {
    /// start the node
    pub async fn run(params: StartNodeParams<C>) {
        //  -> Result<Self> {
        println!("Building the node... ");
        let endpoint = Endpoint::builder()
            .secret_key(params.iroh_secret_key.clone())
            .discovery_n0()
            .discovery_local_network()
            .bind_addr_v4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, params.bind_port))
            .bind()
            .await
            .unwrap();

        // build gossip protocol
        let gossip = Gossip::builder().spawn(endpoint.clone()).await.unwrap();
        // setup router
        let router = Router::builder(endpoint.clone())
            .accept(GOSSIP_ALPN, gossip.clone())
            .spawn()
            .await
            .unwrap();
        let addr = router.endpoint().node_addr().await;
        println!("> Generated node address: {:?}", addr);

        let (sender, mut receiver) = Self::try_connect_peers(
            endpoint.clone(),
            gossip.clone(),
            params.topic,
            params.bootstrap_peers.clone(),
        )
        .await
        .unwrap()
        .split();

        println!("The node is ready.");

        n0_future::task::spawn(async move {
            // start the RPC server
            let addr_str = format!("127.0.0.1:{}", params.rpc_port);
            let addr = addr_str.parse().unwrap();
            let world = MyWorld::new(sender);
            println!("> Server listening on {}", addr);
            Server::builder()
                .add_service(WorldServer::new(world))
                .serve(addr)
                .await
                .unwrap();
        });

        // subscribe and print loop
        loop {
            // task::spawn(subscribe_loop(receiver));
            while let Ok(Some(event)) = receiver.try_next().await {
                if let Event::Gossip(GossipEvent::Received(msg)) = event {
                    println!("RECEIVED MESSAGE {:?}", msg);
                    // let (from, message) = SignedMessage::verify_and_decode(&msg.content)?;
                    // match message {
                    //     Message::AboutMe { name } => {
                    //         names.insert(from, name.clone());
                    //         println!("> {} is now known as {}", from.fmt_short(), name);
                    //     }
                    //     Message::Message { text } => {
                    //         let name = names
                    //             .get(&from)
                    //             .map_or_else(|| from.fmt_short(), String::to_string);
                    //         println!("{}: {}", name, text);
                    //     }
                    // }
                }
            }
        }

        // Ok(Node {
        //     endpoint,
        //     router,
        //     iroh_secret_key: params.iroh_secret_key,
        //     secret_key: params.secret_key,
        //     gossip,
        //     gossip_sender: sender,
        //     gossip_receiver: receiver,
        // })
    }

    /// join the gossip topic by connecting to known peers, if any
    async fn try_connect_peers(
        endpoint: Endpoint,
        gossip: Gossip,
        topic: TopicId,
        peers: Option<Vec<NodeAddr>>,
    ) -> Result<GossipTopic> {
        let mut bootstrap_node_pubkeys = Vec::new();
        match peers {
            Some(bootstrap) => {
                let peer_ids: Vec<NodeId> = bootstrap.iter().map(|p| p.node_id).collect();
                println!("> trying to connect to {} peer(s)", bootstrap.len());
                // add the peer addrs to our endpoint's addressbook so that they can be dialed
                for peer in bootstrap.into_iter() {
                    endpoint.add_node_addr(peer)?;
                }
                bootstrap_node_pubkeys = peer_ids;
            }
            None => {
                // do nothing
            }
        };

        let gossipsub_topic = gossip
            .subscribe_and_join(topic, bootstrap_node_pubkeys)
            .await?;

        println!("> gossipsub topic subscription initiated successfully");

        Ok(gossipsub_topic)
    }

    // pub async fn publish(msg: &[u8], topic: TopicId, peer_ids) -> Result<()> {
    // let (sender, receiver) = gossip.subscribe_and_join(topic, peer_ids).await?.split();
    // println!("> connected!");

    // // broadcast our name, if set
    // if let Some(name) = args.name {
    //     let message = Message::AboutMe { name };
    //     let encoded_message = SignedMessage::sign_and_encode(endpoint.secret_key(), &message)?;
    //     sender.broadcast(encoded_message).await?;
    // }
    //     Ok(())
    // }

    pub async fn addr(&self) -> Result<NodeAddr> {
        self.router.endpoint().node_addr().await
    }

    // pub async fn send(&self, msg: &[u8]) -> Result<()> {
    //     let (sender, _) = self.gossip_topic.split().clone();
    //     sender.broadcast(postcard::from_bytes(msg).unwrap()).await?;
    //     Ok(())
    // }
    // pub async fn connect(&self, node: Node<C>) -> Result<()> {
    //     let addr = node.addr().await?;
    //     self.endpoint.connect(addr, GOSSIP_ALPN).await?;
    //     Ok(())
    // }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.router.shutdown().await?;
        Ok(())
    }
}

// async fn subscribe_loop(mut receiver: GossipReceiver) -> Result<()> {
//     // init a peerid -> name hashmap
//     // let mut names = HashMap::new();
//     while let Some(event) = receiver.try_next().await? {
//         if let Event::Gossip(GossipEvent::Received(msg)) = event {
//             println!("RECEIVED MESSAGE {:?}", msg);
//             // let (from, message) = SignedMessage::verify_and_decode(&msg.content)?;
//             // match message {
//             //     Message::AboutMe { name } => {
//             //         names.insert(from, name.clone());
//             //         println!("> {} is now known as {}", from.fmt_short(), name);
//             //     }
//             //     Message::Message { text } => {
//             //         let name = names
//             //             .get(&from)
//             //             .map_or_else(|| from.fmt_short(), String::to_string);
//             //         println!("{}: {}", name, text);
//             //     }
//             // }
//         }
//     }
//     Ok(())
// }

// #[derive(Debug, Serialize, Deserialize)]
// struct SignedMessage {
//     from: PublicKey,
//     data: Bytes,
//     signature: Signature,
// }

// impl SignedMessage {
//     pub fn verify_and_decode(bytes: &[u8]) -> Result<(PublicKey, Message)> {
//         let signed_message: Self = postcard::from_bytes(bytes)?;
//         let key: PublicKey = signed_message.from;
//         key.verify(&signed_message.data, &signed_message.signature)?;
//         let message: Message = postcard::from_bytes(&signed_message.data)?;
//         Ok((signed_message.from, message))
//     }

//     pub fn sign_and_encode(secret_key: &SecretKey, message: &Message) -> Result<Bytes> {
//         let data: Bytes = postcard::to_stdvec(&message)?.into();
//         let signature = secret_key.sign(&data);
//         let from: PublicKey = secret_key.public();
//         let signed_message = Self {
//             from,
//             data,
//             signature,
//         };
//         let encoded = postcard::to_stdvec(&signed_message)?;
//         Ok(encoded.into())
//     }
// }

// pub async fn connect_side(addr: NodeAddr) -> Result<()> {
//     let endpoint = Endpoint::builder().discovery_n0().bind().await?;
//     // Open a connection to the accepting node
//     let conn = endpoint.connect(addr, ALPN).await?;
//     // Open a bidirectional QUIC stream
//     let (mut send, mut recv) = conn.open_bi().await?;
//     // Send some data to be echoed
//     send.write_all(b"Hello, world!").await?;
//     // Signal the end of data for this particular stream
//     send.finish()?;
//     // Receive the echo, but limit reading up to maximum 1000 bytes
//     let response = recv.read_to_end(1000).await?;
//     assert_eq!(&response, b"Hello, world!");

//     // Explicitly close the whole connection.
//     conn.close(0u32.into(), b"bye!");

//     // The above call only queues a close message to be sent (see how it's not async!).
//     // We need to actually call this to make sure this message is sent out.
//     endpoint.close().await;
//     // If we don't call this, but continue using the endpoint, we then the queued
//     // close call will eventually be picked up and sent.
//     // But always try to wait for endpoint.close().await to go through before dropping
//     // the endpoint to ensure any queued messages are sent through and connections are
//     // closed gracefully.
//     Ok(())
// }

// pub async fn start_accept_side() -> Result<Router> {
//     let endpoint = Endpoint::builder().discovery_n0().bind().await?;
//     // Build our protocol handler and add our protocol,
//     // identified by its ALPN, and spawn the node.
//     let router = Router::builder(endpoint).accept(ALPN, Echo).spawn().await?;
//     Ok(router)
// }

// #[derive(Debug, Clone)]
// struct Echo;

// impl ProtocolHandler for Echo {
//     /// The `accept` method is called for each incoming connection for our ALPN.
//     ///
//     /// The returned future runs on a newly spawned tokio task, so it can run as long as
//     /// the connection lasts.
//     fn accept(&self, connection: Connection) -> BoxFuture<Result<()>> {
//         // We have to return a boxed future from the handler.
//         Box::pin(async move {
//             // We can get the remote's node id from the connection.
//             let node_id = connection.remote_node_id()?;
//             println!("accepted connection from {node_id}");

//             // Our protocol is a simple request-response protocol, so we expect the
//             // connecting peer to open a single bi-directional stream.
//             let (mut send, mut recv) = connection.accept_bi().await?;

//             // Echo any bytes received back directly.
//             // This will keep copying until the sender signals the end of data on the stream.
//             let bytes_sent = tokio::io::copy(&mut recv, &mut send).await?;
//             println!("Copied over {bytes_sent} byte(s)");

//             // By calling `finish` on the send stream we signal that we will not send anything
//             // further, which makes the receive stream on the other end terminate.
//             send.finish()?;

//             // Wait until the remote closes the connection, which it does once it
//             // received the response.
//             connection.closed().await;

//             Ok(())
//         })
//     }
// }
