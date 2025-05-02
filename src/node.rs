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
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
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

use crate::types::*;
use codec::{Decode, Encode};
// use crate::rpc::*;

pub struct Node<C: Pairing> {
    /// the iroh endpoint
    endpoint: Endpoint,
    /// the iroh router
    router: Router,
    /// the iroh-gossip communication layer
    gossip: Gossip,
    /// the gossip sneder
    // gossip_sender: GossipSender,
    // gossip_receiver: GossipReceiver,
    iroh_secret_key: IrohSecretKey,
    /// the bls secret key
    secret_key: SecretKey<C>,
    /// the lagrange params
    lagrange_params: LagrangePowers<C>,
    // known_hints: Option<Vec<u8>>,
}

use crate::{MyWorld, WorldServer};
use tonic::transport::Server;

impl<C: Pairing> Node<C> {
    /// start the node
    pub async fn build(params: StartNodeParams<C>) -> Self {
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
        let lagrange_params = LagrangePowers::<C>::new(params.tau, params.kzg_size);

        Node {
            endpoint,
            router,
            iroh_secret_key: params.iroh_secret_key,
            secret_key: params.secret_key,
            gossip,
            // gossip_sender: sender,
            // gossip_receiver: receiver,
            lagrange_params,
        }


        // let (sender, mut receiver) = Self::try_connect_peers(
        //     endpoint.clone(),
        //     gossip.clone(),
        //     params.topic,
        //     params.bootstrap_peers.clone(),
        // )
        // .await
        // .unwrap()
        // .split();

        // // start the RPC server
        // // n0_future::task::spawn(async move {
        //     let addr_str = format!("127.0.0.1:{}", params.rpc_port);
        //     let addr = addr_str.parse().unwrap();
        //     let world = MyWorld(node);
        //     println!("> Server listening on {}", addr);
        //     Server::builder()
        //         .add_service(WorldServer::new(world))
        //         .serve(addr)
        //         .await
        //         .unwrap();
        // // });
        // println!("asdfasdf");
        // loop {
        //     while let Ok(Some(event)) = receiver.try_next().await {
        //         if let Event::Gossip(GossipEvent::Received(msg)) = event {
        //             let announcement =
        //                 Announcement::decode(&mut msg.content.to_vec().as_slice()).unwrap();
        //             match announcement.tag {
        //                 Tag::Hint => {
        //                     let pk = PublicKey::<E>::deserialize_compressed(&announcement.data[..])
        //                         .unwrap();
        //                 }
        //                 _ => {
        //                     todo!();
        //                 }
        //             }
        //             println!("RECEIVED MESSAGE {:?}", announcement);
        //         }
        //     }
        // }
        // node.listen().await;
    }

    // // start the RPC server
    // n0_future::task::spawn(async move {
    //     let addr_str = format!("127.0.0.1:{}", params.rpc_port);
    //     let addr = addr_str.parse().unwrap();
    //     let world = MyWorld(node);
    //     println!("> Server listening on {}", addr);
    //     Server::builder()
    //         .add_service(WorldServer::new(world))
    //         .serve(addr)
    //         .await
    //         .unwrap();
    // });
    // subscribe and print loop
    // pub async fn listen(&mut self) {
    //     loop {
    //         while let Ok(Some(event)) = self.gossip_receiver.try_next().await {
    //             if let Event::Gossip(GossipEvent::Received(msg)) = event {
    //                 let announcement =
    //                     Announcement::decode(&mut msg.content.to_vec().as_slice()).unwrap();
    //                 match announcement.tag {
    //                     Tag::Hint => {
    //                         let pk = PublicKey::<E>::deserialize_compressed(&announcement.data[..])
    //                             .unwrap();
    //                     }
    //                     _ => {
    //                         todo!();
    //                     }
    //                 }
    //                 println!("RECEIVED MESSAGE {:?}", announcement);
    //             }
    //         }
    //     }
    // }

    /// join the gossip topic by connecting to known peers, if any
    pub async fn try_connect_peers(
        &mut self,
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
                    self.endpoint.add_node_addr(peer)?;
                }
                bootstrap_node_pubkeys = peer_ids;
            }
            None => {
                // do nothing
            }
        };

        let gossipsub_topic = self.gossip
            .subscribe_and_join(topic, bootstrap_node_pubkeys)
            .await?;

        println!("> Connection established.");

        Ok(gossipsub_topic)
    }

    pub(crate) fn lagrange_get_pk(&self, i: usize, size: usize) -> PublicKey<C> {
        self.secret_key
            .lagrange_get_pk(i, &self.lagrange_params, size)
    }

    pub(crate) async fn broadcast(&self, msg: bytes::Bytes) {
        println!(":adsfadfasdf");
        // self.gossip_sender.broadcast(msg).await.unwrap();
    }

    pub async fn addr(&self) -> Result<NodeAddr> {
        self.router.endpoint().node_addr().await
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        self.router.shutdown().await?;
        Ok(())
    }
}
