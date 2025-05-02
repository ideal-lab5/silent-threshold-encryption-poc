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
use crate::node::*;

use codec::{Decode, Encode};
use tonic::{transport::Server, Request, Response, Status};

use tokio::sync::Mutex;
use std::sync::Arc;

pub mod hello {
    tonic::include_proto!("hello");
}
use hello::world_server::{World, WorldServer};
use hello::{HelloReply, HelloRequest};

pub struct MyWorld<C: Pairing>(pub(crate) Node<C>, pub(crate) GossipSender);

#[tonic::async_trait]
impl<C: Pairing> World for MyWorld<C> {
    async fn hello(&self, request: Request<HelloRequest>) -> Result<Response<HelloReply>, Status> {
        let mut node = &self.0;
        let inner = request.into_inner();
        let index = inner.index;
        let size = inner.size;
        // compute your 'hint' and gossip to peers
        let pk = node.lagrange_get_pk(index as usize, size as usize);
        let mut pk_bytes = Vec::new();
        pk.serialize_compressed(&mut pk_bytes).unwrap();

        let announcement = Announcement {
            tag: Tag::Hint,
            data: pk_bytes,
        };

        let encoded = announcement.encode();
        // publish to gossipsub topic
        self.1.broadcast(encoded.into()).await.unwrap();

        let reply = HelloReply {
            message: format!("Broadcasted message to gossipsub topic"),
        };

        Ok(Response::new(reply))
    }
}
