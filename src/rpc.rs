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
    encryption::{Ciphertext, encrypt},
    kzg::KZG10,
    setup::{AggregateKey, LagrangePowers, PublicKey, SecretKey},
};
use std::{
    collections::HashMap,
    fmt,
    net::{Ipv4Addr, SocketAddrV4},
    str::FromStr,
};

use crate::node::*;
use crate::types::*;

use codec::{Decode, Encode};
use tonic::{transport::Server, Request, Response, Status};

use std::sync::Arc;
use tokio::sync::Mutex;

pub mod hello {
    tonic::include_proto!("hello");
}
use hello::world_server::{World, WorldServer};
use hello::{PartDecRequest, PartDecResponse, PreprocessRequest, PreprocessResponse};

pub struct MyWorld<C: Pairing> {
    pub state: Arc<Mutex<State<C>>>,
}

#[tonic::async_trait]
impl<C: Pairing> World for MyWorld<C> {
    /// preprocess with best known hints to get encryption and aggregate keys
    async fn preprocess(
        &self,
        request: Request<PreprocessRequest>,
    ) -> Result<Response<PreprocessResponse>, Status> {
        let mut serialized_aggregate_key: Vec<u8> = vec![];

        let state = self.state.lock().await;

        if let Some(config) = &state.config {
            let kzg_params = KZG10::<C, UniPoly381<C>>::setup(config.size, config.tau).unwrap();
            let agg_key =
                AggregateKey::<C>::new(state.hints.as_ref().unwrap().clone(), &kzg_params);
            agg_key
                .serialize_compressed(&mut serialized_aggregate_key)
                .unwrap();
            println!("> Computed AggregateKey");
        }

        let hex_serialized_aggregate_key = hex::encode(serialized_aggregate_key);
        Ok(Response::new(PreprocessResponse {
            hex_serialized_aggregate_key,
        }))
    }

    /// partial decryption
    async fn partdec(
        &self,
        request: Request<PartDecRequest>,
    ) -> Result<Response<PartDecResponse>, Status> {
        let ciphertext_bytes = hex::decode(request.get_ref().ciphertext_hex.clone()).unwrap();
        let bundle = CiphertextBundle::decode(&mut &ciphertext_bytes[..]).unwrap();
        let key_ct_bytes = bundle.key_ciphertext;
        let ciphertext = Ciphertext::<C>::deserialize_compressed(&key_ct_bytes[..]).unwrap();

        let state = self.state.lock().await;

        let partial_decryption = state.sk.partial_decryption(&ciphertext);
        let mut bytes = Vec::new();
        partial_decryption.serialize_compressed(&mut bytes).unwrap();

        Ok(Response::new(PartDecResponse {
            hex_serialized_decryption: hex::encode(bytes),
        }))
    }
}
