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
use ark_std::{UniformRand, Zero};
use silent_threshold_encryption::{
    aggregate::SystemPublicKeys,
    crs::CRS,
    decryption::agg_dec,
    encryption::encrypt,
    setup::{PublicKey, SecretKey},
    types::Ciphertext,
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
        let mut serialized_sys_key: Vec<u8> = vec![];

        let state = self.state.lock().await;
        if let (Some(config), Some(hints)) = (&state.config, &state.hints) {
            let crs = &config.crs;
            let lag_polys = &config.lag_polys;
            // TODO: This shouldn't be hardcoded, send as parameter?
            let k = 1;
            println!("Computing the system public keys");
            let system_keys = SystemPublicKeys::<C>::new(hints.clone(), crs, lag_polys, k);

            system_keys
                .serialize_compressed(&mut serialized_sys_key)
                .unwrap();

            println!("> Computed system key");
        }

        let hex_serialized_sys_key = hex::encode(serialized_sys_key);

        Ok(Response::new(PreprocessResponse {
            hex_serialized_sys_key,
        }))
    }

    /// partial decryption
    async fn partdec(
        &self,
        request: Request<PartDecRequest>,
    ) -> Result<Response<PartDecResponse>, Status> {
        let ciphertext_bytes = hex::decode(request.get_ref().ciphertext_hex.clone()).unwrap();
        let ciphertext = Ciphertext::<C>::deserialize_compressed(&ciphertext_bytes[..]).unwrap();

        let state = self.state.lock().await;
        let mut partial_decryption = state.sk.partial_decryption(&ciphertext);

        let mut bytes = Vec::new();
        partial_decryption.serialize_compressed(&mut bytes).unwrap();

        Ok(Response::new(PartDecResponse {
            hex_serialized_decryption: hex::encode(bytes),
        }))
    }
}
