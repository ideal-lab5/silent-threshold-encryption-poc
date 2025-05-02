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
    str::{Bytes, FromStr},
};

use codec::{Decode, Encode};

pub(crate) type E = ark_bls12_381::Bls12_381;
pub(crate) type G2 = <E as Pairing>::G2;
pub(crate) type Fr = <E as Pairing>::ScalarField;
pub(crate) type UniPoly381 = DensePolynomial<<E as Pairing>::ScalarField>;

#[derive(Debug, Encode, Decode)]
pub(crate) enum Tag {
    Hint,
}

#[derive(Debug, Encode, Decode)]
pub(crate) struct Announcement {
    pub(crate) tag: Tag,
    pub(crate) data: Vec<u8>,
}

pub struct StartNodeParams<C: Pairing> {
    pub(crate) iroh_secret_key: IrohSecretKey,
    pub(crate) secret_key: SecretKey<C>,
    pub(crate) topic: TopicId,
    pub(crate) tau: <C as Pairing>::ScalarField,
    pub(crate) dummy_pubkey: PublicKey<C>,
    pub(crate) bind_port: u16,
    pub(crate) rpc_port: u16,
    pub(crate) kzg_size: usize,
    pub(crate) bootstrap_peers: Option<Vec<NodeAddr>>,
}

/// params to start a new node
impl<C: Pairing> StartNodeParams<C> {
    pub fn rand(
        topic: TopicId,
        bind_port: u16,
        rpc_port: u16,
        tau: <C as Pairing>::ScalarField,
        dummy_pubkey: PublicKey<C>,
        kzg_size: usize,
        bootstrap_peers: Option<Vec<NodeAddr>>,
    ) -> Self {
        Self {
            iroh_secret_key: IrohSecretKey::generate(OsRng),
            secret_key: SecretKey::<C>::new(&mut OsRng),
            topic,
            bind_port,
            rpc_port,
            tau,
            dummy_pubkey,
            bootstrap_peers,
            kzg_size,
        }
    }
}

pub struct State {
    known_pubkeys: Vec<PublicKey<E>>,
}