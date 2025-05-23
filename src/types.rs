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
use ark_poly::{DenseUVPolynomial, univariate::DensePolynomial};
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

pub(crate) const KZG_CONFIG_KEY: &str = "kzg-config-key";

pub(crate) type E = ark_bls12_381::Bls12_381;
pub(crate) type G2 = <E as Pairing>::G2;
pub(crate) type Fr = <E as Pairing>::ScalarField;
pub(crate) type UniPoly381<C> = DensePolynomial<<C as Pairing>::ScalarField>;

#[derive(Clone, Debug, Encode, Decode)]
pub(crate) enum Tag {
    Config,
    Hint,
}

#[derive(Clone, Debug, Encode, Decode)]
pub(crate) struct Announcement {
    pub(crate) tag: Tag,
    pub(crate) data: Vec<u8>,
}

pub struct StartNodeParams<C: Pairing> {
    pub(crate) iroh_secret_key: IrohSecretKey,
    pub(crate) secret_key: SecretKey<C>,
    pub(crate) bind_port: u16,
    pub(crate) rpc_port: u16,
    pub(crate) index: usize, 
    pub(crate) bootstrap_peers: Option<Vec<NodeAddr>>,
}

/// params to start a new node
impl<C: Pairing> StartNodeParams<C> {
    pub fn rand(
        bind_port: u16,
        rpc_port: u16,
        index: usize,
        bootstrap_peers: Option<Vec<NodeAddr>>,
    ) -> Self {
        Self {
            iroh_secret_key: IrohSecretKey::generate(OsRng),
            secret_key: SecretKey::<C>::new(&mut OsRng),
            bind_port,
            rpc_port,
            index,
            bootstrap_peers,
        }
    }
}

#[derive(Clone, Debug, CanonicalDeserialize, CanonicalSerialize)]
pub(crate) struct Config<C: Pairing> {
    pub dummy: PublicKey<C>,
    pub tau: <C as Pairing>::ScalarField,
    pub size: usize,
}

impl<C: Pairing> Config<C> {
    pub fn rand(size: usize) -> Self {
        let tau = <C as Pairing>::ScalarField::rand(&mut OsRng);
        let sk = SecretKey::<C>::new(&mut OsRng);
        let lagrange_params = LagrangePowers::<C>::new(tau, size);
        let dummy = sk.lagrange_get_pk(0, &lagrange_params, size);
        Self { dummy, tau, size }
    }
}

#[derive(Debug, Decode, Encode)]
pub struct CiphertextBundle {
    pub key_ciphertext: Vec<u8>,
    pub message_ciphertext: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct State<C: Pairing> {
    pub config: Option<Config<C>>,
    pub hints: Option<Vec<PublicKey<C>>>,
    // TODO: This is proof of concept only, so it's fine for now
    // but in the future, we should instead have a secure vault for key mgmt
    // this is only here right now to make it easy to build partial decryptions
    // from the RPC context
    pub sk: SecretKey<C>,
}

impl<C: Pairing> State<C> {
    pub fn empty(sk: SecretKey<C>) -> Self {
        Self {
            config: None,
            hints: None,
            sk,
        }
    }

    pub fn update(&mut self, announcement: Announcement) {
        match announcement.tag {
            Tag::Config => {
                println!("Received Config");
                let config: Config<C> = Config::deserialize_compressed(&announcement.data[..]).unwrap();
                self.config = Some(config.clone());
                self.hints = Some(vec![config.dummy]);
            },
            Tag::Hint => {
                println!("Received Hint");
                let hint: PublicKey<C> = PublicKey::deserialize_compressed(&announcement.data[..]).unwrap();
                if let Some(h) = &self.hints {
                    let mut hints = h.clone();
                    hints.push(hint);
                    self.hints = Some(hints.clone());
                };
            }
        }
    }
}
