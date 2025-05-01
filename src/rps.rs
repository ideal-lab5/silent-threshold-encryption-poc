use futures::prelude::*;
use tarpc::{
    client, context,
    server::{self, Channel},
};

// This is the service definition. It looks a lot like a trait definition.
// It defines one RPC, hello, which takes one arg, name, and returns a String.
#[tarpc::service]
trait STEService {
    async fn hint();
    /// Returns a greeting for name.
    async fn part_dec(ciphertext: Vec<u8>) -> Vec<u8>;
}

// This is the type that implements the generated World trait. It is the business logic
// and is used to start the server.
#[derive(Clone)]
struct STEServer;

impl STEService for STEServer {
    async fn gossip_hint() {
        println!("hey bozo");
    }

    async fn part_dec(self, _: context::Context, name: Vec<u8>) -> Vec<u8> {
        b"hello_world".to_vec()
    }
}