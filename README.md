# Silent-Threshold-Encryption-Network

This is a proof of concept of a distributed network that enables silent threshold encryption.

## Usage

1. start nodes
2. generate initial hints & gossip
3. compute aggregated key
3. generate partial decryption

### Setup

cargo run -- setup --size 3 --out-dir config.txt 

### bootstrap node

cargo run -- run --bind-port 9944 --rpc-port 30333 --config-dir config.txt

## second node

cargo run -- run --bind-port 9945 --rpc-port 30334 --config-dir config.txt --bootstrap-pubkey fbfaec7a54fcf41562f7b03981fc9cf9efb2699d50030027355b1d6621f7ad27 --bootstrap-ip 172.31.149.62:9944

### hint gossip

./grpcurl -plaintext -proto ideal/beacon/src/hello.proto -d '{"index": 1, "size": 3}' '127.0.0.1:30333' hello.World/Hello