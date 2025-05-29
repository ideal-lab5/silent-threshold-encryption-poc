# Silent Threshold Encryption PoC

This is a proof of concept of a distributed network that enables silent threshold encryption.

## Setup Guide

1. start a bootstrap node

cargo run -- run --bind-port 9944 --rpc-port 30333 --is-bootstrap --index 0

> This will save the randomly generated config to config.txt

2. start a second peer (copy/paste pubkey and ticket)

cargo run -- run --bind-port 9945 --rpc-port 30334 --bootstrap-pubkey 426901041c6803fa2cdb2ee5034238e0662816039d290bd4e6be028346df49d8 --bootstrap-ip 172.31.149.62:9944 --ticket docaaacafdccrxsdafkuzzg6y27kfzonwxlo4gjjplig2x6aiz2txduvk3aafbgsaiedruah6rm3mxoka2chdqgmkawaoossc6u427afa2g35e5qajdnb2hi4dthixs65ltmuys2mjoojswyylzfzuxe33ifzxgk5dxn5zgwlrpaiagdmakwd4mgayavqpzkpwyju --index 1

#### Encrypt a message

> hardcoded to save to ciphertext.txt for now

cargo run -- encrypt --message "hello" --config-dir config.txt

#### Decrypt a message 

cargo run -- decrypt --ciphertext-dir ciphertext.txt --config-dir config.txt