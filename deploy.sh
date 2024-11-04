#!/bin/bash

stellar contract deploy \
  --wasm target/wasm32-unknown-unknown/release/notary.wasm \
  --network testnet \
  --source docchain
