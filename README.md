# DocChain Digital Notary Service

DocChain Digital Notary Service provides a Soroban Smart Contract for authenticating and notarizing digital documents. This contract enables secure document management on the blockchain, including features like committing document hashes, verifying authenticity, and digital signing.

## Features

- **Document Hash Commit**: Commit unique document hashes to the blockchain for future verification.
- **Verification**: Confirm the integrity and authenticity of stored document hashes.
- **Digital Signing**: Enable secure digital signatures for documents.
- **Notarization**: Leverage blockchain immutability for document notarization.

## Getting Started

### Prerequisites

- [Rust](https://www.rust-lang.org/) (for building and deploying Soroban contracts)
- [Soroban CLI](https://soroban.stellar.org/) (for interacting with Soroban smart contracts on the Stellar network)

### Installation

Clone the repository and navigate to the project folder:

```bash
git clone https://github.com/docchainnotary/contract.git
cd contract
```

### Deployment

1. Update the deployment configurations in `deploy.sh`.
2. Run the deployment script:

   ```bash
   ./deploy.sh
   ```

### Usage

After deployment, use the Soroban CLI or other Stellar-compatible tools to interact with the contract’s functions.

## License

This project is licensed under the MIT License.

