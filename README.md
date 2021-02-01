# OpenBsc

Fast and feature-rich BSC client based on [Open-Ethereum](https://github.com/openethereum/openethereum).

[» Download the latest release «](https://github.com/binance-chain/open-bsc/releases/latest)

[![GPL licensed][license-badge]][license-url]
[![Build Status][ci-badge]][ci-url]

[license-badge]: https://img.shields.io/badge/license-GPL_v3-green.svg
[license-url]: LICENSE
[ci-badge]: https://github.com/binance-chain/open-bsc/workflows/Build%20and%20Test%20Suite/badge.svg
[ci-url]: https://github.com/binance-chain/open-bsc/actions

## Table of Contents

1. [Binance Smart Chain ](#chapter-001)
2. [Building](#chapter-002)<br>
  2.1 [Building Dependencies](#chapter-0021)<br>
  2.2 [Building from Source Code](#chapter-0022)<br>
  2.3 [Starting OpenEthereum](#chapter-0023)
3. [Testing](#chapter-003)
4. [Documentation](#chapter-004)
5. [Toolchain](#chapter-005)
6. [License](#chapter-006)

## 1. Binance Smart Chain <a id="chapter-001"></a>

The goal of Binance Smart Chain is to bring programmability and interoperability to Binance Chain. In order to embrace the existing popular community and advanced technology, it will bring huge benefits by staying compatible with all the existing smart contracts on Ethereum and Ethereum tooling.
The easiest solution is based on go-ethereum fork, check more details [here](https://github.com/binance-chain/bsc).

OpenEthereum is the lightest and widely used Ethereum client so far, we respect the great work of Ethereum very much,
so Binance Smart Chain starts its development based on open-ethereum fork. So you may see many toolings, binaries and also docs are named after "open-ethereum".

But from that baseline of EVM compatible, Binance Smart Chain introduces  a system of 21 validators with Proof of Staked Authority (PoSA) consensus that can support short block time and lower fees. The most bonded validator candidates of staking will become validators and produce blocks. The double-sign detection and other slashing logic guarantee security, stability, and chain finality.

Cross-chain transfer and other communication are possible due to native support of interoperability. Relayers and on-chain contracts are developed to support that. Binance DEX remains a liquid venue of the exchange of assets on both chains. This dual-chain architecture will be ideal for users to take advantage of the fast trading on one side and build their decentralized apps on the other side. **The Binance Smart Chain** will be:

- **A self-sovereign blockchain**: Provides security and safety with elected validators.
- **EVM-compatible**: Supports all the existing Ethereum tooling along with faster finality and cheaper transaction fees.
- **Interoperable**: Comes with efficient native dual chain communication; Optimized for scaling high-performance dApps that require fast and smooth user experience.
- **Distributed with on-chain governance**: Proof of Staked Authority brings in decentralization and community participants. As the native token, BNB will serve as both the gas of smart contract execution and tokens for staking.

More details in [White Paper](http://binance.org/en#smartChain).

## 2. Building <a id="chapter-002"></a>

### 2.1 Build Dependencies <a id="chapter-0021"></a>

OpenBsc requires **latest stable Rust version** to build.

We recommend installing Rust through [rustup](https://www.rustup.rs/). If you don't already have `rustup`, you can install it like this:

- Linux:
  ```bash
  $ curl https://sh.rustup.rs -sSf | sh
  ```

  OpenEthereum also requires `clang` (>= 9.0), `clang++`, `pkg-config`, `file`, `make`, and `cmake` packages to be installed.

- OSX:
  ```bash
  $ curl https://sh.rustup.rs -sSf | sh
  ```

  `clang` is required. It comes with Xcode command line tools or can be installed with homebrew.

- Windows:
  Make sure you have Visual Studio 2015 with C++ support installed. Next, download and run the `rustup` installer from
  https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe, start "VS2015 x64 Native Tools Command Prompt", and use the following command to install and set up the `msvc` toolchain:
  ```bash
  $ rustup default stable-x86_64-pc-windows-msvc
  ```

Once you have `rustup` installed, then you need to install:
* [Perl](https://www.perl.org)
* [Yasm](https://yasm.tortall.net)

Make sure that these binaries are in your `PATH`. After that, you should be able to build OpenBsc from source.

### 2.2 Build from Source Code <a id="chapter-0022"></a>

It was tested to work with Rust 1.47.0 (some other versions of Rust cause OpenEthereum crash!)

```bash
# download OpenBsc code
$ git clone https://github.com/binance-chain/open-bsc
$ cd open-bsc

# build in release mode
$ cargo build --release --features final
```

This produces an executable in the `./target/release` subdirectory.

Note: if cargo fails to parse manifest try:

```bash
$ ~/.cargo/bin/cargo build --release
```

Note, when compiling a crate and you receive errors, it's in most cases your outdated version of Rust, or some of your crates have to be recompiled. Cleaning the repository will most likely solve the issue if you are on the latest stable version of Rust, try:

```bash
$ cargo clean
```

This always compiles the latest nightly builds. If you want to build stable, do a

```bash
$ git checkout stable
```

### 2.3 Starting BSC <a id="chapter-0023"></a>

#### Manually

To start BSC client manually, just run

```bash
$ ./target/release/openethereum --chain bsc
```

so it begins syncing the Bsc blockchain.

#### Using `systemd` service file

To start OpenEthereum as a regular user using `systemd` init:

1. Copy `./scripts/openethereum.service` to your
`systemd` user directory (usually `~/.config/systemd/user`).
2. Copy release to bin folder, write `sudo install ./target/release/openethereum /usr/bin/openethereum`
3. To configure OpenEthereum, see [our wiki](https://openethereum.github.io/Configuring-OpenEthereum) for details.

## 3. Testing <a id="chapter-003"></a>

Download the required test files: `git submodule update --init --recursive`. You can run tests with the following commands:

* **All** packages
  ```
  cargo test --all
  ```

* Specific package
  ```
  cargo test --package <spec>
  ```

Replace `<spec>` with one of the packages from the [package list](#package-list) (e.g. `cargo test --package evmbin`).

You can show your logs in the test output by passing `--nocapture` (i.e. `cargo test --package evmbin -- --nocapture`)

## 4. Documentation <a id="chapter-004"></a>

Be sure to [check out our wiki](https://openethereum.github.io/) for more information.

### Viewing documentation for OpenBsc packages

You can generate documentation for OpenBsc Rust packages that automatically opens in your web browser using [rustdoc with Cargo](https://doc.rust-lang.org/rustdoc/what-is-rustdoc.html#using-rustdoc-with-cargo) (of the The Rustdoc Book), by running the the following commands:

* **All** packages
  ```
  cargo doc --document-private-items --open
  ```

* Specific package
  ```
  cargo doc --package <spec> -- --document-private-items --open
  ```

Use`--document-private-items` to also view private documentation and `--no-deps` to exclude building documentation for dependencies.

Replacing `<spec>` with one of the following from the details section below (i.e. `cargo doc --package openethereum --open`):

<a id="package-list"></a>
**Package List**
<details><p>

* OpenEthereum Client Application
  ```bash
  openethereum
  ```
* OpenEthereum Account Management, Key Management Tool, and Keys Generator
  ```bash
  ethcore-accounts, ethkey-cli, ethstore, ethstore-cli
  ```
* OpenEthereum Chain Specification
  ```bash
  chainspec
  ```
* OpenEthereum CLI Signer Tool & RPC Client
  ```bash
  cli-signer parity-rpc-client
  ```
* OpenEthereum Ethash & ProgPoW Implementations
  ```bash
  ethash
  ```
* EthCore Library
  ```bash
  ethcore
  ```
  * OpenEthereum Blockchain Database, Test Generator, Configuration,
Caching, Importing Blocks, and Block Information
    ```bash
    ethcore-blockchain
    ```
  * OpenEthereum Contract Calls and Blockchain Service & Registry Information
    ```bash
    ethcore-call-contract
    ```
  * OpenEthereum Database Access & Utilities, Database Cache Manager
    ```bash
    ethcore-db
    ```
  * OpenEthereum Virtual Machine (EVM) Rust Implementation
    ```bash
    evm
    ```
  * OpenEthereum Light Client Implementation
    ```bash
    ethcore-light
    ```
  * Smart Contract based Node Filter, Manage Permissions of Network Connections
    ```bash
    node-filter
    ```
  * OpenEthereum Client & Network Service Creation & Registration with the I/O Subsystem
    ```bash
    ethcore-service
    ```
  * OpenEthereum Blockchain Synchronization
    ```bash
    ethcore-sync
    ```
  * OpenEthereum Common Types
    ```bash
    common-types
    ```
  * OpenEthereum Virtual Machines (VM) Support Library
    ```bash
    vm
    ```
  * OpenEthereum WASM Interpreter
    ```bash
    wasm
    ```
  * OpenEthereum WASM Test Runner
    ```bash
    pwasm-run-test
    ```
  * OpenEthereum EVM Implementation
    ```bash
    evmbin
    ```
  * OpenEthereum JSON Deserialization
    ```bash
    ethjson
    ```
  * OpenEthereum State Machine Generalization for Consensus Engines
    ```bash
    parity-machine
    ```
* OpenEthereum Miner Interface
  ```bash
  ethcore-miner parity-local-store price-info ethcore-stratum using_queue
  ```
* OpenEthereum Logger Implementation
  ```bash
  ethcore-logger
  ```
* OpenEthereum JSON-RPC Servers
  ```bash
  parity-rpc
  ```
* OpenEthereum Updater Service
  ```bash
  parity-updater parity-hash-fetch
  ```
* OpenEthereum Core Libraries (`util`)
  ```bash
  accounts-bloom blooms-db dir eip-712 fake-fetch fastmap fetch ethcore-io
  journaldb keccak-hasher len-caching-lock memory-cache memzero
  migration-rocksdb ethcore-network ethcore-network-devp2p panic_hook
  patricia-trie-ethereum registrar rlp_compress stats
  time-utils triehash-ethereum unexpected parity-version
  ```

</p></details>

## 5. Toolchain <a id="chapter-005"></a>

Similar to the OpenEthereum client, there are additional tools in this repository available:

- [evmbin](./evmbin) - OpenEthereum EVM Implementation.
- [ethstore](./accounts/ethstore) - OpenEthereum Key Management.
- [ethkey](./accounts/ethkey) - OpenEthereum Keys Generator.

The following tools are available in a separate repository:
- [ethabi](https://github.com/openethereum/ethabi) - OpenEthereum Encoding of Function Calls. [Docs here](https://crates.io/crates/ethabi)
- [whisper](https://github.com/openethereum/whisper) - OpenEthereum Whisper-v2 PoC Implementation.

## 6. License <a id="chapter-006"></a>

[LICENSE](./LICENSE)
