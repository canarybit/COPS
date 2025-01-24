# TEE-CLIENT

  

This is a guide on how to use the Tee-client (Trusted Execution Environment client) project and the Implementation of the secure client for COPS TEEs.

  

## Functionality so far

* Generate certificates with customizable values

* Curl STS service

* Parse STS response, extract tokens for further use.

  

## Some good references:

* https://jan.newmarch.name/NetworkProgramming/TLS/wrapper.html?rust

* https://users.rust-lang.org/t/breaking-changes-in-rustls/68621

  

## Rust and Rusoto:

* https://dev.classmethod.jp/articles/rust-access-aws-using-rusoto/

* https://crates.io/crates/curl

* https://github.com/durch/rust-s3

  

## Table of Contents

  

- [Overview](#overview)

- [Installation](#installation)

- [Configuration](#configuration)

- [Usage](#usage)

- [Examples](#examples)

- [API Reference](#api-reference)

- [License](#license)

  

## Overview

  

TBA

  

## Installation

  

To install the Tee-client, it is necessary to have already installed:

* Rust ( https://www.rust-lang.org/ ) version 1.71.1

* Cargo ( https://doc.rust-lang.org/cargo/ )  version 1.71.1

* Docker ( https://www.docker.com/ ) version 24.0.5

  

The tee-client assumes that the Docker image for Vector is already installed on Docker:

* Vector ( https://vector.dev/ ) version Vector 0.29.1

  

To install the vector image on docker, the command is:

```bash

$  docker  pull  timberio/vector:0.29.1-debian

```

  

Next step is building the project, the command is:

```bash

$  cargo  build  --release

```


*The build command fails when using a toolchain version older than the one specified in [`rust-version`](Cargo.toml#L5) (see [manifest format docs](https://doc.rust-lang.org/cargo/reference/manifest.html#the-rust-version-field)). Use [rustup](https://dev-doc.rust-lang.org/beta/edition-guide/rust-2018/rustup-for-managing-rust-versions.html#for-updating-your-installation) for version management.*


Starting from a default ubuntu installation, some additional package might be need, we suggest these solution for the following potential error:

  

**error**:

```bash

$  error:  linker  `cc`  not  found

```

**solution**:

```bash

$  sudo  apt  install  build-essential

```

  

**error**:

```bash

$  error:  failed  to  run  custom  build  command  for  `loopdev v0.4.0`

```

**solution**:

```bash

$  sudo  apt-get  install  llvm

$  sudo  apt-get  install  clang

```
 

## Configuration

  

Before running the Tee-client it is necessary to add the proper configuration.

The Tee-client uses a Json configuration file, whose default name is "info", to collect information about the

application owner , the dataset owner, and the virtual machine (VM).

The expected path of the info file is :

```bash

$  /tmp/collaboration/info

```
Three different example of the info file, one for each currently supported cloud provider, can be found in the "samples" folder, whose default path is : 
```bash

$  /tmp/samples/

```

It is very important to check the "cloud_provider" field, to make sure it matches the type of VM is being used to run the tee-client.

## Usage

The client can be run in different modes, and tests can be launched individually or all together:

To run the Tee-client, the command is:

```bash

$  cargo  run  --release

```
after being compiled in release mode, the binary file will be generated in the default "./target/release" folder. it's possible to run the tee-client using the binary only, the command is: 

```bash

$  /tmp/target/release/tee-client

```
The attestation-only mode launches only the attestation and then shut down the tee-client right after.
To run the Tee-client in attestation only mode, the command is:

```bash

$  cargo  run  --release  --  --attestation-only

```

To run the tests, use the following command:

```bash

$  cargo  test  --release  --  --test-threads=1

```

It is possible to run a single test, use the following command:

```bash

$  cargo  test  --release  name_of_the_test

```

To print the log info while running the test, add the following flag:

```bash

$  cargo  test  --release  name_of_the_test  --  --nocapture

``` 
After each run of the tee-client or of the tests, all the logs will be added to 

## Key generation

For now private and public key of TEE client are generated based on ECC algorithm. If a customer does not support ECC we can change key generation to RSA instead, for that the following code need to be used in credentials.rs instead of lines 262 to 264.

  

```bash

//generate  RSA  key  pair  in  case  RSA  is  used

let  rsa  =  Rsa::generate(2048)?;

let  key_pair  =  PKey::from_rsa(rsa)?;

```

  
