# COnfidential Private Search (COPS)

This repository hosts the components of the Confidential Private Search (COPS) project
funded by the [NGI SEARCH](https://ngi.eu/ngi-projects/ngi-search/) initiative.

## Purpose
COPS helps you privatize your search - both the data you search on, as well as the search queries you submitted.
It allows to create a confidential infrastructure where you can run [OpenSearch](https://opensearch.org/)  
or [ElasticSearch](https://www.elastic.co/elasticsearch) (whatever floats your boat!).

This way, even if you run the search engine on a third-party hosted environment, you remain the only one in control
of your search data, queries and patters. Neat, eh?

## Structure
The repository contains two components, the client-side (tee-client) and the server-side (cops-verifier).
Your can read more about them below.

### tee-client
The tee-client is a small client application written in Rust that collects information about the confidential computing
virtual machine environment. It then sends it over to the verifier to check that the security properties of the
environment.
You can read more in the README.md of the tee-client.

### cops-verifier
The cops-verifier is an attestation service implemented following [RFC9334](https://datatracker.ietf.org/doc/rfc9334/).
It consumes _attestation reports_ produced by the tee-client and verifies their validity and correctness.
Upon successful validation, it returns to the tee-client credentials to access resources (like data fed to a search
engine).
You can read more in the README.md of the cops-verifier.

## Running the project
To run the project, configure and build each of the components individually.
Note that the tee-client should run in a confidential VM, such as the ones provided on 
[GCP](https://cloud.google.com/security/products/confidential-computing) 
or [AWS](https://aws.amazon.com/confidential-computing/).

Happy private searching!