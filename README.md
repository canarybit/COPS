# COnfidential Private Search (COPS)

This repository hosts the components of the Confidential Private Search (COPS) project
funded by the [NGI SEARCH](https://ngi.eu/ngi-projects/ngi-search/) initiative.

## Purpose
COPS helps you privatize your search - both the data you search on, as well as the search queries you submitted.
It allows to create a confidential infrastructure where you can run [OpenSearch](https://opensearch.org/)  or [ElasticSearch](https://www.elastic.co/elasticsearch) (whatever floats your boat!).

This way, even if you run the search engine on a third-party hosted environment, you remain the only one in control
of your search data, queries and patters. Neat, eh?

## Structure
The repository contains two components, the client-side (tee-client) and the server-side (cops-verifier).
Your can read more about them below.

### tee-client
The tee-client is a small client application written in Rust that collects information about the confidential computing
virtual machine environment. It then sends it over to the verifier to check that the security properties of the
environment.
You can read more in the [README](https://github.com/canarybit/COPS/blob/main/tee-client/README.md) of the tee-client.

### cops-verifier
The cops-verifier is an attestation service implemented following [RFC9334](https://datatracker.ietf.org/doc/rfc9334/).
It consumes _attestation reports_ produced by the tee-client and verifies their validity and correctness.
Upon successful validation, it returns to the tee-client credentials to access resources (like data fed to a search
engine).
You can read more in the [README](https://github.com/canarybit/COPS/blob/main/cops-verifier/README.md) of the cops-verifier.

## Running the project
To run the project, configure and build each of the components individually.
Note that the tee-client should run in a [confidential VM instance](https://en.wikipedia.org/wiki/Confidential_computing), such as the ones provided on 
[GCP](https://cloud.google.com/security/products/confidential-computing) 
or [AWS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sev-snp.html).
Note that the confidentiality and integrity guarantees of COPS only apply to data **in memory**.
This means that to avoid data leakage in case of memory swapping, the search engine should launch confiential VM instances without a disk.  

## Performance and scalability considerations

We encourage you to read the documentation of the target search engine ([ElasticSearch](https://www.elastic.co/guide/en/elasticsearch/reference/current/important-settings.html) or [OpenSearch](https://opensearch.org/docs/latest/getting-started/) in order to configure it for best performance.
Considering that the search engine and data should operate entirely in memory to ensure the COPS security guarantees, this influences the choice of VM instance configuration. 

The table below shows the recommended maximum size of the data set for a sample of available VM instance configurations from AWS with [confidental computing support](https://cloud.google.com/security/products/confidential-computing).
As a rough guideline, the recommended maximum data set size should be 50% of the RAM available to the instance.
Note that other cloud providers may have VM instances with confidential computing support with a different configuration.

| Instance Size	| vCPU | Memory (GiB) | Recommended maximum data set size (GiB) |
|---------------|------|--------------|---------------|
| c6a.large	| 2	| 4	|  2 | 
| c6a.xlarge |	4 |	8	| 4 | 
| c6a.2xlarge	| 8	| 16| 	8	|   
| c6a.4xlarge	| 16	| 32		|16 |
| c6a.8xlarge |	32 |	64		| 32 |
| c6a.12xlarge | 48	| 96		|48 |
| c6a.16xlarge	| 64	| 128		| 64 |
| c6a.24xlarge	| 96	| 192		|96 |
| c6a.32xlarge	| 128	| 256		| 128 |
| c6a.48xlarge	| 192	| 384		| 192 |

Happy private searching!
