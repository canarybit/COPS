# cc-inspector
Inspector is an attestation service and the main responsibility of inspector is to verify attestation reports, verify the freshness of the report, enforcing policies, send CSR to the CA for signing, and return the signed certificate to the TEE-Client.

Inspector is running on this domain: https://cops.io/ <br />
Inspector TLS certificates are provided by let’s encrypt and they need to be renewed each six months. 

In inspector code naming convention for Evidence and its structure, is as follows:
This structure should be kept throughout the whole code!
## Evidence

   ### report
    -- report_claim_measurement
    -- report_claim_report-data
    -- report_claim_…

   ### environment_info
    -- info_claim_…
    -- info_claim_…

## Requirements
Install the following requirments on the server where you want to run inspector code:
```
sudo apt-get install -y make gcc zip uuid-dev automake autoconf libssl-dev g++ python3 python3-pip nginx certbot
pip3 install requests flask OPA-python-client pymongo pyOpenSSL python-dotenv
```
### Setup OPA server
OPA should be installed and run alongside the inspector server. 
First install OPA using the following command: 
```
curl -L -o opa https://openpolicyagent.org/downloads/v0.56.0/opa_linux_amd64_static
chmod +x opa
```
Then run OPA as follows: 
```
./opa run --server --addr localhost:8181 &
```
The default policies that are checked by OPA are fetched from mongoDB and will be written to example.rego file, new policies can be added on demand. 

Now run the inspector server: 

```
python3 server.py
```

### Input to the inspector 

Inspector accepts a tar file with any name, and usually the following files needs to be included in the tar file for a successful attestation: <br />
guest_report.bin: a mandatory guest report binary file. <br />
report.txt: a mandatory guest report file in human readable format. <br />
public_key.pem: a mandatory public key of guest VM generated by tee-client. <br />
csr.pem: an optional certificate signing request generated by tee-client. <br />
id.txt: a mandatory id json file that includes some extra evidence from the guest VM such as firmware version, cloud provider, geographical location of the guest VM, etc. CA field inside the id file is optional. <br />
signature.sig: a mandatory signature file which is the signature of id.txt file. <br /> 

ask, ark, vcek: mandatory certificates to verify the AMD certificate chain. <br />

Sample input files can be found under test directory. 

Note: id.txt file can include an optional ‘CA’ field, if CA is included in the id file then the csr will be send to the CA included in the id file otherwise the csr will be sent to the default CA which is https://canarybit.ca.confidentialcloud.cc/. 

### Output of the inspector: 
If csr includes in the tar file then the output of the inspector is a signed certificate from CA.
If csr is NOT included in the tar file then the out of the inspector is “validation success“ of the report. 

## Tests
In order to run the tests run the following command: 

```
python3 test.py
```

## Performance
The cops-verifier is highly scalable, primarily thanks to it's stateless implementation.
In a recent test, a single instance of cops-verifier running on an AWS instanced with 2 vCPU and 4 GB RAM was able to process  about 25 attestations per second.

=======



