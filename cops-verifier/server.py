from enum import Enum
import os
import shutil
import subprocess
import tempfile
import requests
import datetime, time
import tarfile
import sys,json,base64
import logging
import hashlib
import re
import string
import random
from bson import json_util
from OpenSSL.crypto import load_publickey, load_privatekey, FILETYPE_PEM, verify, X509,sign
from werkzeug.utils import secure_filename
from flask import Flask, request, render_template
from flask_caching import Cache

app = Flask(__name__)
from dotenv import load_dotenv
from parser import convert_to_json 

app.config["CACHE_TYPE"] = "SimpleCache" 
cache = Cache(app)
Nonce = []
load_dotenv()

dir = os.getcwd()

CB_WORKDIR = dir
CB_WORKDIR_LOG = os.path.join(dir, "log")
LOG_FILE = os.path.join(dir, "log/cops-verifier.log")

VALIDATION_FAIL_MSG = "", 400
VALIDATION_SUCCESS_MSG = "", 200

#####Create OPA client
from opa_client.opa import OpaClient
client = OpaClient()
client.check_connection()
#Default OPA policy rules
rego_file = os.path.join(CB_WORKDIR, "example.rego")
client.update_opa_policy_fromfile(rego_file, endpoint="fromfile")

# Temporary directory for all attestations
TMP_DIR = "/tmp/"
TMP_FILE_PREFIX = "new_attestation"
TMP_FILE_DIR = "" # Must be an empty string. Built locally using current date.
TMP_TARFILE_PATH = "" # Must be an empty string.
TMP_TARFILE_NAME = "guest-report.tar"
TMP_IDFILE_NAME = "id.txt"
TMP_CSRFILE_NAME = "csr.pem"
TMP_REPORTFILE_NAME = "report.txt"
TMP_REPORTFILE_BIN_NAME = "guest_report.bin"
TMP_SIGNATURE_NAME = "signature.sig"
TMP_VCEK_NAME = "vcek.pem"
TMP_VLEK_NAME = "a8074bc2-a25a-483e-aae6-39c045a0b8a1"
TMP_CERT_CHAIN_NAME = "cert_chain.pem"
TMP_JSON_NAME = 'json-report.json'
DATA_FILE = "public_key.pem"
TMP_ARK_NAME = "ark.pem"
TMP_ASK_NAME = "ask.pem"

SEV_TOOL_SCRIPT = os.path.join(CB_WORKDIR, "sev-tool/sevtool")
SEV_SNP_MEASURE_SCRIPT = os.path.join(CB_WORKDIR, "sev-snp-measure-0.0.7/sev-snp-measure.py")

# CSPs OVMFs configuration files
OVH_AMD_SEV_SNP_OVMF_FILE = os.path.join(CB_WORKDIR, "OVH/OVMF_CODE.fd")
AWS_SNP_OVMF_FILE = os.path.join(CB_WORKDIR, "AWS/ovmf_img.fd")

AWS_CERT_CHAIN = os.path.join(CB_WORKDIR, "AWS/cert_chain.pem")

VCPU_TYPE = "--vcpu-type=EPYC-v4"
VMM_TYPE = "--vmm-type=ec2"

# Certificate Authority (CA)
CA_ENDPOINT = os.getenv('CA_ENDPOINT')

# MongoDB Verifier
MONGODB_INSERT_ACTION = os.getenv('MONGODB_INSERT_ACTION')
MONGODB_FIND_ONE_ACTION = os.getenv('MONGODB_FIND_ONE_ACTION')
MONGODB_API_KEY = os.getenv('MONGODB_API_KEY')
MONGODB_DATABASE = os.getenv('MONGODB_DATABASE')
MONGODB_CLUSTER = os.getenv('MONGODB_CLUSTER')
MONGODB_COLLECTION = os.getenv('MONGODB_COLLECTION')
MONGODB_COLLECTION_N = os.getenv('MONGODB_COLLECTION_N')
MONGODB_COLLECTION_REF = os.getenv('MONGODB_COLLECTION_REF')

# MongoDB Studio
MONGODB_INSERT_ACTION_S = os.getenv('MONGODB_INSERT_ACTION_S')
MONGODB_API_KEY_S = os.getenv('MONGODB_API_KEY_S')
MONGODB_DATABASE_S = os.getenv('MONGODB_DATABASE_S')
MONGODB_CLUSTER_S = os.getenv('MONGODB_CLUSTER_S')
MONGODB_COLLECTION_S = os.getenv('MONGODB_COLLECTION_S')


# Create and configure logger
logging.basicConfig(filename=LOG_FILE,
                    format='%(asctime)s %(message)s',
                    filemode='a') 
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


class Provider(Enum):
    """Helper for CSP identification."""

    AWS = "aws"
    AZURE = "azure"
    OVH = "ovh"


def is_cert_chain_valid(TMP_FILE_DIR, CLOUD_PROVIDER):
    try:
        tag = False
        if CLOUD_PROVIDER == "ovh":

            result = subprocess.run([SEV_TOOL_SCRIPT, "--ofolder", TMP_FILE_DIR, "--validate_cert_chain_vcek"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            tag = True
        if CLOUD_PROVIDER == "aws":
            # Follows these steps: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/snp-attestation.html
            os.system("openssl x509 -inform der -in {}/{} -out {}/{}".format(TMP_FILE_DIR,TMP_VLEK_NAME,TMP_FILE_DIR,TMP_VCEK_NAME))
            
            vcek_path = os.path.join(TMP_FILE_DIR, TMP_VCEK_NAME)
            result = subprocess.run(["openssl", "verify", "--CAfile", AWS_CERT_CHAIN, vcek_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            #If it fails try to redownload the cert_chain.pem
            if "OK" not in result.stdout:
                os.system("curl --proto '=https' --tlsv1.2 -sSf https://kdsintf.amd.com/vlek/v1/Milan/cert_chain -o {}/{}".format(TMP_FILE_DIR,TMP_CERT_CHAIN_NAME))
                cert_chain_path = os.path.join(TMP_FILE_DIR, TMP_CERT_CHAIN_NAME)
                result = subprocess.run(["openssl", "verify", "--CAfile", cert_chain_path, vcek_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            tag = True

        if tag:
            if "Command Successful" in result.stdout:
                logger.info("Cert chain: OK")
                return True
            if "OK" in result.stdout:
                logger.info("Cert chain: OK")
                return True
            else:
                logger.info("Cert chain: ERROR")
                return False

        else:
            return False

    except OSError:
        raise RuntimeError("Failed to validate cert chain.")

def is_evidence_valid(TMP_FILE_DIR):
    try:
        result = subprocess.run([SEV_TOOL_SCRIPT, "--ofolder", TMP_FILE_DIR, "--validate_guest_report"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        if "Command Successful" in result.stdout:
            logger.info("Guest evidence: OK")
            return True
        else:
            logger.info("Guest evidence: ERROR")
            return False

    except OSError:
        raise RuntimeError("Failed to validate evidence.")

def is_signature_valid(data,signature,pubkey):
        try:
            #Read data
            data_content = open(data,"r")
            data_c = data_content.read()
            data_content.close()
            str_encoded = bytes(data_c,'utf-8')
            
            #Read signature
            with open(signature, 'rb') as f:
                signature_val = f.read()

            #Read public key
            with open(pubkey) as f:
                public_key_data = f.read()
            pkey = load_publickey(FILETYPE_PEM, public_key_data)

            x509 = X509()
            x509.set_pubkey(pkey)

            if  verify(x509, signature_val, str_encoded, 'sha256') is None:
                logger.info("Signature is VALID!")
                return True
            else:
                logger.info("Signature is NOT VALID!")
                return False
        except OSError:
            raise RuntimeError("FAILED to verify signature!")



def sha512sum(filename):
    try:
        h = hashlib.sha512()
        b = bytearray(128*1024)
        mv = memoryview(b)
        with open(filename, 'rb', buffering=0) as f:
            while n := f.readinto(mv):
                h.update(mv[:n])
        return h.hexdigest()
    except OSError:

          raise RuntimeError("Failed to caculate the hash.")

def validate_evidence_claim_report_data(TMP_FILE_DIR, DATA):
    try:
        evidence_json = os.path.join(TMP_FILE_DIR,TMP_JSON_NAME)
        json_file = open(evidence_json)
        report_claim_report_data_extracted = json.load(json_file)[0]['Report Data']
        json_file.close()

        data_file = os.path.join(TMP_FILE_DIR,DATA)
        report_claim_report_data_calculated = sha512sum(data_file)
        if (report_claim_report_data_extracted == report_claim_report_data_calculated):
            logger.info("Report claim report data: OK!")
            return True
        else:
            logger.info("Report claim report data: ERROR")
            return False
    except OSError:
        raise RuntimeError("Failed to validate report claim report data.")


def validate_evidence_claim_measurement(TMP_FILE_DIR, TYPE, OVMF):
        evidence_json = os.path.join(TMP_FILE_DIR,TMP_JSON_NAME)
        json_file = open(evidence_json)
        report_claim_measurement_extracted = json.load(json_file)[0]['Measurement']
        json_file.close()
        try:
            report_claim_measurement_calculated = subprocess.run(["python3", SEV_SNP_MEASURE_SCRIPT, "--mode", "snp", "--vcpus=4", TYPE, "--ovmf", OVMF], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if (report_claim_measurement_extracted == report_claim_measurement_calculated.stdout.strip()):
                logger.info("Report claim measurement: OK!")
                return True
            else:
                logger.info("Report claim measurement: ERROR")
                return False
        except OSError:
            raise RuntimeError("Failed to validate report cliam measurement.")

def validate_evidence_claim_measurement_mongodb(TMP_FILE_DIR, PROVIDER):
        evidence_json = os.path.join(TMP_FILE_DIR,TMP_JSON_NAME)
        json_file = open(evidence_json)
        report_claim_measurement_extracted = json.load(json_file)[0]['Measurement']
        json_file.close()
        try:
            if PROVIDER == "ovh":
                measurement_val = {"report_claim_measurement": report_claim_measurement_extracted }
            if PROVIDER == "aws":
                measurement_val = {"aws_report_claim_measurement": report_claim_measurement_extracted }
            if PROVIDER == "azure":
                measurement_val = {"azure_report_claim_measurement": report_claim_measurement_extracted }

            res_measurement = search_mongodb(measurement_val,MONGODB_API_KEY,MONGODB_COLLECTION_REF,MONGODB_DATABASE,MONGODB_CLUSTER,MONGODB_FIND_ONE_ACTION)

            if res_measurement:
                logger.info("Report claim measurement: OK!")
                return True
            else:
                logger.info("Report claim measurement: ERROR")
                return False
        except OSError:
            raise RuntimeError("Failed to validate report cliam measurement.")


def is_nonce_valid(nonce):

        try:
            
            nonceval = {"nonce": nonce }
            res = search_mongodb(nonceval,MONGODB_API_KEY,MONGODB_COLLECTION_N,MONGODB_DATABASE,MONGODB_CLUSTER,MONGODB_FIND_ONE_ACTION)
            if not res:
                dt = datetime.datetime.utcnow()
                newdate = {'createdAt':{'$date':datetime.datetime.now(datetime.timezone.utc).isoformat()}}
                nonceval.update(newdate)
                mongodb_insert(nonceval,MONGODB_API_KEY,MONGODB_COLLECTION_N,MONGODB_DATABASE,MONGODB_CLUSTER,MONGODB_INSERT_ACTION)

                return True
            else:
                return False

        except OSError:

                raise RuntimeError("Failed to validate nonce.")


def ca_sign(CA,TMP_FILE_DIR):
    try:
        csr_file = os.path.join(TMP_FILE_DIR, TMP_CSRFILE_NAME)
        csr_file_content = {
            'filedata': open(csr_file, 'rb'),
        }
        try:
            r = requests.post(CA, files=csr_file_content)
            logger.info("CSR signed by CA: OK")
            return r.text
        except requests.exceptions.RequestException as e:
            raise SystemExit(e)
    
    except ConnectionError as exc:
        raise RuntimeError('Failed to sign the CSR') from exc



def search_mongodb(inputd,key,collection,db,cluster,action):

    try:
        headers = {
            'Content-Type': 'application/json',
            'Access-Control-Request-Headers': '*',
            'api-key': key,
        }
        json_data_r = {
            'collection': collection,
            'database': db,
            'dataSource': cluster,
            'filter': inputd,
        }
        response = requests.post(
            action,
            headers = headers,
            json = json_data_r,
        )
        jsondata = response.json()
        if jsondata['document'] is not None:

            return True
        else:
            return False
    except ConnectionError as exc:

        raise RuntimeError('Failed to connect to database') from exc

def search_rego(inputd,key,collection,db,cluster,action):

    try:
        headers = {
            'Content-Type': 'application/json',
            'Access-Control-Request-Headers': '*',
            'api-key': key,
        }
        json_data_r = {
            'collection': collection,
            'database': db,
            'dataSource': cluster,
            'filter': inputd,
        }
        response = requests.post(
            action, 
            headers = headers,
            json = json_data_r,
        )
        jsondata = response.json()
        if jsondata['document'] is not None:

            return jsondata
        else:
            return None
    except ConnectionError as exc:

        raise RuntimeError('Failed to connect to database') from exc
    

def mongodb_insert(output,key,collection,db,cluster,action):
    #Insert evidence claims to mongoDB
    try:
        headers = {
            'Content-Type': 'application/json',
            'Access-Control-Request-Headers': '*',
            'api-key': key,
        }
        json_data_r = {
            'collection': collection,
            'database': db,
            'dataSource': cluster,
            'document': output,
        }
        response = requests.post(
            action,
            headers = headers,
            json = json_data_r,
        )
        logger.info(response.text)
    except ConnectionError as exc:

        raise RuntimeError('Failed to connect to database') from exc


def validate_ext(file, allowed_extensions):
    """Helper for file upload validation (extension).
    
    Args:
        file: File to validate.
        allowed_extensions: List of allowed extensions.

    Returns:
        The validated file.

    Raises:
        RuntimeError: If the file extension is not in `allowed_extensions`.
    """
    filename = file.filename
    if (filename == '' or
        '.' not in filename or
        filename.rsplit('.', 1)[1].lower() not in allowed_extensions):
        raise RuntimeError('Invalid file submission')
    return file


##################
###   ROUTES   ###
##################

@app.route('/', methods=['GET'])
def home():
    """Renders Verifier home page."""
    return render_template("index.html")


@app.route('/report', methods=['GET'])
def report():
    """Renders manual report submission page."""
    return render_template("report.html", Provider=Provider)


@app.route('/report', methods=['POST'])
def submit_report():
    """Handles manual report submission and verification."""

    # status (pass/fail) logged by helper methods
    logger.info('Manual validation request submitted')

    # common files
    provider = Provider[request.form['provider']]
    report_txt = validate_ext(request.files['report-txt'], ['txt'])
    report_bin = validate_ext(request.files['report-bin'], ['bin'])
    vcek = validate_ext(request.files['vcek'], ['pem'])

    # OVH only
    if provider == Provider.OVH:
        ark = validate_ext(request.files['ark'], ['pem'])
        ask = validate_ext(request.files['ask'], ['pem'])

    # AWS only
    if provider == Provider.AWS:
        vlek = request.files['vlek']

    # save everything to a temporary directory (cleared by gc)
    with tempfile.TemporaryDirectory() as temp_dir:
        # save files
        report_txt.save(os.path.join(temp_dir, TMP_REPORTFILE_NAME))
        report_bin.save(os.path.join(temp_dir, TMP_REPORTFILE_BIN_NAME))
        vcek.save(os.path.join(temp_dir, TMP_VCEK_NAME))

        if provider == Provider.OVH:
            ark.save(os.path.join(temp_dir, TMP_ARK_NAME))
            ask.save(os.path.join(temp_dir, TMP_ASK_NAME))

        if provider == Provider.AWS:
            vlek.save(os.path.join(temp_dir, TMP_VLEK_NAME))

        convert_to_json(os.path.join(temp_dir, TMP_REPORTFILE_NAME),
                        os.path.join(temp_dir, TMP_JSON_NAME))

        # 1: validate cert chain (OVH and AWS only)
        if provider in [Provider.AWS, Provider.OVH]:
            if not is_cert_chain_valid(temp_dir, provider.value):
                raise RuntimeError("Certificate chain validation failed")

        # 2: validate report
        if not is_evidence_valid(temp_dir):
            raise RuntimeError("Evidence validation failed")

        # 3: validate measurement
        if not validate_evidence_claim_measurement_mongodb(temp_dir, provider.value):
            raise RuntimeError("Report claim measurement validation failed")

    return "OK"


@app.route('/nonce',methods=['GET'])
def return_nonce():
    global Nonce
    nonce_time = time.time_ns()
    new_nonce = ''.join(random.choices(string.ascii_uppercase + string.digits, k=30))
    Nonce.append((new_nonce,nonce_time))
    cache.set("nonce", Nonce)

    for j,k in Nonce:
        diff = time.time_ns()-k
        if (diff > 60000000000):
            Nonce.remove((j,k))
            cache.set("nonce", Nonce)

    print(Nonce)
    x = [{
        "nonce-value": new_nonce,
        "nonce-time": nonce_time
        }]

    # convert into JSON:
    y = json.dumps(x)
    return y


# / POST - Receive tar file in a post request    
@app.route('/', methods=['POST'])
def get_file():
    suffix = datetime.datetime.now().strftime("%y%m%d_%H%M%S")
    filename = "_".join([TMP_FILE_PREFIX, suffix])
    global TMP_FILE_DIR
    global TMP_TARFILE_PATH
    global CA_ENDPOINT
    TMP_FILE_DIR = os.path.join(TMP_DIR, filename)
    TMP_TARFILE_PATH = os.path.join(TMP_FILE_DIR, TMP_TARFILE_NAME)
    
    # Change working directory
    os.mkdir(TMP_FILE_DIR)
    os.chdir(TMP_FILE_DIR)
        
    file = request.files['filedata']
    file.save(TMP_TARFILE_PATH)
   
    nonce = request.headers.get('Nonce')
    print(nonce)

    # Unzip .tar file
    tfile = tarfile.open(TMP_TARFILE_PATH)

    try:
        # Extracting file
        tfile.extractall(TMP_FILE_DIR)
        tfile.close()
        logger.info("TAR file extraction: OK")
    except OSError: 
        #logger.info("TAR file extraction: ERROR")
        raise RuntimeError("Failed to extract tar file.")

    print(cache.get("nonce"))
    for x, y in cache.get("nonce"):
        if x == nonce :
            print("nonce is passed!")
            try:
                json_file=open(os.path.join(TMP_FILE_DIR, TMP_IDFILE_NAME))
                evidence_extended_claims = json.load(json_file)
                #time and cloud provider are mandatory, the rest are optional
                evidence_extended_claim_cloud_provider = evidence_extended_claims['cloud_provider']
                if 'Architecture' in evidence_extended_claims:
                    evidence_extended_claim_architecture = evidence_extended_claims['Architecture']
                else: 
                    evidence_extended_claim_architecture = ""
                if 'Boot ID' in evidence_extended_claims:
                    evidence_extended_claim_boot_id = evidence_extended_claims['Boot ID']
                else: 
                    evidence_extended_claim_boot_id = ""
                #info_claim_firmware_ver = environment_info['Firmware Version']
                if 'geo_location' in evidence_extended_claims:
                    evidence_extended_claim_geo_location = evidence_extended_claims['geo_location']
                else: 
                    evidence_extended_claim_geo_location = ""
                if 'Hardware Model' in evidence_extended_claims:
                    evidence_extended_claim_hardware_model = evidence_extended_claims['Hardware Model']
                else: 
                    evidence_extended_claim_hardware_model = ""
                if 'Hardware Vendor' in evidence_extended_claims:
                    evidence_extended_claim_hardware_vendor = evidence_extended_claims['Hardware Vendor']
                else:
                    evidence_extended_claim_hardware_vendor = ""
                if 'Static hostname' in evidence_extended_claims:
                    evidence_extended_claim_hostname = evidence_extended_claims['Static hostname']
                else:
                    evidence_extended_claim_hostname = ""
                if 'Icon name' in evidence_extended_claims:
                    evidence_extended_claim_icon_name = evidence_extended_claims['Icon name']
                else: 
                    evidence_extended_claim_icon_name = ""
                if 'Kernel' in evidence_extended_claims:
                    evidence_extended_claim_kernel = evidence_extended_claims['Kernel']
                else: 
                    evidence_extended_claim_kernel = ""
                if 'Machine ID' in evidence_extended_claims:
                    evidence_extended_claim_machine_id = evidence_extended_claims['Machine ID']
                else: 
                    evidence_extended_claim_machine_id = ""
                if 'Operating System' in evidence_extended_claims:
                    evidence_extended_claim_operating_system = evidence_extended_claims['Operating System']
                else: 
                    evidence_extended_claim_operating_system = ""
                if 'Virtualization' in evidence_extended_claims:
                    evidence_extended_claim_virtualization = evidence_extended_claims['Virtualization']
                else:
                    evidence_extended_claim_virtualization = ""
                #info_claim_time_value = environment_info['time']
                evidence_extended_claim_time_value = evidence_extended_claims['nonce'][0]['nonce-time']
                print(evidence_extended_claim_time_value)
                if 'enclave_id' in evidence_extended_claims:
                    evidence_extended_claim_enclave_id = evidence_extended_claims['enclave_id']
                    JSON_info_claim_enclave_id = {"$oid": evidence_extended_claim_enclave_id}
                else:
                    JSON_info_claim_enclave_id = ""
                if 'hash_bin' in evidence_extended_claims:
                    evidence_extended_claim_reference_value = evidence_extended_claims['hash_bin']
                else:
                    evidence_extended_claim_reference_value = ""

                if 'CA' in evidence_extended_claims:
                    CA_ENDPOINT = evidence_extended_claims['CA']

                if 'enclave_id' in evidence_extended_claims:
                    DB_STUDIO = True
                else:
                    DB_STUDIO = False

                #Remove spaces in json keys for OPA input
                new_dict = {}

                for key, value in evidence_extended_claims.items():
                    new_dict[key.replace(" ", "")] = value

                check_data = {"input": new_dict}
                logger.info("ID File reading: OK")
                json_file.close()

            except OSError:
                #logger.info("ID File reading: ERROR")
                raise RuntimeError("Failed to read id file")

            #JSON_info_claim_enclave_id = {"$oid": evidence_extended_claim_enclave_id}

            # Get the current time as nano seconds
            nowt = time.time_ns()
            diff = nowt - int(evidence_extended_claim_time_value)

            try:    
                # Change the times to milliseconds for mongoDB
                created = int(evidence_extended_claim_time_value)/1000000
                split_string = str(created).split(".", 1)
                substring_creat = split_string[0]

                evidence_extended_claim_createdAT = {"$date":{"$numberLong": substring_creat}}
                verified = nowt/1000000
                
                split_string_verif = str(verified).split(".", 1)
                substring_verif = split_string[0]

                evidence_extended_claim_verifiedAT={"$date":{"$numberLong": substring_verif}}

            except OSError:
                raise RuntimeError("Failed to perform time calculations.")

            extra_checks = False
            # Check if diff is less than a minute in nano seconds
            if diff < 60000000000: 
                logger.info("The diff time of current time and the evidence generated time is less than a minute!")
                csr_file = os.path.join(TMP_FILE_DIR, TMP_CSRFILE_NAME)
                PATH_REPORT = os.path.join(TMP_FILE_DIR,TMP_REPORTFILE_NAME)
                PATH_OUTPUT = os.path.join(TMP_FILE_DIR,TMP_JSON_NAME)
                convert_to_json(PATH_REPORT,PATH_OUTPUT)

                if evidence_extended_claim_cloud_provider == "ovh" or evidence_extended_claim_cloud_provider == "aws":
                    chain_res = is_cert_chain_valid(TMP_FILE_DIR,evidence_extended_claim_cloud_provider)
                    pub_res = validate_evidence_claim_report_data(TMP_FILE_DIR,TMP_IDFILE_NAME)
                    extra_checks = True
                if is_evidence_valid(TMP_FILE_DIR):
                    #In case OVMF file is available for measurement use the line below otherwise use the values stored in mongodb
                    #if validate_report_claim_measurement(TMP_FILE_DIR,VCPU_TYPE,OVH_AMD_SEV_SNP_OVMF_FILE):
                    if validate_evidence_claim_measurement_mongodb(TMP_FILE_DIR,evidence_extended_claim_cloud_provider):
                        ref_val = {"report_claim_report_data": evidence_extended_claim_reference_value }
                        res_ref = search_mongodb(ref_val,MONGODB_API_KEY,MONGODB_COLLECTION_REF,MONGODB_DATABASE,MONGODB_CLUSTER,MONGODB_FIND_ONE_ACTION)
                        if res_ref:
                            if is_signature_valid(os.path.join(TMP_FILE_DIR,TMP_IDFILE_NAME), os.path.join(TMP_FILE_DIR,TMP_SIGNATURE_NAME), os.path.join(TMP_FILE_DIR,DATA_FILE)):
                                #Check OPA policy
                                #TODO: Change example.rego to encalve id name when it is inserted from dashboard
                                policy_name = {"file_name": "example.rego"}
                                policy = search_rego(policy_name,MONGODB_API_KEY,MONGODB_COLLECTION,MONGODB_DATABASE,MONGODB_CLUSTER,MONGODB_FIND_ONE_ACTION)
                                print(policy['document']['contents'])
                                if policy is not None:
                                    policy_file = open(rego_file, "w")
                                    policy_file.write(policy['document']['contents'])
                                    policy_file.close()
                                    client.update_opa_policy_fromfile(rego_file, endpoint="fromfile")

                                output = client.check_permission(input_data=check_data, policy_name="fromfile", rule_name="check")
                                if (output["result"] == True):
                                                                    
                                    if extra_checks:         
                                        if chain_res and pub_res: 
                                            # Check if the CSR exists                      
                                            if os.path.isfile(csr_file):
                                                result = ca_sign(CA_ENDPOINT,TMP_FILE_DIR)
                                                
                                            else:
                                                result = VALIDATION_SUCCESS_MSG
                                        
                                        else:
                                            result = VALIDATION_FAIL_MSG
                                    
                                    if evidence_extended_claim_cloud_provider == "azure":
                                        # Check if the CSR exists                      
                                        if os.path.isfile(csr_file):
                                            result = ca_sign(CA_ENDPOINT,TMP_FILE_DIR)
                                        else:
                                            result = VALIDATION_SUCCESS_MSG
                           
   
    #TODO: Result can be either success or the signed certificate, change this check to a better check
    if result != VALIDATION_FAIL_MSG:
        try:
            json_file_evidence=open(os.path.join(TMP_FILE_DIR, TMP_JSON_NAME))
            evidence_report = json.load(json_file_evidence)

            evidence_claim_type= evidence_report[0]['Type']
            evidence_claim_version = evidence_report[0]['Version']
            evidence_claim_Guest_SVN = evidence_report[0]['Guest SVN']
            evidence_claim_policy = evidence_report[0]['Policy']
            evidence_claim_Debugging_Allowed = evidence_report[0]['Debugging Allowed']
            evidence_claim_Migration_Agent_Allowed = evidence_report[0]['Migration Agent Allowed']
            evidence_claim_SMT_Allowed =  evidence_report[0]['SMT Allowed']
            evidence_claim_ABI_Major = evidence_report[0]['Min. ABI Major']
            evidence_claim_ABI_Minor = evidence_report[0]['Min. ABI Minor']
            evidence_claim_Family_ID = evidence_report[0]['Family ID']
            evidence_claim_Image_ID = evidence_report[0]['Image ID']
            evidence_claim_VMPL = evidence_report[0]['VMPL']
            evidence_claim_Signature_Algorithm = evidence_report[0]['Signature Algorithm']
            evidence_claim_Platform_Version= evidence_report[0]['Platform Version']
            evidence_claim_Boot_Loader_SVN= evidence_report[0]['Boot Loader SVN']
            evidence_claim_TEE_SVN = evidence_report[0]['TEE SVN']
            evidence_claim_SNP_firmware_SVN = evidence_report[0]['SNP firmware SVN']
            evidence_claim_Microcode_SVN = evidence_report[0]['Microcode SVN']
            evidence_claim_Platform_Info = evidence_report[0]['Platform Info']
            evidence_claim_SMT_Enabled = evidence_report[0]['SMT Enabled']
            evidence_claim_Author_Key_Enabled = evidence_report[0]['Author Key Enabled']
            evidence_claim_Report_Data = evidence_report[0]['Report Data']
            evidence_claim_Measurement = evidence_report[0]['Measurement']
            evidence_claim_Host_Data = evidence_report[0]['Host Data']
            evidence_claim_ID_Key_Digest = evidence_report[0]['ID Key Digest']
            evidence_claim_Author_Key_Digest = evidence_report[0]['Author Key Digest']
            evidence_claim_Report_ID = evidence_report[0]['Report ID']
            evidence_claim_Migration_Agent_Report_ID = evidence_report[0]['Migration Agent Report ID']
            evidence_claim_Reported_TCB = evidence_report[0]['Reported TCB']
            evidence_claim_Chip_ID = evidence_report[0]['Chip ID']
            evidence_claim_SignatureR = evidence_report[0]['Signature-R']
            evidence_claim_SignatureS = evidence_report[0]['Signature-S']
            json_file_evidence.close()
            
            data = {}
            if JSON_info_claim_enclave_id:
                data['enclave_id'] = JSON_info_claim_enclave_id
            if evidence_claim_Family_ID:
                data['family_id'] = evidence_claim_Family_ID
            if evidence_claim_Image_ID:
                data['image_id'] = evidence_claim_Image_ID
            if evidence_claim_Host_Data:
                data['host_data'] = evidence_claim_Host_Data
            if evidence_claim_Measurement:
                data['measurement'] = evidence_claim_Measurement
            if evidence_claim_Report_ID:
                data['report_id'] = evidence_claim_Report_ID
            if evidence_claim_Report_Data:
                data['report_data'] = evidence_claim_Report_Data
            if  evidence_claim_ID_Key_Digest:
                data['id_key_digest'] = evidence_claim_ID_Key_Digest
            if evidence_claim_Author_Key_Digest:
                data['author_key_digest'] = evidence_claim_Author_Key_Digest
            if evidence_claim_Guest_SVN:
                data['guest_svn'] = evidence_claim_Guest_SVN
            if evidence_claim_VMPL:
                data['vmpl'] = evidence_claim_VMPL
            if evidence_claim_Signature_Algorithm:
                data['signature_algorithm'] = evidence_claim_Signature_Algorithm
            if evidence_claim_policy:
                data['policy'] = evidence_claim_policy
            if evidence_claim_Platform_Version:
                data['platform_version'] = evidence_claim_Platform_Version
            if evidence_claim_Platform_Info:
                data['platform_info'] = evidence_claim_Platform_Info
            if evidence_claim_Author_Key_Enabled:
                data['author_key_enabled'] = evidence_claim_Author_Key_Enabled
            if evidence_claim_Migration_Agent_Report_ID:
                data['migration_agent_report_id'] = evidence_claim_Migration_Agent_Report_ID
            if evidence_claim_Reported_TCB:
                data['reported_tcb'] = evidence_claim_Reported_TCB
            if evidence_claim_Chip_ID:
                data['chip_id'] = evidence_claim_Chip_ID
            if evidence_claim_type:
                data['type'] = evidence_claim_type
            if evidence_claim_version:
                data['version'] = evidence_claim_version
            if evidence_extended_claim_createdAT:
                data['created_at'] = evidence_extended_claim_createdAT
            if evidence_extended_claim_createdAT:
                data['updated_at'] = evidence_extended_claim_createdAT
            if evidence_extended_claim_architecture:
                data['arch'] = evidence_extended_claim_architecture
            if evidence_extended_claim_boot_id:
                data['boot_id'] = evidence_extended_claim_boot_id
            if evidence_extended_claim_geo_location:
                data['geo_location'] = evidence_extended_claim_geo_location
            if evidence_extended_claim_hardware_model:
                data['hardware_model'] = evidence_extended_claim_hardware_model
            if evidence_extended_claim_hardware_vendor:
                data['hardware_vendor'] = evidence_extended_claim_hardware_vendor
            if evidence_extended_claim_hostname:
                data['hostname'] = evidence_extended_claim_hostname
            if evidence_extended_claim_icon_name:
                data['icone_name'] = evidence_extended_claim_icon_name
            if evidence_extended_claim_kernel:
                data['kernel'] = evidence_extended_claim_kernel
            if evidence_extended_claim_machine_id:
                data['machine_id'] = evidence_extended_claim_machine_id
            if evidence_extended_claim_operating_system:
                data['os'] = evidence_extended_claim_operating_system
            if evidence_extended_claim_virtualization:
                data['virtualization'] = evidence_extended_claim_virtualization

            outputjson = json.dumps(data)
            output = json.loads(outputjson)
            
            # Insert evidence fields to mongoDB
            if DB_STUDIO:
                mongodb_insert(output,MONGODB_API_KEY_S,MONGODB_COLLECTION_S,MONGODB_DATABASE_S,MONGODB_CLUSTER_S,MONGODB_INSERT_ACTION_S)
            else:
                mongodb_insert(output,MONGODB_API_KEY,MONGODB_COLLECTION,MONGODB_DATABASE,MONGODB_CLUSTER,MONGODB_INSERT_ACTION)
                

            # Clean /tmp direcotry
            shutil.rmtree(TMP_FILE_DIR)

        except OSError:
            raise RuntimeError("Failed to insert to database!")

    
    return result

if __name__ == "__main__":
    from waitress import serve
    app.config['MAX_CONTENT_LENGTH'] = 5 * 1000 * 1000 # 5MB
    serve(app, host="0.0.0.0", port=8080)
