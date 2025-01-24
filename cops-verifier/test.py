import unittest
import sys
import os
from unittest.mock import Mock

#sys.path.append('..')
from server import is_cert_chain_valid, is_evidence_valid, sha512sum, validate_evidence_claim_report_data,validate_evidence_claim_measurement,is_nonce_valid,is_signature_valid, mongodb_insert,search_mongodb,ca_sign,validate_evidence_claim_measurement_mongodb
from parser import convert_to_json
from dotenv import load_dotenv

load_dotenv()

directory = os.getcwd()
work_dir = os.path.join(directory, "test/test-report")
work_aws_dir = os.path.join(directory, "test/aws_test")
wrong_dir = os.path.join(directory, "test/test-report-wrong")
malformed_dir = os.path.join(directory, "test/malformed-test")

DATA ="public_key.pem"
report = os.path.join(work_dir,"report.txt")
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


# CSPs OVMFs configuration files
OVH_AMD_SEV_SNP_OVMF_FILE = os.path.join(directory, "OVH/OVMF_CODE.fd")
AWS_SNP_OVMF_FILE = os.path.join(directory, "AWS/ovmf_img.fd")

VCPU_TYPE = "--vcpu-type=EPYC-v4"
VMM_TYPE = "--vmm-type=ec2"

class TestServer(unittest.TestCase):
    

    def test_value(self):
        res = is_cert_chain_valid(work_dir,'ovh')
        self.assertEqual(res, True)
        print("------cert chain validated is passed!------\n")
        
        #res_aws = is_cert_chain_valid(work_aws_dir,'aws')
        #self.assertEqual(res_aws, True)
        #print("------AWS cert chain validated is passed!------\n")


        report_res = is_evidence_valid(work_dir)
        self.assertEqual(report_res, True)
        print("------report validated is passed!------\n")
        
        
        pubkey_res = validate_evidence_claim_report_data(work_dir, DATA)
        self.assertEqual(pubkey_res, True)
        print("------pubkey validation is passed!------\n")
        
        measure_res = validate_evidence_claim_measurement(work_dir, VCPU_TYPE, OVH_AMD_SEV_SNP_OVMF_FILE)
        self.assertEqual(measure_res, True)
        print("------Measurement is passed!------\n")

        measure_res = validate_evidence_claim_measurement_mongodb(work_dir, 'ovh')
        self.assertEqual(measure_res, True)
        print("------Measurement mongodb is passed!------\n")

        signature_res = is_signature_valid(os.path.join(work_dir,'id.txt'), os.path.join(work_dir,'signature.sig'), os.path.join(work_dir,'public_key.pem'))
        self.assertEqual(signature_res, True)
        print("------Signature is passed!------\n")


    def test_wrong_values(self):

        neg = is_cert_chain_valid(wrong_dir,'ovh')
        self.assertEqual(neg, False)
        print("------cert chain NOT validated is passed!------\n")

        report_neg = is_evidence_valid(wrong_dir)
        self.assertEqual(report_neg, False)
        print("------Test evidence NOT validated is passed!------\n")
        
        pubkey_neg = validate_evidence_claim_report_data(wrong_dir, DATA)
        self.assertEqual(pubkey_neg, False)
        print("------Test pubkey validation NOT passed!------\n")
        
        measure_neg = validate_evidence_claim_measurement(wrong_dir, VCPU_TYPE, OVH_AMD_SEV_SNP_OVMF_FILE)
        self.assertEqual(measure_neg, False)
        print("------Test Measurement NOT passed!------\n")

        measure_res = validate_evidence_claim_measurement_mongodb(wrong_dir, 'ovh')
        self.assertEqual(measure_res, False)
        print("------Measurement mongodb NOT passed!------\n")


        nonceval = {"nonce": "458hjfse345agflgh43" }
        nonce_res = is_nonce_valid(nonceval)
        self.assertEqual(nonce_res, False)
        print("------Nonce NOT passed is OK!------\n")
        
        testvalue = {"test": "akdslkldskflds" }
        search_res = search_mongodb(testvalue,MONGODB_API_KEY,MONGODB_COLLECTION_N,MONGODB_DATABASE,MONGODB_CLUSTER,MONGODB_FIND_ONE_ACTION)
        self.assertEqual(search_res, False)
        print("------Search NOT passed is OK!------\n")
        
        with self.assertRaises(Exception):
            is_signature_valid(os.path.join(wrong_dir,'id.txt'), os.path.join(wrong_dir,'signature.sig'), os.path.join(wrong_dir,'public_key.pem'))
            print("------Signature NOT passed!------\n")


    def test_malformed_values(self):

        mal = is_cert_chain_valid(malformed_dir,'ovh')
        self.assertEqual(mal, False)
        print("------cert chain malformed NOT passed!------\n")

        evidence_mal = is_evidence_valid(malformed_dir)
        self.assertEqual(evidence_mal, False)
        print("------report malformed NOT passed!------\n")
        
        with self.assertRaises(Exception):
            validate_evidence_claim_report_data(malformed_dir, DATA)
            print("------pubkey malformed NOT passed!------\n")


        testvalue = {"This is malformed" }
        with self.assertRaises(Exception):
            search_res = search_mongodb(testvalue,MONGODB_API_KEY,MONGODB_COLLECTION_N,MONGODB_DATABASE,MONGODB_CLUSTER,MONGODB_FIND_ONE_ACTION)
            print("------Search malformed NOT passed is OK!------\n")
        
        with self.assertRaises(Exception):
            is_signature_valid(os.path.join(malformed_dir,'id.txt'), os.path.join(malformed_dir,'signature.sig'), os.path.join(malformed_dir,'public_key.pem'))
            print("------Signature malformed NOT passed!------\n")


    def test_inputerror(self):
        sha512sum(os.path.join(directory,"test/test-report/report.txt"))
        ca_sign("https://ca.cops.io/",work_dir)

    def test_no_output(self):
        test_data = {"test":"This is for unit testing!"}
        Mock().mongodb_insert(test_data,MONGODB_API_KEY_S,MONGODB_COLLECTION_S,MONGODB_DATABASE_S,MONGODB_CLUSTER_S,MONGODB_INSERT_ACTION_S)
        Mock().convert_to_json(report)

if __name__=='__main__':
	unittest.main()
