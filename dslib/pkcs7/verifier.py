'''
Created on Dec 9, 2009

@author: mdioszegi
'''
import logging

import sys, string, base64
from pyasn1.type import tag,namedtype,namedval,univ,constraint,char,useful
from pyasn1.codec.der import decoder, encoder
from pyasn1 import error

import pkcs7.asn1_models

from asn1_models.X509certificate import *
from asn1_models.pkcsSignedData import *
from asn1_models.RSA import *
from asn1_models.digestInfo import *

from rsa_verifier import *

from debug import *

from asn1_models.tools import *

from asn1_models.oid import *

import hashlib

RSA_NAME = "RSA"
SHA1_NAME = "SHA-1"


def _calculate_digest(data, alg):    
    digest_alg = None
    if (alg == SHA1_NAME):
        digest_alg = hashlib.sha1() 
           
    if digest_alg is None:
        logging.error("Unknown digest algorithm : %s" % alg)
    
    digest_alg.update(data)   
    dg = digest_alg.digest()       
    
    logging.debug("Calculated hash from incoming file (digesting autheticatedAttributes):")
    logging.debug(base64.b64encode(dg))
    return dg


def _prepare_auth_attributes_to_digest(auth_attributes_instance):
    implicit_tag = chr(0xa0)    # implicit tag of the set of authAtt
    set_tag = chr(0x31)         # tag of the ASN type "set"
    
    # encode authentcatdAttributes instance into DER
    attrs = encoder.encode(auth_attributes_instance)
    # remove implicit tag
    if (attrs[0] == implicit_tag):
        attrs = attrs.lstrip(implicit_tag)
        attrs = str(set_tag) + attrs
    
    return attrs

"""
Extracts public ket material and alg. name from certificate.
Certificate is pyasn1 object Certificate
"""  
def _get_key_material(certificate):
    pubKey = certificate.getComponentByName("tbsCertificate").\
            getComponentByName("subjectPublicKeyInfo").\
                getComponentByName("subjectPublicKey")
    
    signing_alg = str(certificate.getComponentByName("tbsCertificate").\
            getComponentByName("subjectPublicKeyInfo").\
                getComponentByName("algorithm"))
    
    algorithm = None
    if oid_map.has_key(signing_alg):
        algorithm = oid_map[signing_alg]
    
    logging.debug("Extracting key material form public key:")
    
    if (algorithm is None):
        logging.error("Signing algorithm is: unknown OID: %s" % signing_alg)
        raise Exception("Unrecognized signing algorithm")
    else:
        logging.debug("Signing algorithm is: %s" % algorithm)
    
    key_material = None
    if (algorithm == RSA_NAME):
        key_material = get_RSA_pub_key_material(pubKey)
    
    return algorithm, key_material

def _get_digest_algorithm(signer_info):
    digest_alg = str(signer_info.getComponentByName("digestAlg"))
    result = None
    if oid_map.has_key(digest_alg):
        result = oid_map[digest_alg]
    if result is None:
        logging.error("Unknown digest algorithm: %s" % digest_alg)
        raise Exception("Unrecognized digest algorithm")
    
    return result
    
    
'''
input is a tuple (message, signer_information)
'''
def verify_msg(decoded_pkcs7_msg):
    message = decoded_pkcs7_msg[0]
    signer_information = decoded_pkcs7_msg[1]
    
    cert = message.getComponentByName("certificate")
    
    sig_algorithm, key_material = _get_key_material(cert) 
    
    msg = message.getComponentByName("signedData").\
                    getComponentByName("content").\
                        getComponentByName("signed_content").getContentValue()
                    
    auth_attributes = signer_information.getComponentByPosition(0).\
                        getComponentByName("authAttributes")
    
    
    digest_alg = _get_digest_algorithm(signer_information.getComponentByPosition(0))
    
    if auth_attributes is None:
        data_to_verify = msg
    else:
        data_to_verify = _prepare_auth_attributes_to_digest(auth_attributes)
    
    #show_bytes(data_to_verify)
    
    data_to_verify = _calculate_digest(data_to_verify, digest_alg)
    
    #print base64.b64encode(data_to_verify)
    
    signature = signer_information.getComponentByPosition(0).\
            getComponentByName("signature")._value
    
    
    if (sig_algorithm == RSA_NAME):
        result = rsa_verify(data_to_verify, signature, key_material)
    # Note: here we should not have unknown signing algorithm
    # .....only RSA for now
    
    return result