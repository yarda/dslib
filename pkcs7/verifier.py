'''
Created on Dec 9, 2009

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

from digest import *

from certs.cert_finder import *

MESSAGE_DIGEST_KEY = "1.2.840.113549.1.9.4"

def _prepare_auth_attributes_to_digest(auth_attributes_instance):
    """
    Prepares autheticated attributes field to digesting process.
    Replaces implicit tag with SET tag.
    """
    implicit_tag = chr(0xa0)    # implicit tag of the set of authAtt
    set_tag = chr(0x31)         # tag of the ASN type "set"
    
    # encode authentcatdAttributes instance into DER
    attrs = encoder.encode(auth_attributes_instance)
    # remove implicit tag
    if (attrs[0] == implicit_tag):
        attrs = attrs.lstrip(implicit_tag)
        attrs = str(set_tag) + attrs
    
    return attrs

  
def _get_key_material(certificate):
    """
    Extracts public ket material and alg. name from certificate.
    Certificate is pyasn1 object Certificate
    """
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
    '''
    Extracts digest algorithm from signerInfo component.
    Returns algorithm's name pr raises Exception
    '''
    digest_alg = str(signer_info.getComponentByName("digestAlg"))
    result = None
    if oid_map.has_key(digest_alg):
        result = oid_map[digest_alg]
    if result is None:
        logging.error("Unknown digest algorithm: %s" % digest_alg)
        raise Exception("Unrecognized digest algorithm")
    
    return result

def _verify_data(data, certificates, signer_infos):
    result = False
    for signer_info in signer_infos:
        id = signer_info.getComponentByName("issuerAndSerialNum").\
                        getComponentByName("serialNumber")._value
        cert = find_certificate_by_serial(id, certificates)
        
        if cert is None:
            raise Exception("No certificate found for signer %d" % id)
        
        sig_algorithm, key_material = _get_key_material(cert) 
        digest_alg = _get_digest_algorithm(signer_info)
                
        auth_attributes = signer_info.getComponentByName("authAttributes")            
        
        if auth_attributes is None:
            data_to_verify = data
        else:
            for attr in auth_attributes:
                type = str(attr.getComponentByName("type"))
                if (type == MESSAGE_DIGEST_KEY):
                    value = str(attr.getComponentByName("value"))
                    calculated = calculate_digest(data, digest_alg)
                    if (value != calculated):
                        raise Exception("Digest in authenticated attributes differs\
                                        from the digest of message!")
            data_to_verify = _prepare_auth_attributes_to_digest(auth_attributes)
    
        data_to_verify = calculate_digest(data_to_verify, digest_alg)    
        #print base64.b64encode(data_to_verify)    
        signature = signer_info.getComponentByName("signature")._value
    
        if (sig_algorithm == RSA_NAME):
            r = rsa_verify(data_to_verify, signature, key_material)
            if not r:
                logging.debug("Verification of signature with id %d failed"%id)
                return False
            else:
                result = True
        # Note: here we should not have unknown signing algorithm
        # .....only RSA for now
    return result
    
def verify_msg(decoded_pkcs7_msg):
    '''
    Method verifies decoded message (built from pyasn1 objects)
    Input is decoded pkcs7 message.
    '''
    message_content = decoded_pkcs7_msg.getComponentByName("content")
    
    signer_infos = message_content.getComponentByName("signerInfos")    
    certificates = message_content.getComponentByName("certificates")    
    msg = message_content.\
                    getComponentByName("content").\
                        getComponentByName("signed_content").getContentValue()
    
    return _verify_data(msg, certificates, signer_infos)
    

def verify_qts(asn1_qts):
    qts_content = asn1_qts.getComponentByName("content")
    
    signer_infos = qts_content.getComponentByName("signerInfos")
    certificates = qts_content.getComponentByName("certificates")
    msg = qts_content.\
                    getComponentByName("encapsulatedContentInfo").\
                        getComponentByName("eContent")._value
    
    return _verify_data(msg, certificates, signer_infos)
    