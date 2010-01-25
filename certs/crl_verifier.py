'''
Verification of CRL.
CRL is downloaded from distribution point specified in
the certificate extension => CRL is signed with this certificate.
'''
import logging

from pyasn1.codec.der import encoder
from pyasn1 import error

from pkcs7.asn1_models.oid import *
from pkcs7.digest import *
import pkcs7.verifier
import pkcs7.rsa_verifier

from constants import *

def verify_crl(crl, certificate):
    '''
    Checks if the signature of CRL is OK.
    '''
    tbs = crl.getComponentByName("tbsCertList")
    # bad idea - encoding too time consuming
    # try to keep the encoded version of tbsCertlist
    tbs_encoded = encoder.encode(tbs)
    
    sig_alg = str(crl.getComponentByName("signatureAlgorithm"))
    sa_name = oid_map[sig_alg]
    
    if (sa_name == SHA1RSA_NAME):
        calculated_digest = calculate_digest(tbs_encoded, SHA1_NAME)
    elif (sa_name == SHA256RSA_NAME):
        calculated_digest = calculate_digest(tbs_encoded, SHA256_NAME)
    else:
        raise Exception("Unknown certificate signature algorithm: %s" % sig_alg)
    
    alg, key_material = pkcs7.verifier._get_key_material(certificate)
    
    signature = crl.getComponentByName("signatureValue").toOctets()
    
    # problem - very weird RSA signature format -looks like it 
    # does not match anything from http://tools.ietf.org/html/rfc3447 
    
    # compare calculated hash and decrypted signature
    try:
        res = pkcs7.rsa_verifier.rsa_verify(calculated_digest, signature, key_material)
    except:
        return False
    
    return res