import logging

from pyasn1.codec.der import encoder
from pyasn1 import error

from pkcs7.asn1_models.oid import *
from pkcs7.digest import *
import pkcs7.verifier
import pkcs7.rsa_verifier

from cert_finder import *

SHA1RSA_NAME = "SHA1/RSA"
SHA256RSA_NAME = "SHA256/RSA"

def verify_certificate(cert, trusted_ca_certs):
    if len(trusted_ca_certs) == 0:
        raise Exception("No trusted certificate found")
    # extract tbs certificate
    tbs = cert.getComponentByName("tbsCertificate")
    # encode tbs into der
    tbs_encoded = encoder.encode(tbs)
    # hash tbs with used digest algorithm
    sig_alg = str(cert.getComponentByName("signatureAlgorithm"))
    sa_name = oid_map[sig_alg]
    
    if (sa_name == SHA1RSA_NAME):
        calculated_digest = calculate_digest(tbs_encoded, SHA1_NAME)
    elif (sa_name == SHA256RSA_NAME):
        calculated_digest = calculate_digest(tbs_encoded, SHA256_NAME)
    else:
        raise Exception("Unknown certificate signature algorithm: %s" % sig_alg)

    # look for signing certificate among certificates
    issuer = str(tbs.getComponentByName("issuer"))    
    signing_cert = find_cert_by_subject(issuer, trusted_ca_certs)    
    if not signing_cert:
        msg = "No certificate found for %s" % issuer
        logging.error(msg)
        raise Exception(msg)
    # extract public key from matching certificate
    alg, key_material = pkcs7.verifier._get_key_material(signing_cert)
    # decrypt signature in explored certificate
    signature = cert.getComponentByName("signatureValue").toOctets()
    # compare calculated hash and decrypted signature
    res = pkcs7.rsa_verifier.rsa_verify(calculated_digest, signature, key_material)
        
    return res
   