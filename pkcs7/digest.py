import hashlib
import logging
import base64

RSA_NAME = "RSA"
SHA1_NAME = "SHA-1"
SHA256_NAME = "SHA-256"
SHA384_NAME = "SHA-384"
SHA512_NAME = "SHA-512"

def calculate_digest(data, alg):    
    '''
    Calculates digest according to algorithm
    '''
    digest_alg = None
    if (alg == SHA1_NAME):
        digest_alg = hashlib.sha1() 
    
    if (alg == SHA256_NAME):
        digest_alg = hashlib.sha256()
    
    if (alg == SHA384_NAME):
        digest_alg = hashlib.sha384()
    
    if (alg == SHA512_NAME):
        digest_alg = hashlib.sha512()
    
    if digest_alg is None:
        logging.error("Unknown digest algorithm : %s" % alg)
        return None
    
    digest_alg.update(data)   
    dg = digest_alg.digest()       
    
    logging.debug("Calculated hash from incoming file (digesting autheticatedAttributes):")
    logging.debug(base64.b64encode(dg))
    return dg