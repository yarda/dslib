'''
Created on Dec 9, 2009

Verifying RSA signatures.
Uses parts ofcode from  http://stuvel.eu/rsa
'''
import logging

import types, base64
import asn1_models

from asn1_models.digestInfo import *

from pyasn1.codec.der import decoder
from pyasn1 import error

def bytes2int(bytes):
    """Converts a list of bytes or a string to an integer

    >>> (128*256 + 64)*256 + + 15
    8405007
    >>> l = [128, 64, 15]
    >>> bytes2int(l)
    8405007
    """

    if not (type(bytes) is types.ListType or type(bytes) is types.StringType):
        raise TypeError("You must pass a string or a list")

    # Convert byte stream to integer
    integer = 0
    for byte in bytes:
        integer *= 256
        if type(byte) is types.StringType: byte = ord(byte)
        integer += byte

    return integer

def int2bytes(number):
    """Converts a number to a string of bytes
    
    >>> bytes2int(int2bytes(123456789))
    123456789
    """

    if not (type(number) is types.LongType or type(number) is types.IntType):
        raise TypeError("You must pass a long or an int")

    string = ""

    while number > 0:
        string = "%s%s" % (chr(number & 0xFF), string)
        number /= 256
    
    return string

def _fast_exponentiation(a, p, n):
    """Calculates r = a^p mod n
    """
    result = a % n
    remainders = []
    while p != 1:
        remainders.append(p & 1)
        p = p >> 1
    while remainders:
        rem = remainders.pop()
        result = ((a ** rem) * result ** 2) % n
    return result


def _get_hash_from_DER(pkcs1_5_DER_bytes):
    '''
    Decodes DER and returns content of hash component 
    (the hash of the original document)
    '''
    di = DigestInfo()
    digestInfo = decoder.decode(pkcs1_5_DER_bytes, asn1Spec = di)[0]
    hash = digestInfo.getComponentByName("digest")._value
    return hash
    

def _extract_hash_from_decoded_sig(pkcs1_5_encoded_bytes):
    '''
    Returns DER encoded bytes from signature.
    Signature is created according to EMSA-PKCS1-v1_5 :
    shortly: first byte 0x0 | 0x1 | 0*FF .... 0*FF | 0x00 | msg
    msg is DER encoded DigestInfo, which contains hash alg specification
    and the hash itself
    '''
    idx = 0
    for byte in pkcs1_5_encoded_bytes:
        if ord(byte) == 0x01 or ord(byte) == 0xff:
            idx += 1
            continue
        if ord(byte) == 0x00:
            idx += 1
            break
    decoded_bytes = pkcs1_5_encoded_bytes[idx:]
    
    return decoded_bytes

def _rsa_decode(encoded, pub_key):
    """
    "Decrypts" RSA signature (applies public exponent modulo n)
    """    
    _enc = bytes2int(encoded)
    _mod = bytes2int(pub_key["mod"])
    _exp = pub_key["exp"]
    
    rr = _fast_exponentiation(_enc, _exp, _mod)
        
    _decrypt = int2bytes(rr)    
    
    return _decrypt
   

def _get_hash_from_signature(signature, pub_key):
    """
    Decodes (not decrypts!) RSA signature and returns the hash, which was signed
    """
    # decrypt the signature
    decrypted = _rsa_decode(signature, pub_key)  
    # get the DER encoded (DigestInfo component) bytes from the decrypted signature
    decoded_bytes = _extract_hash_from_decoded_sig(decrypted)
    #show_bytes(hash)    
    # get the bytes of the hash
    hash = _get_hash_from_DER(decoded_bytes)
    
    logging.debug("Hash from decoded signature:")
    logging.debug(base64.b64encode(hash))
        
    return hash


def rsa_verify(data_digest, signature, pub_key):    
    '''
    Verifies data digest against signature with public key
    '''
    hash_signature = _get_hash_from_signature(signature, pub_key)
    if (data_digest == hash_signature):
        logging.debug("Signature OK")
        return True
    else:
        logging.debug("Verification failed")
        return False