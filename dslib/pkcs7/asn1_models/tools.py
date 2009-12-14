'''
Created on Dec 3, 2009

@author: mdioszegi
'''

from RSA import *
from pyasn1.codec.der import decoder
from pyasn1 import error

"""
Converts OID tuple to OID string
"""
def tuple_to_OID(tuple):
    l = len(tuple)
    buf = ''
    for idx in xrange(l):
        if (idx < l-1):
            buf += str(tuple[idx]) + '.'
        else:
            buf += str(tuple[idx])
    return buf



'''
Extracts modulus and public exponent from 
ASN1 bitstring component subjectPublicKey
'''
def get_RSA_pub_key_material(subjectPublicKeyAsn1):
    # create template for decoder
    rsa_key = RsaPubKey()
    # convert ASN1 subjectPublicKey component from BITSTRING to octets
    pubkey = subjectPublicKeyAsn1.toOctets()
    
    key = decoder.decode(pubkey, asn1Spec=rsa_key)[0]
    
    mod = key.getComponentByName("modulus")._value
    exp = key.getComponentByName("exp")._value
    
    return {'mod': mod, 'exp': exp}