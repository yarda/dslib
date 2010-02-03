
#*    dslib - Python library for Datove schranky
#*    Copyright (C) 2009-2010  CZ.NIC, z.s.p.o. (http://www.nic.cz)
#*
#*    This library is free software; you can redistribute it and/or
#*    modify it under the terms of the GNU Library General Public
#*    License as published by the Free Software Foundation; either
#*    version 2 of the License, or (at your option) any later version.
#*
#*    This library is distributed in the hope that it will be useful,
#*    but WITHOUT ANY WARRANTY; without even the implied warranty of
#*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#*    Library General Public License for more details.
#*
#*    You should have received a copy of the GNU Library General Public
#*    License along with this library; if not, write to the Free
#*    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#*
'''
Verification of CRL.
CRL is downloaded from distribution point specified in
the certificate extension => CRL is signed with this certificate.
'''
import logging
logger = logging.getLogger("certs.crl_verifier")


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
        logger.error("Unknown certificate signature algorithm: %s" % sig_alg)
        raise Exception("Unknown certificate signature algorithm: %s" % sig_alg)
    
    alg, key_material = pkcs7.verifier._get_key_material(certificate)
    
    signature = crl.getComponentByName("signatureValue").toOctets()
        
    # compare calculated hash and decrypted signature
    try:
        res = pkcs7.rsa_verifier.rsa_verify(calculated_digest, signature, key_material)
    except:
        logger.error("RSA verification of CRL failed")
        return False
    
    return res