'''
Module for certificate verification.
'''
import logging
logger = logging.getLogger("certs.cert_verifier")
logger.setLevel(logging.DEBUG)

from pyasn1.codec.der import encoder
from pyasn1 import error

from pkcs7.asn1_models.oid import *
from pkcs7.digest import *
import pkcs7.verifier
import pkcs7.rsa_verifier

from cert_finder import *

import time

from constants import *

import certs.crl_store as crl_store


def _verify_date(certificate): 
    '''
    Checks date boundaries in the certificate (actual time must be inside). 
    '''
    tbs = certificate.getComponentByName("tbsCertificate")
    validity = tbs.getComponentByName("validity")
    start = validity.getComponentByName("notBefore").getComponentByPosition(0)._value
    
    format = '%y%m%d%H%M%SZ'
    start_time = time.strptime(start, format)
    end = validity.getComponentByName("notAfter").getComponentByPosition(0)._value
    end_time = time.strptime(end, format)
    now = time.gmtime()    
    
    if (start_time < now) and (end_time > now):    
        return True
    return False

def _check_crl(checked_cert, issuer_cert):
    '''
    Checks if the certificate is not revoked by its issuer.
    '''    
    # extract CDT from issuer certificate
    # find issuer and its cdt in cache
    # add them eventually to cache
    # check the issuer and sn of checked cert if they are in the cache
    # if yes, return False
    
    # serial number of checked certificate
    cert_sn = checked_cert.getComponentByName("tbsCertificate").\
                            getComponentByName("serialNumber")._value
    # get the CRL cache
    crl_cache = crl_store.CRL_cache_manager.get_cache()
    # get the name of issuer of CRL
    issuer_name = str(checked_cert.getComponentByName("tbsCertificate").\
                          getComponentByName("issuer"))
    from pkcs7_models import X509Certificate
    # extract CDPs from checked certificate
    c = X509Certificate(checked_cert)
    dist_points = crl_store.extract_crl_distpoints(c)
    # look for CRL issuer in the cache
    iss = crl_cache.get_issuer(issuer_name)
    if iss is None:
      # add new CRL issuer
      added = crl_cache.add_issuer(issuer_name)
      # add issuer's CDPs to issuer
      for dp in dist_points:
        added_dp = added.add_dist_point(dp)
        if added_dp is not None:
          crl_cache.changed = True
          # initialize added CDP
          added.init_dist_point(dp, verification=issuer_cert)
    else:
      # if CRL issuer exists, only refresh his CDPs
      for dp in iss.dist_points:
        added_certs = iss.refresh_dist_point(dp.url, verification=issuer_cert)
        if iss.changed:
          crl_cache.changed = True
    # check the CRL cache for the certificate issuer and serial number
    is_revoked = crl_cache.is_certificate_revoked(issuer_name, cert_sn)
    # if it is not revoked, checked certificate is ok
    if is_revoked is False:
      return True
    else:
      return False
    
    

def verify_certificate(cert, trusted_ca_certs, check_crl=False):
    '''
    Verifies the certificate - checks signature and date validity.
    '''
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
        logger.error(msg)
        raise Exception(msg)
    # if we want to download and check the crl of issuing authority 
    # for certificate being checked
    if check_crl:
        is_ok = _check_crl(cert, signing_cert)
        csn = tbs.getComponentByName("serialNumber")._value
        if not is_ok:
          logger.error("Certificate %d of %s is revoked" % (csn,issuer))
        else:
          logger.info("Certificate %d of %s is not on CRL" % (csn,issuer))
    # check validity of certificate - validity period etc.
    if not _verify_date(signing_cert):
        msg = "Signing certificate out of validity period"
        logger.error(msg)
        raise Exception(msg)
    # extract public key from matching certificate
    alg, key_material = pkcs7.verifier._get_key_material(signing_cert)
    # decrypt signature in explored certificate
    signature = cert.getComponentByName("signatureValue").toOctets()    
    # compare calculated hash and decrypted signature
    res = pkcs7.rsa_verifier.rsa_verify(calculated_digest, signature, key_material)
        
    return res
   