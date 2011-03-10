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
Created on Dec 4, 2009

Sandbox unstable module.
'''
import logging

logging.basicConfig()

logger = logging.getLogger('pkcs_test')

#logger.setLevel(logging.DEBUG)

import pkcs7
import pkcs7.pkcs7_decoder
import pkcs7.verifier
import pkcs7.asn1_models.oid

import os

from pkcs7.asn1_models.TST_info import *
from pkcs7.asn1_models.pkcs_signed_data import *

from pyasn1.type import tag,namedtype,namedval,univ,constraint,char,useful
from pyasn1.codec.der import decoder, encoder
from pyasn1 import error

import models

from properties.properties import Properties as props

def parse_url( crl_url):
    url = crl_url
    if url.startswith("http://"):
        url = url[7:]
    slash = url.find('/')
    hostname = url[:slash]
    path = url[slash:]
    return hostname, path

from certs.cert_verifier import *
from certs.cert_loader import *
import httplib
from pkcs7.asn1_models.crl import *

def download_crl(url):
    hostname, path = parse_url(url)
    #path = self.__clean_path(path)
    con = httplib.HTTPConnection(hostname)
    con.request("GET", path)
    resp = con.getresponse()
    c = resp.read()
    return c

from pyasn1.codec.der import decoder
from pyasn1 import error

from pkcs7.asn1_models.crl import * 

def decode_crl(der_data):
    crl = decoder.decode(der_data, asn1Spec=RevCertificateList())[0]
    return crl

def getTimestampFromQts(dmQTimestamp):
    '''
    Extracts information from dmQTimestamp element. Decodes PKCS data
    of timestamp and verifies the signed content of the docment.
    Returns result of verification and Timestamp Token Info object.
    User has to check the message imprint value, it should be the same
    as the content of dmHash element
    '''
    import base64
    ts = base64.b64decode(dmQTimestamp)

    qts = pkcs7.pkcs7_decoder.decode_qts(ts)
    vr = pkcs7.verifier.verify_qts(qts)
    
    if vr:
        logger.info("QTimeStamp verified")
    else:
        logger.info("QTimeStamp verification failed")
    
    tstData = qts.getComponentByName("content").getComponentByName("encapsulatedContentInfo").getComponentByName("eContent")._value
    
    tstinfo = pkcs7.pkcs7_decoder.decode_tst(tstData)
    
    t = models.TimeStampToken(tstinfo)
    return vr, t


def v_crl(cert):
  import certs.cert_loader as l
  certs = l.load_certificates_from_dir("trusted_certificates")
  # crl
  dl = download_crl("http://www.postsignum.cz/crl/psqualifiedca.crl")
  crl = decode_crl(dl)
  rev_certs = crl.getComponentByName("tbsCertList").getComponentByName("revokedCertificates")._value
  
  import certs.crl_verifier as v
  
  r = v.verify_crl(crl, certs[2])
  
  import fast_rev_cert_parser as p
  csn = p.parse_all(rev_certs)
  logger.info("Numbers = %d" % len(csn))  
  return r


#import properties.properties as p
#print p.Properties.VERIFY_MESSAGE
#p.Properties.load_from_file("properties/security.properties")

'''
subory v test_msgs obsahuju binarnu formu prijatych podpisanych sprav
t.j. odpoved na getSignedXXX obsahovala element dmSignature. Jeho obsah
je base64 dekodovany a zapisany do danych suborov (podpisana prijata a odoslana 
sprava, podpisana dorucenka).
'''

from certs.cert_manager import CertificateManager

CertificateManager.read_trusted_certificates_from_dir("trusted_certificates")
#f = open(os.path.join("test_msgs","signedSentMessage"), "rb")
#f = open("test_msgs/signedReceivedMessage", "r")
f = open("test_msgs/srm2", "r")
#f = open("test_msgs/sigDeliveryInfo", "r")
coded = f.read()

decoded_msg = pkcs7.pkcs7_decoder.decode_msg(coded)
verification_result = pkcs7.verifier.verify_msg(decoded_msg)

#print decoded_msg.getComponentByName("signedData")

if verification_result:
    logger.info("Message verified - ok")
else:
    logger.warning("Verification of pkcs7 message failed")

pkcs_data = models.PKCS7_data(decoded_msg)

msg = pkcs_data.message
     
import sudsds.sax.parser as p
parser = p.Parser()
document = parser.parse(string = msg)

'''
messageImprint je totozny s dmHashom, ten je hash z elementu dmDm
'''


'''
# ak sa jedna o podpisanu dorucenku        
m = models.Message(xml_document = document, 
                   path_to_content=models.Message.SIG_DELIVERY_CONTENT_PATH)
'''

#'''
# ak sa jedna o podpisanu spravu
m = models.Message(xml_document = document, 
                   path_to_content=models.Message.SIG_MESSAGE_CONTENT_PATH)
#'''

m.pkcs7_data = pkcs_data

# mala ukazka
e_alg_code = m.pkcs7_data.signer_infos[0].encrypt_algorithm
logger.info("Msg encryption alg: %s" % pkcs7.asn1_models.oid.oid_map[e_alg_code])


cert = decoded_msg.getComponentByName("content").getComponentByName("certificates")[0]
trusted = load_certificates_from_dir("trusted_certificates")

#v_crl(cert)


#certificate_verified = verify_certificate(cert, trusted, check_crl=True, force_crl_download= props.FORCE_CRL_DOWNLOAD)

#logger.info("Certificate verified?..... %s" % certificate_verified)

# daju sa overit aj samotne doveryhodne certifikaty voci sebe
#is_ok = verify_certificate(trusted[0], trusted, check_crl=True)


import pkcs7.tstamp_helper

qts_verified, tstinfo = pkcs7.tstamp_helper.parse_qts(m.dmQTimestamp)

if qts_verified:
    imprint = tstinfo.msgImprint.imprint
    imprint = base64.b64encode(imprint)
    
    hashFromMsg = m.dmHash.value
    
    if hashFromMsg == imprint:
        logger.info("Message imprint in timestamp and dmHash value are the same")
    else:
        logger.warning("Message imprint in timestamp and dmHash value differ!")
        
    genTime = tstinfo.genTime
    logger.info("Timestamp created: %s" % genTime)
    logger.info("TS authority: %s" % tstinfo.tsa)
    logger.info("TS serial: %s" % tstinfo.serialNum)


# try something from crls
import certs.crl_store as crl_store

certificate = m.pkcs7_data.certificates[0]
issuer = str(certificate.tbsCertificate.issuer)

dps = crl_store.extract_crl_distpoints(certificate)

url = dps[0]
# find certificate issued for issuer 
# in case of DS, certificate for PSQCA issued by PSROOTCA
import certs.cert_finder as finder
cert = finder.find_cert_by_subject(issuer, trusted)

crl_cache = crl_store.CRL_cache_manager.get_cache()
# should return existing instance
#crl_cache = None#crl_store.CRL_cache_manager.get_cache()
#'''
if crl_cache is None:
    logger.info("CRL cache not found locally, downloading...")
    crl_cache = crl_store.CRL_cache()
    added = crl_cache.add_issuer(issuer)
    added.add_dist_point(url)
    added.init_dist_point(url, verification=cert)
    logger.info("Refreshing distribution point...")
    added.refresh_dist_point(url, verification=cert, force_download=props.FORCE_CRL_DOWNLOAD)
    logger.info("Done")
else:
    logger.info("CRL cache read from local store")
    i = crl_cache.get_issuer(issuer)
    logger.info("Refreshing distribution point...")
    i.refresh_dist_point(url, verification=cert, force_download=props.FORCE_CRL_DOWNLOAD)
    logger.info("Done")
#'''
revoked = 330011
not_revoked = certificate.tbsCertificate.serial_number

# revoked case
is_rev = crl_cache.is_certificate_revoked(issuer, revoked)
logger.info("Is certificate %s revoked? %s" % (str(revoked), is_rev))  
if is_rev:
    logger.info("Certificate %s revoked on %s" % (str(revoked), crl_cache.certificate_rev_date(issuer, revoked)))

# not revoked_case
is_rev = crl_cache.is_certificate_revoked(issuer, not_revoked)
logger.info("Is certificate %s revoked? %s" % (str(not_revoked), is_rev))  
if is_rev:
    logger.info("Certificate %s revoked on %s" % (str(not_revoked), crl_cache.certificate_rev_date(issuer, not_revoked)))


crl_cache.pickle()

