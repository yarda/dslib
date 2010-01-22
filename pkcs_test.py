'''
Created on Dec 4, 2009

Sandbox unstable module.
'''
import pkcs7
import pkcs7.pkcs7_decoder
import pkcs7.verifier
import pkcs7.asn1_models.oid

from pkcs7.asn1_models.TST_info import *
from pkcs7.asn1_models.pkcs_signed_data import *

from pyasn1.type import tag,namedtype,namedval,univ,constraint,char,useful
from pyasn1.codec.der import decoder, encoder
from pyasn1 import error

import models


from certs.cert_verifier import *
from certs.cert_loader import *

from pkcs7.asn1_models.crl import *

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
        print "TEST: QTimeStamp verified"
    else:
        print "TEST: QTimeStamp verification failed"
    
    tstData = qts.getComponentByName("content").getComponentByName("encapsulatedContentInfo").getComponentByName("eContent")._value
    
    tstinfo = pkcs7.pkcs7_decoder.decode_tst(tstData)
    
    t = models.TimeStampToken(tstinfo)
    return vr, t


'''
subory v test_msgs obsahuju binarnu formu prijatych podpisanych sprav
t.j. odpoved na getSignedXXX obsahovala element dmSignature. Jeho obsah
je base64 dekodovany a zapisany do danych suborov (podpisana prijata a odoslana 
sprava, podpisana dorucenka).
'''
f = open("test_msgs/signedSentMessage", "r")
#f = open("test_msgs/signedReceivedMessage", "r")
#f = open("test_msgs/sigDeliveryInfo", "r")
coded = f.read()

decoded_msg = pkcs7.pkcs7_decoder.decode_msg(coded)
verification_result = pkcs7.verifier.verify_msg(decoded_msg)

#print decoded_msg.getComponentByName("signedData")

if verification_result:
    print "TEST: Message verified - ok"
else:
    print "TEST: Verification of pkcs7 message failed"

pkcs_data = models.PKCS7_data(decoded_msg)

msg = pkcs_data.message
     
import suds.sax.parser as p
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
print "TEST: Msg encryption alg: %s" % pkcs7.asn1_models.oid.oid_map[e_alg_code]


cert = decoded_msg.getComponentByName("content").getComponentByName("certificates")[0]
trusted = load_certificates_from_dir("trusted_certificates/")

certificate_verified = verify_certificate(cert, trusted)

print "TEST: Certificate verified?..... %s" % certificate_verified

# daju sa overit aj samotne doveryhodne certifikaty voci sebe
ok = verify_certificate(trusted[0], trusted)
print ok

import pkcs7.tstamp_helper

qts_verified, tstinfo = pkcs7.tstamp_helper.parse_qts(m.dmQTimestamp)

if qts_verified:
    imprint = tstinfo.msgImprint.imprint
    imprint = base64.b64encode(imprint)
    
    hashFromMsg = m.dmHash.value
    
    if hashFromMsg == imprint:
        print "TEST: Message imprint in timestamp and dmHash value are the same"
    else:
        print "TEST: Message imprint in timestamp and dmHash value differ!"
        
    genTime = tstinfo.genTime
    print "TEST: Timestamp created: %s" % genTime
    print "TEST: TS authority: %s" % tstinfo.tsa
    print "TEST: TS serial: %s" % tstinfo.serialNum

# try something from crls
from certs.crl_store import *

certificate = m.pkcs7_data.certificates[0]
issuer = str(certificate.tbsCertificate.issuer)

dps = extract_crl_distpoints(certificate)

url = dps[0][1]

b = restore_cache()
if b is None:
    print "CRL cache not found locally, downloading..."
    b = CRL_cache()
    added = b.add_issuer(issuer)
    added.add_dist_point(url)
    added.init_dist_point(url, verification=cert)
    print "Refreshing distribution point..."
    added.refresh_dist_point(url)
    print "Done"
else:
    print "CRL cache read from local store"
    i = b.get_issuer(issuer)
    i.refresh_dist_point(url)

revoked = 330011
print "Date of revocation of cetificate %s: %s" % (str(revoked), b.is_certificate_revoked(issuer, revoked))    


b.pickle()

