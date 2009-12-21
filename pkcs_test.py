'''
Created on Dec 4, 2009

Sandbox unstable module.
'''
import pkcs7
import pkcs7.pkcs7_decoder
import pkcs7.verifier
import pkcs7.asn1_models.oid

from pkcs7.asn1_models.TSTinfo import *

from pyasn1.type import tag,namedtype,namedval,univ,constraint,char,useful
from pyasn1.codec.der import decoder, encoder
from pyasn1 import error

import models


from certs.cert_verifier import *
from certs.pem_decoder import *

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
    print "Verification of pkcs7 message failed"

pkcs_data = models.PKCS7_data(decoded_msg)

msg = pkcs_data.signed_data.message
        
import suds.sax.parser as p
parser = p.Parser()
document = parser.parse(string = msg)

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


cert = decoded_msg.getComponentByName("certificates")[0]
trusted = load_certificates_from_dir("trusted_certificates/")

certificate_verified = verify_certificate(cert, trusted)

print "TEST: Certificate verified?..... %s" % certificate_verified

# daju sa overit aj samotne doveryhodne certifikaty voci sebe
ok = verify_certificate(trusted[0], trusted)
print ok
'''
import base64
ts = base64.b64decode(m.dmQTimestamp)

f = open("binary_ts", "w")
f.write(ts)
f.close()


#x = pkcs7.decoder.decode_msg(ts)
#print x

d = pkcs7.decoder.decode_msg(ts)

a = decoder.decode(ts)
print a
aa = a[0].getComponentByPosition(1).getComponentByPosition(2).getComponentByPosition(1)._value

f = open("TSTInfo", "w")
f.write(aa)
f.close()


spec = TSTinfo()
bb = decoder.decode(aa, asn1Spec=spec)

c = encoder.encode(a[0].getComponentByPosition(0))
b = pkcs7.decoder.decode_msg(c)
print b
'''