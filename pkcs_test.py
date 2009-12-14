'''
Created on Dec 4, 2009
'''
import pkcs7
import pkcs7.decoder
import pkcs7.verifier
import pkcs7.asn1_models.oid

import models

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


decoded_msg, decoded_sig_info = pkcs7.decoder.decode_msg(coded)

verification_result = pkcs7.verifier.verify_msg((decoded_msg, decoded_sig_info))

if verification_result:
    print "TEST: Message verified - ok"
else:
    print "Verification of pkcs7 message failed"

message = decoded_msg
signer_info = decoded_sig_info

signed_data = message.getComponentByName("signedData")

certificate = message.getComponentByName("certificate")

pkcs_data = models.PKCS7_data(signed_data, certificate, signer_info)

msg = pkcs_data.signed_data.message
        
import suds.sax.parser as p
parser = p.Parser()
document = parser.parse(string = msg)

# ak sa jedna o podpisanu dorucenku        
#m = models.Message(xml_document = document, 
#                   path_to_content=models.Message.SIG_DELIVERY_CONTENT_PATH)

# ak sa jedna o podpisanu spravu
m = models.Message(xml_document = document, 
                   path_to_content=models.Message.SIG_MESSAGE_CONTENT_PATH)


m.pkcs7_data = pkcs_data

# mala ukazka
e_alg_code = m.pkcs7_data.signer_infos.signers[0].encrypt_algorithm
print "Encryption alg:"
print pkcs7.asn1_models.oid.oid_map[e_alg_code]
