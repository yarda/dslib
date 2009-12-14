import sys, string, base64
from pyasn1.type import tag,namedtype,namedval,univ,constraint,char,useful
from pyasn1.codec.der import decoder, encoder
from pyasn1 import error

import pkcs7.asn1_models

from asn1_models.X509certificate import *
from asn1_models.pkcsSignedData import *
from asn1_models.RSA import *
from asn1_models.digestInfo import *

from debug import *
            
'''
Decodes message in DER encoding.
Return tuple - (message, signer_information)
'''
def decode_msg(message):    
    # create template for decoder
    msg = Message()
    # decode pkcs signed message
    decoded = decoder.decode(message,asn1Spec=msg)
    message = decoded[0]
    # decode signer information
    sigInfos = SignerInfos()    
    signer_information = decoder.decode(decoded[1], asn1Spec=sigInfos)[0]
    
    return message, signer_information




    
    
    
 