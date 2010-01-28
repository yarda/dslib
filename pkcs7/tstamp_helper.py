'''
Module for parsing dmQTimestamp.
dmQtimestamp is base64 encoded DER pkcs7 document containing
signedData component, so it is the same format as the format
of signed data message. Version of content is '3', so there are small
differences.
'''
import logging
logger = logging.getLogger("pkcs7.tstamp_helper")


import base64
import pkcs7
import pkcs7.pkcs7_decoder
import pkcs7.verifier
import models

def parse_qts(dmQTimestamp, verify=True):
    '''
    Parses QTimestamp and verifies it.
    Returns result of verification and TimeStampTOken instance.
    '''    
    ts = base64.b64decode(dmQTimestamp)

    qts = pkcs7.pkcs7_decoder.decode_qts(ts)
    #if we want to verify the timestamp
    if (verify):
        verif_result = pkcs7.verifier.verify_qts(qts)        
        if verif_result:
            logger.info("QTimeStamp verified")
        else:
            logger.error("QTimeStamp verification failed")
    
    tstData = qts.getComponentByName("content").getComponentByName("encapsulatedContentInfo").getComponentByName("eContent")._value    
    tstinfo = pkcs7.pkcs7_decoder.decode_tst(tstData)
    
    t = models.TimeStampToken(tstinfo)
    return verif_result, t