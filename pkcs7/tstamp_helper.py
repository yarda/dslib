
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
    verif_result = None
    #if we want to verify the timestamp
    if (verify):
        verif_result = pkcs7.verifier.verify_qts(qts)        
        if verif_result:
            logger.info("QTimeStamp verified")
        else:
            logger.error("QTimeStamp verification failed")
    else:
        logger.info("Verification of timestamp skipped")
        
    tstData = qts.getComponentByName("content").getComponentByName("encapsulatedContentInfo").getComponentByName("eContent")._value    
    tstinfo = pkcs7.pkcs7_decoder.decode_tst(tstData)
    
    t = models.TimeStampToken(tstinfo)
    return verif_result, t