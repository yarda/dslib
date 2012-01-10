
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
Decoder for PEM files
'''

# standard library imports
import sys
import string
import base64

# dslib imports
from pyasn1.codec.der import decoder
from pyasn1 import error
from dslib.pkcs7.asn1_models.X509_certificate import *

PEM_SUFFIX = ".pem"
CER_SUFFIX = ".cer"

def _get_substrate(lines):
    '''
    Returns substrate from PEM file
    '''
    begin_cert, content, end_cert = 0, 1, 2
    state = begin_cert
    certCnt = 0
    substrate = None
    
    for certLine in lines:
        certLine = string.strip(certLine)
        if state == begin_cert:
            if state == begin_cert:
                if certLine == '-----BEGIN CERTIFICATE-----':
                    certLines = []
                    state = content
                    continue
        if state == content:
            if certLine == '-----END CERTIFICATE-----':
                state = end_cert
            else:
                certLines.append(certLine)
        if state == end_cert:
            substrate = ''
            for certLine in certLines:
                substrate = substrate + base64.b64decode(certLine)
    return substrate


def parse_pem(pem_file):
    '''
    Parses PEM certificate.
    Returns pyasn Certificate object or None, if parsing failed.
    '''
    try:
        f = open(pem_file, "r")
        lines = f.readlines()
    except IOError:
        return None
    substrate = _get_substrate(lines)
    pattern = Certificate()
    try:
        certificate = decoder.decode(substrate, asn1Spec=pattern)[0]
    except Exception, e:
        return None
    
    return certificate

def parse_cer(der_file):
    '''
    Parses certificate file in DER format.
    Returns pyasn Certificate or None, if parsing failed
    '''
    f = open(der_file, "r")
    lines = f.readlines()
    substrate = ''
    for line in lines:
        substrate += line    
    pattern = Certificate()
    try:
        certificate = decoder.decode(substrate, asn1Spec=pattern)[0]
    except Exception, e:
        print e.message
        return None
    
    return certificate

def load_certificates_from_dir(cert_folder):
    '''
    Tries to extract X509 certificate from each file in the specified directory.
    Returns list of X509 certificates
    '''
    if cert_folder[len(cert_folder) - 1] != "/":
        cert_folder += "/"
    import os
    try:
      files = os.listdir(cert_folder)
    except:
      return []
    result = []
    for file in files:
        certificate = None
        if file.endswith(PEM_SUFFIX):
            certificate = parse_pem(cert_folder + file)
        if file.endswith(CER_SUFFIX):
            certificate = parse_cer(cert_folder + file)
            
        if certificate:
            result.append(certificate)
    return result


