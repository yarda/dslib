'''
Decoder for PEM files
'''
import sys, string, base64
from pyasn1.codec.der import decoder
from pyasn1 import error

import pkcs7.asn1_models
import pkcs7.asn1_models.X509_certificate
from pkcs7.asn1_models.X509_certificate import *

PEM_SUFFIX = ".pem"
CER_SUFFIX = ".cer"

def _get_substrate(lines):
    '''
    Returns substrate from PEM file
    '''
    begin_cert, content, end_cert = 0, 1, 2
    state = begin_cert
    certCnt = 0
    
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
    f = open(pem_file, "r")
    lines = f.readlines()
    substrate = _get_substrate(lines)
    pattern = Certificate()
    try:
        certificate = decoder.decode(substrate, asn1Spec=pattern)[0]
    except Exception, e:
        print e.message
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

if __name__ == "__main__":    
    certs = load_certificates_from_dir("certificates/")
    print len(certs)

