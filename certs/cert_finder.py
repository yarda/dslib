'''
This module contains methods which can look for a certificate among other 
certificates.
'''
import logging

def find_cert_by_subject(subject, certs):
    '''
    Looks for the certificate with specified subject.
    '''
    for cert in certs:
        subj = str(cert.getComponentByName("tbsCertificate")\
                    .getComponentByName("subject"))
        if subj == subject:
            return cert
    return None


def find_cert_by_serial(serial_number, certificates):
    '''
    Looks for certificate with serial_number.
    Returns the certificate or None.
    '''
    for cert in certificates:
        try:
            sn = cert.getComponentByName("tbsCertificate")\
                                .getComponentByName("serialNumber")        
            if sn == serial_number:
                return cert
        except Exception, ex:
            logging.error(ex)
            continue
    return None

def find_cert_by_iss_sn(certs, issuer, sn):
  '''
  Looks for certificate with specified issuer and serial number.
  Difference is that certs are objects pkcs7_models.X509certificate,
  not pyAsn components.
  '''
  for cert in certs:
    logging.debug("Cert issuer/from DER: %s" % str(cert.tbsCertificate.issuer))
    logging.debug("Cert issuer/from python obj: %s" % issuer)      
    if str(cert.tbsCertificate.issuer) == issuer:
      if cert.tbsCertificate.serial_number == sn:
        return cert
  return None 

def find_cert_in_crl(cert_sn, crl):
    '''
    Looks for certificate with specified serial number in
    certificate revocation list.
    '''
    revoked = crl.getComponentByName("tbsCertList").\
                getComponentByName("revokedCertificates")
    for cert in revoked:
        csn = cert.getComponentByName("userCertificate")._value
        if csn == cert_sn:
            return csn
    
    return None