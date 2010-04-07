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

"""
Cache and management of certificate data
"""

from pyasn1.codec.der import encoder
from hashlib import sha256
import cert_verifier
import cert_loader
from dslib.properties.properties import Properties as props


class CertificateManager(object):
  """
  application wide singleton for storage and caching of parsed certificates
  """
  
  _cert_store = {}
  trusted_certificates = []


  @classmethod
  def get_certificate_from_der(cls, der):
    h = cls._hash_certificate_der_data(der)
    if h in cls._cert_store:
      return cls._cert_store[h]
    else:
      from pyasn1.codec.der import decoder
      from pkcs7.asn1_models.X509_certificate import Certificate
      data = decoder.decode(der,asn1Spec=Certificate())[0]
      cert = cls._create_certificate(data, der)
      cls._cert_store[h] = cert
      return cert
  
  @classmethod
  def get_certificate(cls, data):
    der = encoder.encode(data)
    h = cls._hash_certificate_der_data(der)
    if h in cls._cert_store:
      return cls._cert_store[h]
    else:
      cert = cls._create_certificate(data, der)
      cls._cert_store[h] = cert
      return cert
    
  @classmethod
  def add_trusted_certificate(cls, cert):
    cls.trusted_certificates.append(cert)
  
  @classmethod
  def read_trusted_certificates_from_dir(cls, dirname):
    for cert in cert_loader.load_certificates_from_dir(dirname):
      cls.add_trusted_certificate(cert)
    
  @classmethod
  def verify_asn1_certificate(cls, certificate):
    '''
    Verfies certificate by calling method from cert_verifier
    '''
    res = cert_verifier.verify_certificate(
                            certificate,
                            cls.trusted_certificates,
                            check_crl = props.CHECK_CRL,
                            force_crl_download=props.FORCE_CRL_DOWNLOAD
                            )
    return res
  
  @classmethod
  def _create_certificate(cls, data, der):
    from pkcs7_models import X509Certificate
    cert = X509Certificate(data)
    cert.raw_der_data = der
    if props.VERIFY_CERTIFICATE:
      cert.verification_results = cls.verify_asn1_certificate(data)
    return cert
    
  @classmethod
  def _hash_certificate_der_data(cls, data):
    h = sha256(data).hexdigest()
    return h
  