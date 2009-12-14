'''
Created on Dec 11, 2009

@author: mdioszegi
'''

from pkcs7.asn1_models.tools import *
from pkcs7.asn1_models.oid import *
from pkcs7.asn1_models.tools import *
from pkcs7.asn1_models.X509certificate import *
from pkcs7.debug import *

class SignedData():    
    '''
    Represents SignedData object.
    Attributes:
    - version
    - digest_algorithms
    - message
    '''
    def __init__(self, signed_data):
        self.version = signed_data.getComponentByName("version")        
        self.digest_algorithms = self._extract_used_digest_algs(signed_data)
        self.message = signed_data.getComponentByName("content").getComponentByName("signed_content").getContentValue()                 
    
    def _extract_used_digest_algs(self, signed_data):
        used_digests = signed_data.getComponentByName("digestAlgs")
        result = []
        for used_digest in used_digests:           
            algorithm_key = tuple_to_OID(used_digest.getComponentByName("algorithm")._value)
            result.append(algorithm_key)  
        return result

class Name():
    '''
    Represents Name (structured, tagged).
    This is a dictionary. Keys are types of names (their OIDs), value is thei value.
    String representation: "1.2.3.5=>CZ, 2.3.6.5=>Ceska posta..."
    Oids are in oid_map, in module oid
    '''
    def __init__(self, name):
        self.__attributes = {}
        for name_part in name:
            for attr in name_part:
                type = str(attr.getComponentByPosition(0).getComponentByName('type'))                
                value = str(attr.getComponentByPosition(0).getComponentByName('value'))
                self.__attributes[type] = value        
    
    def __str__(self):        
        result = ''
        for key in self.__attributes.keys():
            result += key
            result += ' => '
            result += self.attributes[key]
            result += ','
        return result[:len(result)-1]
        
    def get_attributes(self):
        return self.__attributes.copy()

class ValidityInterval():
    '''
    Validity interval of a certificate. Values are UTC times.
    Attributes:
    -valid_from
    -valid_to
    '''
    def __init__(self, validity):
        self.valid_from = validity.getComponentByName("notBefore").getComponent()._value
        self.valid_to = validity.getComponentByName("notAfter").getComponent()._value

class PublicKeyInfo():
    '''
    Represents information about public key.
    Expected RSA.
    TODO: other types of algorithms (DSA)!
    Attributes:
    - alg (identifier of algorithm)
    - key (tuple of modulus and exponent)
    '''
    def __init__(self, public_key_info):
        self.alg = str(public_key_info.getComponentByName("algorithm"))
        bitstr_key = public_key_info.getComponentByName("subjectPublicKey")
        self.key = get_RSA_pub_key_material(bitstr_key)

class Extension():
    '''
    Represents one Extension in X509v3 certificate
    Attributes:
    - id  (identifier of extension)
    - is_critical
    - value (value of extension, needs more parsing - it is in DER encoding)
    
    TODO: parsing of extension value (contains info about CRL distrib. points, alternative subject name, some constraints etc)
    '''
    def __init__(self, extension):
        self.id = tuple_to_OID(extension.getComponentByName("extnID"))
        critical = extension.getComponentByName("critical")
        if critical == 0:
            self.is_critical = False
        else:
            self.is_critical = True
        
        self.value = extension.getComponentByName("extnValue")._value
       
class Certificate():
    '''
    Represents Certificate object.
    Attributes:
    - version
    - serial_number
    - signature_algorithm (data are signed with this algorithm)
    - issuer (who issued this certificate)
    - validity
    - subject (for who the certificate was issued)
    - pub_key_info 
    - issuer_uid (optional)
    - subject_uid (optional)
    - extensions (list of extensions)
    '''
    def __init__(self, tbsCertificate):
        self.version = tbsCertificate.getComponentByName("version")._value
        self.serial_number = tbsCertificate.getComponentByName("serialNumber")._value
        self.signature_algorithm = str(tbsCertificate.getComponentByName("signature"))
        self.issuer = Name(tbsCertificate.getComponentByName("issuer"))
        self.validity = ValidityInterval(tbsCertificate.getComponentByName("validity"))
        self.subject = Name(tbsCertificate.getComponentByName("subject"))
        self.pub_key_info = PublicKeyInfo(tbsCertificate.getComponentByName("subjectPublicKeyInfo"))
        
        issuer_uid = tbsCertificate.getComponentByName("issuerUniqueID")
        if issuer_uid:
            self.issuer_uid = issuer_uid.toOctets()
        else:
            self.issuer_uid = None
            
        subject_uid = tbsCertificate.getComponentByName("subjectUniqueID")
        if subject_uid:
            self.subject_uid = subject_uid.toOctets()
        else:
            self.subject_uid = None
            
        self.extensions = self._create_extensions_list(tbsCertificate.getComponentByName('extensions'))        
    
    def _create_extensions_list(self, extensions):
        from pyasn1.type import tag,namedtype,namedval,univ,constraint,char,useful
        from pyasn1.codec.der import decoder, encoder
        from pyasn1 import error
            
        if extensions is None:
            return []
        result = []
        for extension in extensions:
            ext = Extension(extension)
            result.append(ext)
          
        return result
    
class X509Certificate():
    '''
    Represents X509 certificate.
    Attributes:
    - signature_algorithm (used to sign this certificate)
    - signature
    - tbsCertificate (the certificate)
    '''
    def __init__(self, certificate):
        self.sighnature_algorithm = str(certificate.getComponentByName("signatureAlgorithm"))
        self.signature = certificate.getComponentByName("signatureValue").toOctets()     
        tbsCert = certificate.getComponentByName("tbsCertificate")
        self.tbsCertificate = Certificate(tbsCert)   

class Attribute():
    """
    One attribute in SignerInfo attributes set
    """
    def __init__(self, attribute):
        self.type = str(attribute.getComponentByName("type"))
        self.value = str(attribute.getComponentByName("value").getComponentByPosition(0))
        #print base64.b64encode(self.value)

class AutheticatedAttributes():
    """
    Authenticated attributes of signer info
    """
    def __init__(self, auth_attributes):
        self.attributes = []
        for aa in auth_attributes:
            self.attributes.append(Attribute(aa))

class SignerInfo():
    """
    Represents information about a signer.
    Attributes:
    - version
    - issuer 
    - serial_number (of the certificate used to verify this signature)
    - digest_algorithm 
    - encryp_algorithm
    - signature
    - auth_atributes (optional field, contains authenticated attributes)
    """
    def __init__(self, signer_info):
        self.version = signer_info.getComponentByName("version")._value
        self.issuer = Name(signer_info.getComponentByName("issuerAndSerialNum").getComponentByName("issuer"))
        self.serial_number = signer_info.getComponentByName("issuerAndSerialNum").getComponentByName("serialNumber")._value
        self.digest_algorithm = str(signer_info.getComponentByName("digestAlg"))
        self.encrypt_algorithm = str(signer_info.getComponentByName("encryptAlg"))
        self.signature = signer_info.getComponentByName("signature")._value
        auth_attrib = signer_info.getComponentByName("authAttributes")
        if auth_attrib is None:
            self.auth_attributes = None
        else:
            self.auth_attributes = AutheticatedAttributes(auth_attrib)

class SignerInfoList():
    def __init__(self, signer_infos):
        self.signers = []
        for signer_info in signer_infos:
            self.signers.append(SignerInfo(signer_info))

class PKCS7_data():    
    '''
    Holder for PKCS7 data - signed content, certificate, signer information.
    signed_data, certificate, signer_info = instances from pyasn1, will be 
    mapped into plain python objets
    '''
    def __init__(self, signed_data, certificates, signer_infos):
        self.signed_data = SignedData(signed_data)
        self.certificates = X509Certificate(certificates)
        self.signer_infos = SignerInfoList(signer_infos)
