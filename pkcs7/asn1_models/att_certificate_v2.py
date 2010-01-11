import string
from pyasn1.type import tag,namedtype,namedval,univ,char,useful

from pyasn1 import error

from X509_certificate import *
from general_types import *
from oid import oid_map as oid_map
'''
ASN.1 modules from http://www.ietf.org/rfc/rfc3281.txt
'''


'''
   ObjectDigestInfo ::= SEQUENCE {
                 digestedObjectType  ENUMERATED {
                         publicKey            (0),
                         publicKeyCert        (1),
                         otherObjectTypes     (2) },
                                 -- otherObjectTypes MUST NOT
                                 -- be used in this profile
                 otherObjectTypeID   OBJECT IDENTIFIER OPTIONAL,
                 digestAlgorithm     AlgorithmIdentifier,
                 objectDigest        BIT STRING
            }

'''
class ObjectDigestInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
                        namedtype.OptionalNamedType("digestedObjectType", univ.Enumerated()),
                        namedtype.OptionalNamedType("otherObjectTypeID", univ.ObjectIdentifier()),
                        namedtype.OptionalNamedType("digestAlgorithm", AlgorithmIdentifier()),
                        namedtype.OptionalNamedType("objectDigest", univ.BitString()),
                        )
'''
 IssuerSerial  ::=  SEQUENCE {
                 issuer         GeneralNames,
                 serial         CertificateSerialNumber,
                 issuerUID      UniqueIdentifier OPTIONAL
            }

'''
class IssuerSerial(univ.Sequence):
    componentType = namedtype.NamedTypes(
                        namedtype.NamedType("issuer", GeneralNames()),
                        namedtype.NamedType("serial", CertificateSerialNumber()),
                        namedtype.OptionalNamedType("issuerUID", UniqueIdentifier()),                        
                        )

'''
Holder ::= SEQUENCE {
                  baseCertificateID   [0] IssuerSerial OPTIONAL,
                           -- the issuer and serial number of
                           -- the holder's Public Key Certificate
                  entityName          [1] GeneralNames OPTIONAL,
                           -- the name of the claimant or role
                  objectDigestInfo    [2] ObjectDigestInfo OPTIONAL
                           -- used to directly authenticate the holder,
                           -- for example, an executable
            }
'''
class Holder(univ.Sequence):
    componentType = namedtype.NamedTypes(
                        namedtype.OptionalNamedType("baseCertificateID", IssuerSerial().\
                                                    subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x0))),
                        namedtype.OptionalNamedType("entityName", GeneralNames().\
                                                    subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x1))),                               
                        namedtype.OptionalNamedType("objectDigestInfo", ObjectDigestInfo().\
                                                    subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x2))),                        
                        )
'''
 AttCertIssuer ::= CHOICE {
                   v1Form   GeneralNames,  -- MUST NOT be used in this
                                           -- profile
                   v2Form   [0] V2Form     -- v2 only
             }

             V2Form ::= SEQUENCE {
                   issuerName            GeneralNames  OPTIONAL,
                   baseCertificateID     [0] IssuerSerial  OPTIONAL,
                   objectDigestInfo      [1] ObjectDigestInfo  OPTIONAL
                      -- issuerName MUST be present in this profile
                      -- baseCertificateID and objectDigestInfo MUST
                      -- NOT be present in this profile
             }
'''
class V2Form(univ.Sequence):
   componentType = namedtype.NamedTypes(
                        namedtype.OptionalNamedType("issuerName", GeneralNames()),
                        namedtype.OptionalNamedType("basicCertificateID", IssuerSerial()\
                                            .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x0))), 
                        namedtype.OptionalNamedType("objectDigestInfo", ObjectDigestInfo()\
                                            .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x1))), 
                    
                        ) 

class AttCertIssuer(univ.Choice):
   componentType = namedtype.NamedTypes(
                        namedtype.NamedType("v1Form", GeneralNames()),
                        namedtype.NamedType("v2Form", V2Form()\
                                            .subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x0))), 
                        )                                            
    
    
class AttrCertAttributes(univ.Sequence):
    #componentType = AttributeTypeAndValue()
    pass


'''
 AttributeCertificateInfo ::= SEQUENCE {
                 version              AttCertVersion -- version is v2,
                 holder               Holder,
                 issuer               AttCertIssuer,
                 signature            AlgorithmIdentifier,
                 serialNumber         CertificateSerialNumber,
                 attrCertValidityPeriod   AttCertValidityPeriod,
                 attributes           SEQUENCE OF Attribute,
                 issuerUniqueID       UniqueIdentifier OPTIONAL,
                 extensions           Extensions OPTIONAL
            }

'''
class ACInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
                        namedtype.DefaultedNamedType("version", Version('v2')),
                        namedtype.NamedType("holder", Holder()),                                             
                        namedtype.NamedType("issuer", AttCertIssuer()), 
                        namedtype.NamedType("signature", AlgorithmIdentifier()),
                        namedtype.NamedType("serialNumber", CertificateSerialNumber()),
                        namedtype.NamedType("attrCertValidityPeriod", Validity()),
                        namedtype.NamedType("attributes", AttrCertAttributes()),
                        namedtype.OptionalNamedType("issuerUniqueID", UniqueIdentifier()),
                        namedtype.OptionalNamedType("extensions", Extensions()),
                        )


class AttributeCertificateV2(univ.Sequence):
    componentType = namedtype.NamedTypes(
                        namedtype.NamedType("acInfo", ACInfo()),
                        namedtype.NamedType("sigAlg", AlgorithmIdentifier()),                                             
                        namedtype.NamedType("signature", univ.BitString()) 
                        )



class CertificateChoices(univ.Choice):
    componentType = namedtype.NamedTypes(
                        namedtype.NamedType("certificate", Certificate()),
                        namedtype.NamedType("extendedC", Certificate().\
                                                    subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x0))),
                        namedtype.NamedType("v1AttrCert", AttributeCertificateV2().\
                                                    subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x1))),
                        namedtype.NamedType("v2AttrCert", univ.Sequence().\
                                                    subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x2))),
                        namedtype.NamedType("otherCert", univ.Sequence().\
                                                    subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x3)))
                        )


class CertificateSet(univ.SetOf):
    componentType = CertificateChoices()
