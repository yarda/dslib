'''
Created on Dec 3, 2009

@author: mdioszegi
'''
import sys, string, base64
from pyasn1.type import tag,namedtype,namedval,univ,constraint,char,useful
from pyasn1.codec.der import decoder, encoder
from pyasn1 import error

from tools import *
from oid import oid_map as oid_map

from general_types import  *


class GeneralName(univ.Choice):
    componentType = namedtype.NamedTypes(
                            namedtype.NamedType("rfc822name", char.IA5String().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x1))),
                            namedtype.NamedType("name", univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x4)))                            
                                         ) 
class GeneralNames(univ.SequenceOf):
    componentType = GeneralName()

class GeneralName1(univ.Choice):
    componentType = namedtype.NamedTypes(
                            namedtype.NamedType("rfc822name", char.IA5String().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x1)))                            
                                         ) 

class GeneralNames1(univ.SequenceOf):
    componentType = GeneralName1()
    tagSet = univ.SequenceOf.tagSet.tagImplicitly(
                                            tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x1)
                                           )
class KeyIdentifier(univ.OctetString):
    tagSet = univ.OctetString.tagSet.tagImplicitly(
                                            tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x0)
                                            )
    
    
class AuthKeyId(univ.Sequence):
    componentName = namedtype.NamedTypes(
                            namedtype.OptionalNamedType("keyIdentifier", KeyIdentifier()),#univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x0))),
                            namedtype.OptionalNamedType("authorityCertIssuer", GeneralNames1()),
                            namedtype.OptionalNamedType("authorityCertSerialNum", univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x2))),
                                         )

 
class ExtensionValue(univ.Choice):
    componentType = namedtype.NamedTypes(
                            namedtype.NamedType("subjectAltName", GeneralNames()),
                            namedtype.NamedType("authKeyId", AuthKeyId()),
                            #namedtype.NamedType(),
                            #namedtype.NamedType(),
                            #namedtype.NamedType(),
                            #namedtype.NamedType(),
                            #namedtype.NamedType(),
                            #namedtype.NamedType(),
                                         )


class Extension(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('extnID', univ.ObjectIdentifier()),
        namedtype.DefaultedNamedType('critical', univ.Boolean('False')),
        namedtype.NamedType('extnValue', univ.OctetString())
        )
   


class Extensions(univ.SequenceOf):
    componentType = Extension()
    sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, MAX)

class SubjectPublicKeyInfo(univ.Sequence):
     componentType = namedtype.NamedTypes(
         namedtype.NamedType('algorithm', AlgorithmIdentifier()),
         namedtype.NamedType('subjectPublicKey', univ.BitString())
         )

class UniqueIdentifier(univ.BitString): pass

class Time(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('utcTime', useful.UTCTime()),
        namedtype.NamedType('generalTime', useful.GeneralizedTime())
        )
    
class Validity(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('notBefore', Time()),
        namedtype.NamedType('notAfter', Time())
        )

class CertificateSerialNumber(univ.Integer): pass

class Version(univ.Integer):
    namedValues = namedval.NamedValues(
        ('v1', 0), ('v2', 1), ('v3', 2)
        )

class TBSCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('version', Version('v1', tagSet=Version.tagSet.tagExplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))),
        namedtype.NamedType('serialNumber', CertificateSerialNumber()),
        namedtype.NamedType('signature', AlgorithmIdentifier()),
        namedtype.NamedType('issuer', Name()),
        namedtype.NamedType('validity', Validity()),
        namedtype.NamedType('subject', Name()),
        namedtype.NamedType('subjectPublicKeyInfo', SubjectPublicKeyInfo()),
        namedtype.OptionalNamedType('issuerUniqueID', UniqueIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.OptionalNamedType('subjectUniqueID', UniqueIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
        namedtype.OptionalNamedType('extensions', Extensions().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)))
        )
    

class Certificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tbsCertificate', TBSCertificate()),
        namedtype.NamedType('signatureAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('signatureValue', univ.BitString())
        )

class Certificates(univ.SetOf):
    componentType = Certificate()
    tagSet = univ.SequenceOf.tagSet.tagImplicitly(
                                             tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x0)
                                             )
