'''
Certificate extensions specifications
'''
import sys, string, base64
from pyasn1.type import tag,namedtype,namedval,univ,constraint,char,useful
from pyasn1.codec.der import decoder, encoder
from pyasn1 import error

from tools import *
from oid import oid_map as oid_map

from general_types import  *
         

#RDNS sequence otagovana A4 (constructed octet string)
class IssuerName(univ.Sequence):
    componentType = namedtype.NamedTypes(
                            namedtype.NamedType("name", RDNSequence().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x4))),
                                         )

class KeyId(univ.Sequence):
    componentType = namedtype.NamedTypes(
                            namedtype.OptionalNamedType("keyIdentifier", univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x0))),
                            namedtype.OptionalNamedType("authorityCertIssuer", IssuerName().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x1))),
                            namedtype.OptionalNamedType("authorityCertSerialNum", univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x2))),
                                         )

class BasicConstraints(univ.Sequence):
    componentType = namedtype.NamedTypes(
                            namedtype.DefaultedNamedType("ca", univ.Boolean(False)),
                            namedtype.OptionalNamedType("pathLen", univ.Integer())                                       
                                        )

class AnyQualifier(univ.Choice):
    componentType = namedtype.NamedTypes(
                            namedtype.NamedType("t1", univ.Sequence()),
                            namedtype.NamedType("t2", univ.Set()),                            
                            namedtype.NamedType("t3", DirectoryString()),
                                         )
    
class PolicyQualifierInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
                            namedtype.NamedType("policyQualifierId", univ.ObjectIdentifier()),
                            namedtype.OptionalNamedType("qualifier", AnyQualifier())
                                         )

class PolicyQualifiers(univ.SequenceOf):
    componentType = PolicyQualifierInfo()

class PolicyInformation(univ.Sequence):
    componentType = namedtype.NamedTypes(
                            namedtype.NamedType("policyIdentifier", univ.ObjectIdentifier()),
                            namedtype.OptionalNamedType("policyQualifiers", PolicyQualifiers())                                       
                                         )
    
class CertificatePolicies(univ.SequenceOf):
    componentType = PolicyInformation()

class DpointName(univ.Choice):
    componentType = namedtype.NamedTypes(
                            namedtype.NamedType("fullName", GeneralNames().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x0))),
                            namedtype.NamedType("relativeToIssuer", RelativeDistinguishedName().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x1)))                                       
                                         )


class ReasonFlags(univ.BitString):
    pass

class DistributionPoint(univ.Sequence):
    componentType = namedtype.NamedTypes(
                            namedtype.OptionalNamedType("distPoint", DpointName().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x0))),
                            namedtype.OptionalNamedType("reasons", ReasonFlags().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x1))),
                            namedtype.OptionalNamedType("issuer", GeneralNames().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x2))),
                                         )
    

class CRLDistributionPoints(univ.SequenceOf):
    componentType = DistributionPoint()

class Statement(univ.Sequence):
    componentType = namedtype.NamedTypes(
                            namedtype.NamedType("stmtId", univ.ObjectIdentifier()),    
                                         )    

class Statements(univ.SequenceOf):
    componentType = Statement()

class SubjectKeyId(univ.OctetString):
    pass

class ExtensionValue(univ.Choice):
    componentType = namedtype.NamedTypes(
                            namedtype.NamedType("subjectAltName", GeneralNames()),
                            namedtype.NamedType("authKeyId", KeyId()),
                            namedtype.NamedType("CRLdistPoints", univ.Sequence()),
                            namedtype.NamedType("certPolicies", univ.Sequence()),
                            namedtype.NamedType("basicConstraints", univ.Sequence()),
                            namedtype.NamedType("keyUsage", univ.BitString()),
                            namedtype.NamedType("qcStatements", univ.Sequence()),
                            namedtype.NamedType("subjectKeyId", KeyId()),
                                         )

