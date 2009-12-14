'''
Created on Dec 4, 2009

@author: mdioszegi
'''
import sys, string, base64
from pyasn1.type import tag,namedtype,namedval,univ,constraint,char,useful
from pyasn1.codec.der import decoder, encoder
from pyasn1 import error

from X509certificate import Certificate
from general_types import *
from oid import oid_map as oid_map


class SignedContent(univ.StructuredOctetString):
    tagSet = univ.OctetString.tagSet.tagExplicitly(
                        tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
                    )
    def getContentValue(self):
        buffer = ''
        for idx in xrange(len(self)):
            comp = self.getComponentByPosition(idx)
            buffer += comp
        return buffer._value


class Content(univ.Sequence):
    componentType = namedtype.NamedTypes(
                        namedtype.NamedType("content_type", univ.ObjectIdentifier()),
                        namedtype.NamedType("signed_content", SignedContent()),                    
                    )

class AlgIdentifiers(univ.SetOf):
    componentType = AlgorithmIdentifier()
            

class SignedData(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagExplicitly(
                                                tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
                                                )
    componentType = namedtype.NamedTypes(
                        namedtype.NamedType("version", univ.Integer()),                        
                        namedtype.NamedType("digestAlgs", AlgIdentifiers()),
                        namedtype.NamedType("content", Content())    
                    )

class MsgType(univ.ObjectIdentifier): pass



class SignVersion(univ.Integer):pass

class IssuerAndSerial(univ.Sequence):
    componentType = namedtype.NamedTypes(
                                         namedtype.NamedType("issuer", Name()),
                                         namedtype.NamedType("serialNumber", univ.Integer())
                                         )

class AuthAttributeValue(univ.Set): 
    pass
    

class AuthAttribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', univ.ObjectIdentifier()),
        namedtype.NamedType('value', AuthAttributeValue())
        )

# attributes are implicitly tagged sequence
class Attributes(univ.SetOf):
    tagSet = univ.Sequence.tagSet.tagImplicitly(
                                                tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
                                                )
    componentType = AuthAttribute()


class SignerInfo(univ.Sequence): 
    componentType = namedtype.NamedTypes(
                                        namedtype.NamedType("version", SignVersion()),
                                        namedtype.NamedType("issuerAndSerialNum", IssuerAndSerial()),
                                        namedtype.NamedType("digestAlg", AlgorithmIdentifier()),
                                        namedtype.OptionalNamedType("authAttributes", Attributes()),
                                        namedtype.NamedType("encryptAlg", AlgorithmIdentifier()),
                                        namedtype.NamedType("signature", univ.OctetString()),
                                        namedtype.OptionalNamedType("unauthAttributes", Attributes())
                                         )

class SignerInfos(univ.SetOf):
    componentType = SignerInfo()

class Message(univ.Sequence):
    componentType = namedtype.NamedTypes(
                        namedtype.NamedType("type", MsgType()),
                        namedtype.NamedType("signedData", SignedData()),
                        namedtype.NamedType("certificate", Certificate()),
                        namedtype.OptionalNamedType("crls", univ.Sequence())
                )
