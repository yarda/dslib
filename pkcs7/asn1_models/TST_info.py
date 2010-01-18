'''
Model of TSTInfo - timestamp token sent back from TSA to the MVCR.
This token is encapsulated into pkcs7 content and signed by MVCR 
(Postsignum Qualified QCA)
'''

'''
TSTInfo ::= SEQUENCE  {
   version                      INTEGER  { v1(1) },
   policy                       TSAPolicyId,
   messageImprint               MessageImprint,
     -- MUST have the same value as the similar field in
     -- TimeStampReq
   serialNumber                 INTEGER,
    -- Time-Stamping users MUST be ready to accommodate integers
    -- up to 160 bits.
   genTime                      GeneralizedTime,
   accuracy                     Accuracy                 OPTIONAL,
   ordering                     BOOLEAN             DEFAULT FALSE,
   nonce                        INTEGER                  OPTIONAL,
     -- MUST be present if the similar field was present
     -- in TimeStampReq.  In that case it MUST have the same value.
   tsa                          [0] GeneralName          OPTIONAL,
   extensions                   [1] IMPLICIT Extensions   OPTIONAL  }
'''
import string
from pyasn1.type import tag,namedtype,univ,char,useful
from pyasn1 import error

from X509_certificate import *
from general_types import *
from oid import oid_map as oid_map

from certificate_extensions import *


class MessageImprint(univ.Sequence):
    componentType = namedtype.NamedTypes(
                        namedtype.NamedType("algId", AlgorithmIdentifier()),
                        namedtype.NamedType("imprint", univ.OctetString())
                                         )

class Accuracy(univ.Sequence):
    componentType = namedtype.NamedTypes(
                        namedtype.OptionalNamedType("seconds", univ.Integer()),
                        namedtype.OptionalNamedType("milis", univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x0))),
                        namedtype.OptionalNamedType("micros", univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x1)))
                        )
    
class TSAName(univ.Sequence):
    componentType = namedtype.NamedTypes(
                            namedtype.NamedType("name", RDNSequence().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x4))),
                                         )
    def __str__(self):
        return str(self.getComponentByName("name"))
    
class TSTInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
                        namedtype.NamedType("version", univ.Integer()),                        
                        namedtype.NamedType("policy", univ.ObjectIdentifier()),
                        namedtype.NamedType("messageImprint", MessageImprint()),
                        namedtype.NamedType("serialNum", univ.Integer()),
                        namedtype.NamedType("genTime", useful.GeneralizedTime()),
                        namedtype.OptionalNamedType("accuracy", Accuracy()),
                        namedtype.DefaultedNamedType("ordering", univ.Boolean('False')),
                        namedtype.OptionalNamedType("nonce", univ.Integer()),
                        namedtype.OptionalNamedType("tsa", TSAName().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x0))),                        
                        namedtype.OptionalNamedType("extensions", univ.Sequence().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x1)))
                    )