'''
Model of CRL
'''

'''
CertificateList  ::=  SEQUENCE  {
        tbsCertList          TBSCertList,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }

   TBSCertList  ::=  SEQUENCE  {
        version                 Version OPTIONAL,
                                     -- if present, MUST be v2
        signature               AlgorithmIdentifier,
        issuer                  Name,
        thisUpdate              Time,
        nextUpdate              Time OPTIONAL,
        revokedCertificates     SEQUENCE OF SEQUENCE  {
             userCertificate         CertificateSerialNumber,
             revocationDate          Time,
             crlEntryExtensions      Extensions OPTIONAL
                                      -- if present, version MUST be v2
                                  }  OPTIONAL,
        crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
                                      -- if present, version MUST be v2
                                  }

'''
import string
from pyasn1.type import tag,namedtype,univ,useful
from pyasn1 import error

from general_types import *
from X509_certificate import *

class RevokedCertInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('userCertificate', CertificateSerialNumber()),
        namedtype.NamedType('revocationDate', Time()),
        namedtype.OptionalNamedType('crlEntryExts', univ.Sequence())#Extensions())        
        )

class RevokedCertList(univ.SequenceOf):
    componentType = RevokedCertInfo()

class TbsCertList(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('version', Version()),
        namedtype.NamedType('signature', AlgorithmIdentifier()),
        namedtype.NamedType('issuer', Name()),        
        namedtype.NamedType('thisUpdate', Time()),
        namedtype.OptionalNamedType('nextUpdate', Time()),
        namedtype.OptionalNamedType('revokedCertificates', univ.Sequence()),#RevokedCertList()),
        namedtype.OptionalNamedType('crlExtensions', Extensions().\
                                    subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x0))),
        )


class RevCertificateList(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tbsCertList', TbsCertList()),
        namedtype.NamedType('signatureAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('signatureValue', univ.BitString())        
        )
