'''
Created on Dec 9, 2009

'''
from pyasn1.type import tag,namedtype,univ
from pyasn1 import error

from general_types import AlgorithmIdentifier

class DigestInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
                                         namedtype.NamedType("digestAgorithm", AlgorithmIdentifier()),
                                         namedtype.NamedType("digest", univ.OctetString())
                                         )
    