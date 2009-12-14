'''
Created on Dec 9, 2009

@author: mdioszegi
'''
from pyasn1.type import tag,namedtype,namedval,univ,constraint,char,useful
from pyasn1 import error

from general_types import AlgorithmIdentifier

class DigestInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
                                         namedtype.NamedType("digestAgorithm", AlgorithmIdentifier()),
                                         namedtype.NamedType("digest", univ.OctetString())
                                         )
    