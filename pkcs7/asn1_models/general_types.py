'''
Created on Dec 9, 2009

'''
from pyasn1.type import tag,namedtype,namedval,univ,constraint,char,useful
from pyasn1 import error

from tools import *
from oid import *

# constraint for length  should go away
MAX = 1000

class DirectoryString(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('teletexString', char.TeletexString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('printableString', char.PrintableString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('universalString', char.UniversalString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('utf8String', char.UTF8String().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('bmpString', char.BMPString().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.NamedType('ia5String', char.IA5String().subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX))), # hm, this should not be here!? XXX
        namedtype.NamedType('gString', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 0x19))) 
        )
    def __repr__(self):
        c = self.getComponent()
        return c.__str__()
    def __str__(self):
        return repr(self)

class AttributeValue(DirectoryString): pass
   

class AttributeType(univ.ObjectIdentifier): 
    def __str__(self):
        return tuple_to_OID(self._value)

class AttributeTypeAndValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeType()),
        namedtype.NamedType('value', AttributeValue())
        )
    def __repr__(self):
       # s = "%s => %s" % [ self.getComponentByName('type'), self.getComponentByName('value')]
       type = self.getComponentByName('type')
       value = self.getComponentByName('value')
       s = "%s => %s" % (type,value)
       return s
    
    def __str__(self):
        return self.__repr__()

class RelativeDistinguishedName(univ.SetOf):
    componentType = AttributeTypeAndValue()
    
    def __str__(self):
        buf = ''
        for component in self._componentValues:
            buf += str(component)
            buf += ','
        buf = buf[:len(buf)-1]
        return buf

class RDNSequence(univ.SequenceOf):
    componentType = RelativeDistinguishedName()
    
    def __str__(self):
        buf = ''        
        for component in self._componentValues:            
            buf += str(component)
            buf += ';'
        buf = buf[:len(buf)-1]
        return buf
            

class Name(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('', RDNSequence())
        )
    
    def __str__(self):
        return str(self.getComponent())
           
               
class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('parameters', univ.Null())
        # XXX syntax screwed?
#        namedtype.OptionalNamedType('parameters', univ.ObjectIdentifier())
        )
    def __repr__(self):
        tuple = self.getComponentByName('algorithm')
        str_oid = tuple_to_OID(tuple)
        return str_oid
    
    def __str__(self):
        return repr(self)
