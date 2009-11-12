"""
This module contains some help functions specific to the suds library.
"""

# ** pickling and unpickling **
# based on http://osdir.com/ml/fedora-suds-list/2009-04/msg00008.html

from suds.sudsobject import asdict, Object
from suds.sax.text import Text
import types

def suds_pickle(sobject):
  return {'class_name': sobject.__class__.__name__,
          'data': _pickle_one(sobject)}
  
import inspect

def _pickle_one(sobject):
  begin = asdict(sobject)
  for key, value in begin.iteritems():
    if isinstance(value, Object):
      begin[key] = _pickle_one(value)
    elif type(value) == types.InstanceType:
      # this again fixes some trouble inside suds preventing proper introspection
      #print "YYYY", key, type(value), isinstance(value, Text), value.__class__.__name__
      begin[key] = _pickle_one(value)
    elif value.__class__.__name__ == "Text":
      # this is a nasty hack, but there is some magic that prevents
      # isinstance from working in some cases :(
      begin[key] = unicode(value)
    elif type(value) == list:
      begin[key] = [_pickle_one(_x) for _x in value]
    else:
      pass
      #print "XXXXX", key, type(value), isinstance(value, Text), value.__class__.__name__
  return begin
  

def suds_unpickle(factory, dct):
  assert 'class_name' in dct
  assert 'data' in dct
  inst = factory.create(dct['class_name'])

  def fill(dct, pnt):
    for key, value in dct.iteritems():
      if isinstance(value, dict):
        fill(value, getattr(pnt, key))
      else:
        setattr(pnt, key, value)

  fill(dct['data'], inst)
  return inst
