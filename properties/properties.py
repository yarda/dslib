
#*    dslib - Python library for Datove schranky
#*    Copyright (C) 2009-2010  CZ.NIC, z.s.p.o. (http://www.nic.cz)
#*
#*    This library is free software; you can redistribute it and/or
#*    modify it under the terms of the GNU Library General Public
#*    License as published by the Free Software Foundation; either
#*    version 2 of the License, or (at your option) any later version.
#*
#*    This library is distributed in the hope that it will be useful,
#*    but WITHOUT ANY WARRANTY; without even the implied warranty of
#*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#*    Library General Public License for more details.
#*
#*    You should have received a copy of the GNU Library General Public
#*    License along with this library; if not, write to the Free
#*    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#*
from ConfigParser import ConfigParser


class Properties:
  
  #default values
  VERIFY_MESSAGE = True
  VERIFY_TIMESTAMP =  True
  VERIFY_CERTIFICATE = True
  CHECK_CRL = True
  FORCE_CRL_DOWNLOAD = True
  
  # these properties are expected boolean
  _boolean_values = [
                     "VERIFY_MESSAGE", "VERIFY_TIMESTAMP",
                     "VERIFY_CERTIFICATE", "CHECK_CRL", 
                     "FORCE_CRL_DOWNLOAD"
                     ]
  
  # these properties are expected as integers/longs
  _integer_values = []
  
  # name of the section in the config file that contains security props
  SECURITY_SECTION_NAME = "security"
  
  @classmethod
  def __str_to_bool(cls, str):
    return str[0].upper == 'T'
  
  @classmethod
  def __str_to_long(cls, str):
    return long(str)
    
  @classmethod
  def load_from_file(self,file):
    '''
    Loads properties from specified file.
    File format is one property /line in form:
    property_name=property_value
    Properties are grouped [{SECURITY_SECTION_NAME}] section
    '''
    cfg = ConfigParser()
    cfg.read(file)
    sec_items = cfg.items(self.SECURITY_SECTION_NAME)
    for i in xrange(len(sec_items)):
      name = sec_items[i][0].upper()
      if name in self._boolean_values:        
        setattr(self, name, self.__str_to_bool(sec_items[i][1]))
      elif name in self._integer_values:
        setattr(self, name, self.__str_to_long(sec_items[i][1]))
      else:
        setattr(self, name, sec_items[i][1])
    
    
