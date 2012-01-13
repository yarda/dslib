
#*    dslib - Python library for Datove schranky
#*    Copyright (C) 2009-2012  CZ.NIC, z.s.p.o. (http://www.nic.cz)
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
"""
in this file AbstractDSDatabase is located,
it is used as parent for specific database backends
"""

class AbstractDSDatabase(object):
  
  def __init__(self):
    pass
  
  def open_database(self, **kwargs):
    """should open the database. kwargs will be implementation specific"""
    raise NotImplementedError("this method should be overridden")  
  
  def close_database(self):
    """should close the database. The client is not usable until open_database
    is called again"""
    raise NotImplementedError("this method should be overridden")  
  
  def store_message(self, message):
    """message - dslib.models.Message instance"""
    raise NotImplementedError("this method should be overridden")
  
  def get_message(self, id):
    """return message by its id"""
    raise NotImplementedError("this method should be overridden")
  
  def find_messages(self, **kwargs):
    """return messages based on criteria supplied in kwargs"""
    raise NotImplementedError("this method should be overridden")
