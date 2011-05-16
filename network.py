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
#*    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
#*    02110-1301  USA
#*

import urllib2
import re

class Proxy(object):
  
  def __init__(self, uri, method='http', username=None, password=None):
    self.method = method 
    self.set_uri(uri)
    # username and password override data passed as part of the uri
    self.username = username
    self.password = password
    
  def set_uri(self, proxy):
    """interpret the proxy setting to obtain a real name and port or None"""
    if proxy == None:
      self.hostname = None
    else:
      if proxy == -1:
        uri = urllib2.getproxies().get(self.method, None)
      else:
        uri = proxy
      if uri:
        method, self.username, self.password, self.hostname = self.parse_uri(uri)
        if method:
          self.method = method
      else:
        self.hostname = None
        self.username = None
        self.password = None
    
  @classmethod
  def parse_uri(cls, uri):
    """returns tuple (method, username, password, hostname)"""
    return urllib2._parse_proxy(uri)
    
  def create_http_pass_manager(self):
    if self.hostname and self.username and self.password:
      man = urllib2.HTTPPasswordMgrWithDefaultRealm()
      man.add_password(None, self.hostname, self.username, self.password)
      return man
    return None
  
  def create_proxy_handler(self):
    if self.hostname:
      if self.username and self.password:
        full_uri = "%s://%s:%s@%s" % (self.method, self.username,
                                      self.password, self.hostname)
      else:
        full_uri = "%s://%s" % (self.method, self.hostname)
      return urllib2.ProxyHandler({self.method: full_uri})
    
  def create_proxy_auth_handler(self):
    return None
    #* There is a bug in Python that prevents the ProxyBasicAuthHandler from
    #* working with HTTPS anyway, so we use the password and username encoded
    #* in URI (see create_proxy_handler above) and this is here just for
    #* completeness and cleanliness of code
    #pass_man = self.create_http_pass_manager()
    #if pass_man:
    #  return urllib2.ProxyBasicAuthHandler(pass_man)

    

class ProxyManager(object):
  HTTP_PROXY = Proxy(None, method='http')
  HTTPS_PROXY = Proxy(None, method='https')

