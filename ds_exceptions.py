
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

"""
Here we define DS related exceptions
"""

class DSException(Exception):
  
  def __unicode__(self):
    return "DSException"

  def __str__(self):
    return unicode(self).encode("utf-8")

class DSGenericException(DSException):

  def __init__(self, message, code, text):
    self.message = message
    self.code = code
    self.text = text

  def __unicode__(self):
    return "%s (code: %s, text: %s)" % (self.message, self.code, self.text)
  
  def __str__(self):
    return unicode(self).encode("utf-8")
  

class DSSOAPException(DSException):
  """fired when something in OTP authorization got out of hand"""
  
  def __init__(self, status_code, status_message):
    self.status_code = status_code
    self.status_message = status_message
    
  def __unicode__(self):
    return "SOAP Error:\nStatusCode: %s\nStatusMessage: %s" % \
            (self.status_code, self.status_message) 


class DSOTPException(DSException):
  """fired when something in OTP authorization got out of hand"""
  
  OTP_CANCELED_BY_USER = 1
  LOGOUT_NOT_POSSIBLE = 2
  
  def __init__(self, code, text):
    self.code = code
    self.text = text
    
  def __unicode__(self):
    return "OTP Error %s: %s" % (self.code, self.text) 
  
  
class DSNotAuthorizedException(DSException):
  """fired when the client could not be authorized by the server"""
  
  def __init__(self, http_exc):
    self.text = ""
    self.code = ""
    self._extract_data_from_http_exc(http_exc)
    
    
  def _extract_data_from_http_exc(self, e):
    from email.header import decode_header
    self.code = e.headers.get("x-response-message-code", "")
    text = e.headers.get("x-response-message-text", "")
    if text:
      try:
        ret = decode_header(text)
      except:
        pass
      else:
        if ret:
          text, encoding = ret[0]
          if encoding:
            text = text.decode(encoding)
    self.text = text
    
  def __unicode__(self):
    return "Authorization error %s: %s" % (self.code, self.text) 
