"""
This is the main part of the dslib library - a client object resides here
which is responsible for all communication with the DS server
"""

# suds does not work properly without this
import sys, os
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from suds.client import Client as SudsClient
from suds.transport.http import HttpAuthenticated
import exceptions
from ds_exceptions import DSException


class Dispatcher(object):
  """
  DS splits its functionality between several parts. These have different URLs
  as well as different WSDL files.
  Dispatcher is a simple client that handles one of these parts
  """

  def __init__(self, ds_client, wsdl_url, soap_url=None):
    self.ds_client = ds_client # this is a Client instance; username, password, etc. will be take from it
    self.wsdl_url = wsdl_url
    self.soap_url = soap_url # if None, default will be used
    transport = HttpAuthenticated(username=self.ds_client.login, password=self.ds_client.password)
    self.soap_client = SudsClient(self.wsdl_url, transport=transport)

  def __getattr__(self, name):
    return getattr(self.soap_client.service, name)

  def _handle_dmrescords_and_status_response(self, method):
    reply = method()
    if int(reply.dmStatus.dmStatusCode) == 0:
      messages = reply.dmRecords.dmRecord
      # the following is a hack around a bug in the suds library that
      # does not properly create a list when only one object is present
      if type(messages) != list:
        return [messages]
      else:
        return messages
    else:
      raise DSException("Problem with %s" % method.__name__,
                        reply.dmStatus.dmStatusCode,
                        reply.dmStatus.dmStatusMessage)
    

  def GetListOfSentMessages(self):
    method = self.soap_client.service.GetListOfSentMessages
    return self._handle_dmrescords_and_status_response(method)

  def GetListOfReceivedMessages(self):
    method = self.soap_client.service.GetListOfReceivedMessages
    return self._handle_dmrescords_and_status_response(method)



class Client(object):

  WSDL_URL_BASE = 'file://%s/wsdl/' % os.path.dirname(os.path.abspath(__file__))

  attr2dispatcher_name = {"GetListOfSentMessages": "info",
                          "GetListOfReceivedMessages": "info",
                          "MessageDownload": "operations"
                          }

  dispatcher_name2config = {"info": {"wsdl_name": "dm_info.wsdl",
                                     },
                            "operations": {"wsdl_name": "dm_operations.wsdl",
                                           },
                            }

  def __init__(self, login=None, password=None):
    self.login = login
    self.password = password
    self._dispatchers = {}

  def __getattr__(self, name):
    """called when the user tries to access attribute or method;
    it looks if some dispatcher supports it and then returns the
    corresponding dispatchers method."""
    if name not in Client.attr2dispatcher_name:
      raise AttributeError("Client object does not have an attribute named '%s'"%name)
    dispatcher_name = Client.attr2dispatcher_name[name]
    dispatcher = self.get_dispatcher(dispatcher_name)
    return getattr(dispatcher, name)


  def get_dispatcher(self, name):
    """returns a dispatcher object based on its name;
    creates the dispatcher if it does not exist yet"""
    if name not in self._dispatchers:
      if name in Client.dispatcher_name2config:
        return self._create_dispatcher(name)
      else:
        raise Exception("Wrong or unsupported dispatcher name '%s'" % name)
    else:
      return self._dispatchers[name]

  def _create_dispatcher(self, name):
    """creates a dispatcher based on it name;
    config for a name is present in Client.dispatcher_name2config
    """
    config = Client.dispatcher_name2config[name]
    dis = Dispatcher(self, Client.WSDL_URL_BASE+config['wsdl_name'])
    self._dispatchers[name] = dis
    return dis


if __name__ == "__main__":
  import tools
  username = "kvm6ra"
  password = "Schr8ne4ka"
  c = Client(username, password)
  for message in c.GetListOfReceivedMessages():
    print "Message:", message.dmID
    m = c.MessageDownload(message.dmID)
    for f in m.dmReturnedMessage.dmDm.dmFiles.dmFile:
      print tools.save_file(f, "./")
    
