import os
from suds.client import Client
import logging
logging.basicConfig(level=logging.INFO)
#logging.getLogger('suds.client').setLevel(logging.DEBUG)
#logging.getLogger('suds.resolver').setLevel(logging.DEBUG)
#
#logging.getLogger('suds.client').setLevel(logging.ERROR)
#logging.getLogger('suds.transport.http').setLevel(logging.DEBUG)

from suds.transport.http import HttpAuthenticated

boxname = "avzfin2"
username = "kvm6ra"
password = "Schr8ne4ka"
url_info="https://www.czebox.cz/DS/ds"
url_info="https://www.czebox.cz/nidp"
#url_info="http://localhost:4430/"
location = url_info #.replace("https://", "https://%s:%s@"%(username,password)) 

url = 'file://%s/wsdl/dm_operations.wsdl' % os.path.dirname(os.path.abspath(__file__))
#url = 'file://%s/wsdl/dm_info.wsdl' % os.path.dirname(os.path.abspath(__file__))
t = HttpAuthenticated(username=username, password=password)
client = Client(url, transport=t, username=username, password=password)

import constants
dmid = "142499"

# copied from http://osdir.com/ml/fedora-suds-list/2009-04/msg00008.html
from suds_helpers import suds_pickle, suds_unpickle

## reply = client.service.GetListOfReceivedMessages()
## print "-------------------- GetListOfReceivedMessages --------------------"
## print reply
## reply = client.service.MessageEnvelopeDownload(dmid)
reply = client.service.MessageDownload(dmid)
#print "-------------------- MessageEnvelopeDownload --------------------"
print reply



if True:
  import pickle
  store = suds_pickle(reply.dmReturnedMessage)
  f = file("message.dump","w")
  pickle.dump(store, f)
  f.close()
  reply2 = suds_unpickle(client.factory,store)
  print reply2
  
