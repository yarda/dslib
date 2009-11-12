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

url = 'file://%s/wsdl/dm_operations.wsdl' % os.path.dirname(os.path.abspath(__file__))
t = HttpAuthenticated(username=username, password=password)
client = Client(url, transport=t)

dmid = "142499"
reply = client.service.MessageDownload(dmid)
print reply
