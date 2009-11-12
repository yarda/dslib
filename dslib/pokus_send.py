import os
from suds.client import Client
import logging
logging.basicConfig(level=logging.INFO)
#logging.getLogger('suds.client').setLevel(logging.DEBUG)
#logging.getLogger('suds.mx.literal').setLevel(logging.DEBUG)
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
client = Client(url, transport=t, xstq=False) #, location="http://localhost:8000")

#reply = client.service.MessageEnvelopeDownload(dmid)
create_message = client.factory.create('CreateMessage')
dmEnvelope = client.factory.create("dmEnvelope")
dmEnvelope.dbIDRecipient = "hjyaavk"
dmEnvelope.dmAnnotation = "tohle je pokus posilany z pythonu"
dmEnvelope.dmAllowSubstDelivery = False
dmEnvelope.dmPersonalDelivery = False
dmEnvelope.dmOVM = False
create_message.dmEnvelope = dmEnvelope

attach_file = client.factory.create("dmFile")
#print attach_file
attach_file._dmMimeType = "text/plain"
attach_file._dmFileMetaType = "main"
attach_file._dmFileDescr = "prilozeny_soubor.txt"
import base64
attach_file.dmEncodedContent = base64.standard_b64encode("tohle je pokusny text v pokusne priloze")
dmFiles = client.factory.create("dmFiles")
dmFiles.dmFile.append(attach_file)
print dmFiles

reply = client.service.CreateMessage(dmEnvelope, dmFiles)
print reply
