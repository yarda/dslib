# encoding: utf-8

from client import Client
import models

username = "kvm6ra"
password = "Schr8ne4ka"
ds_client = Client(username, password)

def active(f):
  """decorator to activate a test"""
  f.active = True
  return f

# ============================== Tests start here ==============================

#@active
def GetListOfSentMessages():
  template = "%(dmID)-8s %(dmSender)-20s %(dmRecipient)-20s %(dmAnnotation)-20s %(dmDeliveryTime)-20s"
  heading = {"dmID":"ID",
             "dmSender":"Sender",
             "dmRecipient":"Recipient",
             "dmDeliveryTime":"DeliveryTime",
             "dmAnnotation":"Annotation",
             }
             
  print (template % heading).encode("utf-8")
  print "------------------------------------------------------------------------------------"
  for message in ds_client.GetListOfSentMessages().data:
    print (template % (message.__dict__)).encode("utf-8")


#@active
def GetListOfReceivedMessages():
  template = "%(dmID)-8s %(dmSender)-20s %(dmRecipient)-20s %(dmAnnotation)-20s %(dmDeliveryTime)-20s"
  heading = {"dmSender":"Sender",
             "dmRecipient":"Recipient",
             "dmDeliveryTime":"DeliveryTime",
             "dmAnnotation":"Annotation",
             "dmID":"ID",
             }
             
  print (template % heading).encode("utf-8")
  print "------------------------------------------------------------------------------------"
  for message in ds_client.GetListOfReceivedMessages().data:
    print (template % (message.__dict__)).encode("utf-8")


#@active
def MessageDownload():
  for envelope in ds_client.GetListOfReceivedMessages().data:
    message = ds_client.MessageDownload(envelope.dmID).data
    print "dmID:", message.dmID
    print "dmSender:", message.dmSender.encode('utf-8')
    print "dmAnnotation:", message.dmAnnotation.encode('utf-8')
    print "Attachments:"
    for f in message.dmFiles:
      print "  '%s' saved" % f.save_file("./")


#@active
def MessageEnvelopeDownload():
  for envelope in ds_client.GetListOfReceivedMessages().data:
    message = ds_client.MessageEnvelopeDownload(envelope.dmID).data
    print "dmID:", message.dmID
    print "dmSender:", message.dmSender.encode('utf-8')
    print "dmAnnotation:", message.dmAnnotation.encode('utf-8')


#@active
def GetDeliveryInfo():
  import tools
  for envelope in ds_client.GetListOfSentMessages().data:
    message = ds_client.GetDeliveryInfo(envelope.dmID).data
    print "dmID:", message.dmID
    print "dmSender:", message.dmSender.encode('utf-8')
    print "dmAnnotation:", message.dmAnnotation.encode('utf-8')
    print "dmHash:", message.dmHash
    for event in message.dmEvents:
      print event
    print "----------------------------------------"

@active
def DummyOperation():
  print "Should be None None"
  reply = ds_client.DummyOperation()
  print "Actually is", reply.status, reply.data

@active
def FindDataBox():
  # part 1
  info = models.dbOwnerInfo()
  info.dbType = "OVM"
  info.firmName = u"Město Kladno"
  info.adZipCode = "27201"
  reply = ds_client.FindDataBox(info)
  print " * Should find one hit for Kladno"
  print (u"%-10s %-20s %-20s %-20s" % ("ID","Name","Street","City")).encode("utf-8")
  for owner in reply.data:
    print (u"%-10s %-20s %-20s %-20s" % (owner.dbID, owner.firmName, owner.adStreet, owner.adCity)).encode('utf-8')
  # part 2
  info = models.dbOwnerInfo()
  info.dbType = "OVM"
  info.firmName = u"Město"
  reply = ds_client.FindDataBox(info)
  print
  print " * Now much more hits starting with 'Město'"
  print (u"%-10s %-30s %-20s %-20s" % ("ID","Name","Street","City")).encode("utf-8")
  for owner in reply.data:
    print (u"%-10s %-30s %-20s %-20s" % (owner.dbID, owner.firmName, owner.adStreet, owner.adCity)).encode('utf-8')
  # part 3
  info = models.dbOwnerInfo()
  info.dbType = "OVM"
  info.firmName = u"Prase"
  reply = ds_client.FindDataBox(info)
  print
  print " * Should not find anything for 'Prase'"
  print "Result:", reply.data

if __name__ == "__main__":
  import sys, inspect

  for name, f in inspect.getmembers(sys.modules[__name__], inspect.isfunction):
    if hasattr(f, "active") and f.active:
      print "==================== %s ====================" % name
      f()
      print "==================== end of %s ====================" % name    
      print
      print
