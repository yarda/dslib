from client import Client

username = "kvm6ra"
password = "Schr8ne4ka"
ds_client = Client(username, password)


def GetListOfSentMessages():
  template = "%(dmOrdinal)-4s %(dmSender)-20s %(dmRecipient)-20s %(dmAnnotation)-20s %(dmDeliveryTime)-20s"
  heading = {"dmOrdinal":"Num",
             "dmSender":"Sender",
             "dmRecipient":"Recipient",
             "dmDeliveryTime":"DeliveryTime",
             "dmAnnotation":"Annotation",
             }
             
  print (template % heading).encode("utf-8")
  print "--------------------------------------------------------------------------------"
  for message in ds_client.GetListOfSentMessages():
    print (template % (message.__dict__)).encode("utf-8")


def GetListOfReceivedMessages():
  template = "%(dmOrdinal)-4s %(dmID)-8s %(dmSender)-20s %(dmRecipient)-20s %(dmAnnotation)-20s %(dmDeliveryTime)-20s"
  heading = {"dmOrdinal":"Num",
             "dmSender":"Sender",
             "dmRecipient":"Recipient",
             "dmDeliveryTime":"DeliveryTime",
             "dmAnnotation":"Annotation",
             "dmID":"ID",
             }
             
  print (template % heading).encode("utf-8")
  print "--------------------------------------------------------------------------------"
  for message in ds_client.GetListOfReceivedMessages():
    print (template % (message.__dict__)).encode("utf-8")


def MessageDownload():
  import tools
  for envelope in ds_client.GetListOfReceivedMessages():
    message = ds_client.MessageDownload(envelope.dmID)
    print "dmID:", message.dmReturnedMessage.dmDm.dmID
    print "dmSender:", message.dmReturnedMessage.dmDm.dmSender.encode('utf-8')
    print "dmAnnotation:", message.dmReturnedMessage.dmDm.dmAnnotation.encode('utf-8')
    print "Attachments:"
    for f in message.dmReturnedMessage.dmDm.dmFiles.dmFile:
      print "  '%s' saved" % tools.save_file(f, "./")


if __name__ == "__main__":
  import sys, inspect

  for name, f in inspect.getmembers(sys.modules[__name__], inspect.isfunction):
    print "==================== %s ====================" % name
    f()
    print "==================== end of %s ====================" % name    
    print
    print
