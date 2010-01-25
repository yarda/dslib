# encoding: utf-8

from client import Client
import models
import sys

def active(f):
  """decorator to activate a test"""
  f.active = True
  return f

# ============================== Tests start here ==============================

@active
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


@active
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


@active
def MessageDownload():
  for envelope in ds_client.GetListOfReceivedMessages().data:
    message = ds_client.MessageDownload(envelope.dmID).data
    print "dmID:", message.dmID
    print "dmSender:", message.dmSender.encode('utf-8')
    print "dmAnnotation:", message.dmAnnotation.encode('utf-8')
    print "Attachments:"
    for f in message.dmFiles:
      print "  '%s' saved" % f.save_file("./")
    break # just the first one


@active
def MessageEnvelopeDownload():
  for envelope in ds_client.GetListOfReceivedMessages().data:
    message = ds_client.MessageEnvelopeDownload(envelope.dmID).data
    print "dmID:", message.dmID
    print "dmSender:", message.dmSender.encode('utf-8')
    print "dmAnnotation:", message.dmAnnotation.encode('utf-8')


@active
def GetDeliveryInfo():
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
  # part 4
  info = models.dbOwnerInfo()
  info.dbType = "OVM"
  info.dbID = u"hjyaavk"
  reply = ds_client.FindDataBox(info)
  print
  print " * Searching using dbID - should find Milotice only"
  print (u"%-10s %-30s %-20s %-20s" % ("ID","Name","Street","City")).encode("utf-8")
  for owner in reply.data:
    print (u"%-10s %-30s %-20s %-20s" % (owner.dbID, owner.firmName, owner.adStreet, owner.adCity)).encode('utf-8')
  # part 5
  info = models.dbOwnerInfo()
  info.dbType = "OVM"
  info.ic = u"00282651"
  reply = ds_client.FindDataBox(info)
  print
  print " * Searching using IC - should find Slapanice"
  print (u"%-10s %-30s %-20s %-20s" % ("ID","Name","Street","City")).encode("utf-8")
  for owner in reply.data:
    print (u"%-10s %-30s %-20s %-20s" % (owner.dbID, owner.firmName, owner.adStreet, owner.adCity)).encode('utf-8')
  
    
    
@active
def CreateMessage():
  envelope = models.dmEnvelope()
  envelope.dbIDRecipient = "hjyaavk"
  envelope.dmAnnotation = "tohle je dalsi pokus posilany z pythonu"
  dmfile = models.dmFile()
  dmfile._dmMimeType = "text/plain"
  dmfile._dmFileMetaType = "main"
  dmfile._dmFileDescr = "prilozeny_soubor.txt"
  import base64
  dmfile.dmEncodedContent = base64.standard_b64encode("tohle je pokusny text v pokusne priloze")
  dmfiles = [dmfile]
  reply = ds_client.CreateMessage(envelope, dmfiles)
  print reply.status
  print "Message ID is:", reply.data

@active
def GetOwnerInfoFromLogin():
  reply = ds_client.GetOwnerInfoFromLogin()
  print reply.status
  print reply.data

@active
def GetUserInfoFromLogin():
  reply = ds_client.GetUserInfoFromLogin()
  print reply.status
  print reply.data

@active
def SignedMessageDownload():
  for envelope in ds_client.GetListOfReceivedMessages().data:
    print "ID:", envelope.dmID
    reply = ds_client.SignedMessageDownload(envelope.dmID)    
    print reply.status
    print "ID matches:", reply.data.dmID, reply.data.dmID == envelope.dmID
    print "Verified message: %s" % reply.data.is_verified
    print "Verified certificate: %s" % reply.data.pkcs7_data.certificates[0].is_verified
    break

@active
def SignedSentMessageDownload():
  for envelope in ds_client.GetListOfSentMessages().data:
    print "ID:", envelope.dmID
    reply = ds_client.SignedSentMessageDownload(envelope.dmID)    
    print reply.status
    print "ID matches:", reply.data.dmID, reply.data.dmID == envelope.dmID
    print "Verified message: %s" % reply.data.is_verified
    print "Verified certificate: %s" % reply.data.pkcs7_data.certificates[0].is_verified
    break
  
@active
def GetSignedDeliveryInfo():  
  for envelope in ds_client.GetListOfSentMessages().data:
    print "ID:", envelope.dmID
    reply = ds_client.GetSignedDeliveryInfo(envelope.dmID)    
    print reply.status
    print "ID matches:", reply.data.dmID, reply.data.dmID == envelope.dmID
    print "Verified message: %s" % reply.data.is_verified
    print "Verified certificate: %s" % reply.data.pkcs7_data.certificates[0].is_verified
    break

@active
def GetPasswordInfo():
  reply = ds_client.GetPasswordInfo()
  print "Password expires: %s" %reply.data
  
@active
def ChangeISDSPassword():
  #old_pass = "Matej1234"
  import getpass
  old_pass = getpass.getpass("Current password:")
  new_pass = getpass.getpass("New password:")
  reply = ds_client.ChangeISDSPassword(old_pass, new_pass)
  print "%s : %s"% (reply.status.dbStatusCode, reply.status.dbStatusMessage)
  


if __name__ == "__main__":
  #import logging
  #logging.basicConfig(level=logging.INFO)
  #logging.getLogger('suds').setLevel(logging.DEBUG)
  
  def list_tests(tests):
    print "Available tests:"
    for i,test in enumerate(tests):
      print "  %2d. %s" % (i, test.__name__)
    print
    
  # get list of tests
  import sys, inspect
  tests = []
  for name, f in inspect.getmembers(sys.modules[__name__], inspect.isfunction):
    if hasattr(f, "active") and f.active:
      tests.append(f)

  # parse options
  from optparse import OptionParser
  import os
  op = OptionParser(usage="python %prog [options] username test+\n\nusername - the login name do DS\ntest - either a number or name of a test or 'ALL'")
  op.add_option( "-t", action="store_true",
                 dest="test_account", default=False,
                 help="the account is a test account, not a standard one.")
  op.add_option( "-p", action="store",
                 dest="proxy", default="",
                 help="address of HTTP proxy to be used (use 'SYSTEM' for default system setting).")
  
  (options, args) = op.parse_args()
  if len(args) <= 1:
    list_tests(tests)
    op.error("Too few arguments")
  username = args[0]
  # try to find a stored password
  passfile = "./.isds_password"
  if os.path.exists(passfile):
    print "Using password from '%s'" % passfile
    password = file(passfile,'r').read().strip()
  else:
    import getpass
    password = getpass.getpass()
  proxy = options.proxy
  if proxy == "SYSTEM":
    proxy = -1
  # read the tests
  to_run = []
  if 'ALL' in args[1:]:
    to_run = tests
  else:
    for test_name in args[1:]:
      if test_name.isdigit():
        test_id = int(test_name)
        if test_id < len(tests):
          to_run.append(tests[test_id])
        else:
          sys.stderr.write("Test %d does not exist!\n" % test_id)
      else:
        for test in tests:
          if test.__name__ == test_name:
            to_run.append(test)
            break
        else:
          sys.stderr.write("Test '%s' does not exist!\n" % test_name)
  # run the tests
  if to_run:      
    ds_client = Client(username, password, test_environment=options.test_account,\
                       proxy=proxy, trusted_certs_dir="trusted_certificates")
    for test in to_run:
      print "==================== %s ====================" % test.__name__
      # if testing password change, pass current password      
      test()
      print "==================== end of %s ====================" % test.__name__  
      print
      print
  else:
    list_tests(tests)

