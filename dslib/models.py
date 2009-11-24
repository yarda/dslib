# encoding: utf-8
"""
This modules hosts classes that reflect objects used in the
DS SOAP interface.
The purpose of these classes is to provide further functionality,
such as serialization, etc.
"""

import logging
import os
import constants


class Model(object):

  KNOWN_ATTRS = ()
  ATTR_TO_TYPE = {}

  def __init__(self, soap_message=None):
    self._init_default()
    if soap_message:
      self._load_from_soap(soap_message)


  def __unicode__(self):
    ret = u"%s:" % self.__class__.__name__
    for a in self.__class__.KNOWN_ATTRS:
      ret += u"\n  %s: %s" % (a, unicode(getattr(self, a)))
    return ret

  def __str__(self):
    return unicode(self).encode('utf-8')

  # ---------- private methods ----------

  def _init_default(self):
    for attr in self.__class__.KNOWN_ATTRS:
      if attr in self.__class__.ATTR_TO_TYPE:
        value = self.__class__.ATTR_TO_TYPE[attr]()
      else:
        value = None
      setattr(self, attr, value)


  def _load_from_soap(self, soap):
    _origin = soap.__class__.__name__
    for a in self.__class__.KNOWN_ATTRS:
      parent = soap
      self._load_one_attr(parent, a)


  def _load_one_attr(self, parent, attr):
    if hasattr(parent, attr):
      value = getattr(parent, attr)
      # some hardcoded stuff
      typ = value.__class__.__name__
      if typ == "tEventsArray":
        if type(value.dmEvent) == list:
          todo = value.dmEvent
        else:
          todo = [value.dmEvent]
        values = [dmEvent(child) for child in todo]
        setattr(self, attr, values)
      elif typ == "tFilesArray":
        values = [dmFile(child) for child in value.dmFile]
        setattr(self, attr, values)
      elif typ == "dmHash":
        setattr(self, attr, dmHash(value))
      else:
        setattr(self, attr, self._decode_soap_value(value))
    else:
      logging.debug("Attribute %s not present in %s", attr, parent.__class__.__name__)
    

        
  def _decode_soap_value(self, soap):
    """take a value as returned by SOAP and return a more suitable one;
    for example suds uses a class for text, so we translate to normal
    unicode string here"""
    if soap.__class__.__name__ == "Text":
      return unicode(soap)
    return soap

  def copy_to_soap_object(self, soap):
    for attr in self.KNOWN_ATTRS:
      value = getattr(self, attr)
      if value != None:
        # we do not copy default empty values
        setattr(soap, attr, value)
  

class Message(Model):
  """reflection of the DS message, which could be a result from
  several SOAP calles, namely: MessageDownload, MessageEnvelopeDownload,
  GetListOfSentMessages and GetListOfReceivedMessages"""

  KNOWN_ATTRS = ("dmID", "dbIDSender", "dmSender", "dmSenderAddress",
                 "dmSenderType", "dmRecipient", "dmRecipientAddress",
                 "dmAmbiguousRecipient", "dmSenderOrgUnit", "dmSenderOrgUnitNum",
                 "dbIDRecipient", "dmRecipientOrgUnit", "dmRecipientOrgUnitNum",
                 "dmToHands", "dmAnnotation", "dmRecipientRefNumber",
                 "dmSenderRefNumber", "dmRecipientIdent", "dmSenderIdent",
                 "dmLegalTitleLaw", "dmLegalTitleYear", "dmLegalTitleSect",
                 "dmLegalTitlePar", "dmLegalTitlePoint", "dmPersonalDelivery",\
                 "dmAllowSubstDelivery", "dmFiles",
                 "dmHash", "dmQTimestamp", "dmDeliveryTime", "dmAcceptanceTime",
                 "dmMessageStatus", "dmAttachmentSize", "dmEvents")

  ATTR_TO_TYPE = {"dmFiles":list, "dmEvents":list}

  # attributes of message returned outside in case of MessageEnvelopeDownload,
  # MessageDownload, GetDeliveryInfo
  OUTSIDE_ATTRS = ("dmDeliveryTime","dmAcceptanceTime","dmMessageStatus",
                   "dmAttachmentSize","dmHash","dmQTimestamp","dmEvents")

  # origins in which some info (described above in OUTSIDE_ATTRS) is placed outside
  SPLIT_ORIGINS = ("tReturnedMessageEnvelope","tReturnedMessage","tDelivery")


  # ---------- public methods ----------

  def get_origin(self):
    """returns a string describing from which SOAP call this Message comes;
    this could be used to determine which parts are (or should be) present."""
    return self._origin

  def get_status_description(self):
    return constants.MESSAGE_STATUS.get(self.dmMessageStatus, u"neznámy")

  # ---------- private methods ----------

  # overrides the Model._load_from_soap
  def _load_from_soap(self, soap):
    _origin = soap.__class__.__name__
    for a in Message.KNOWN_ATTRS:
      if a in Message.OUTSIDE_ATTRS or _origin not in Message.SPLIT_ORIGINS:
        # get if directly
        parent = soap
      else:
        parent = soap.dmDm
      self._load_one_attr(parent, a)
    self._origin = _origin
        


class dmFile(Model):
  """this class corresponds to the SOAP dmFile class"""

  KNOWN_ATTRS = ("_dmFileDescr","_dmUpFileGuid","_dmFileGuid","_dmMimeType","_dmFormat",
                 "_dmFileMetaType","dmEncodedContent")

  import os
  import base64

  def get_decoded_content(self):
    import base64
    return base64.standard_b64decode(self.dmEncodedContent)

  def get_size(self):
    """just approximate it"""
    return int(6.0 * len(self.dmEncodedContent) / 8)

  def save_file(self, dir, fname=None):
    """if fname is null, the one in the file_obj will be used"""
    if not fname:
      fname = self._dmFileDescr
    fullname = os.path.join(dir, fname)
    outf = file(fullname, "wb")
    outf.write(self.get_decoded_content())
    outf.close()
    return fullname



class dmEvent(Model):
  """corresponds to dmEvent SOAP class"""

  KNOWN_ATTRS = ("dmEventTime", "dmEventDescr")



class dmStatus(Model):
  """corresponds to dmStatus SOAP class"""

  KNOWN_ATTRS = ("dmStatusCode", "dmStatusMessage")


class dbStatus(Model):
  """corresponds to dmStatus SOAP class"""

  KNOWN_ATTRS = ("dbStatusCode", "dbStatusMessage")


class dmHash(Model):
  """corresponds to dmHash SOAP class"""

  KNOWN_ATTRS = ("value", "_algorithm")

  
class dbOwnerInfo(Model):

  KNOWN_ATTRS = ("dbID", "dbType", "ic", "pnFirstName", "pnMiddleName", "pnLastName",
                 "pnLastNameAtBirth", "firmName", "biDate", "biCity", "biCounty",
                 "biState", "adCity", "adStreet", "adNumberInStreet", "adNumberInMunicipality",
                 "adZipCode", "adState", "nationality", "identifier", "registryCode",
                 "dbState", "dbEffectiveOVM", "dbOpenAddressing")
