"""
Here we define DS related exceptions
"""

class DSException(Exception):

  def __init__(self, message, code, text):
    self.message = message
    self.code = code
    self.text = text

  def __unicode__(self):
    return "%s (code: %s, text: %s)" % (self.message, self.code, self.text)
