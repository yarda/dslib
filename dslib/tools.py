import os
import base64

def save_file(file_obj, dir, fname=None):
  """if fname is null, the one in the file_obj will be used"""
  if not fname:
    fname = file_obj._dmFileDescr
  fullname = os.path.join(dir, fname)
  outf = file(fullname, "wb")
  outf.write(base64.standard_b64decode(file_obj.dmEncodedContent))
  outf.close()
  return fullname
