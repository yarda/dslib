"""
Provides useful functionality for discovering where data files
are and other things specific for one installation.
"""

import sys
import os

try:
  local_dir = os.path.dirname(__file__)
except NameError:
  local_dir = os.path.dirname(sys.executable)
local_dir = local_dir.decode(sys.getfilesystemencoding())
  
def find_data_directory(name):
  # at first try path set in environment variable
  env_path = os.environ.get("DSLIB_DATA_DIR", None)
  if env_path:
    path = os.path.join(env_path, name)
    if os.path.isdir(path):
      return path
  # then try path relative to this file
  local_path = os.path.join(local_dir, name)
  if os.path.isdir(local_path):
    return local_path
  # try relative path inside an egg
  if os.path.dirname(local_dir).endswith(".egg"):
    local_path = os.path.join(os.path.dirname(local_dir),'share','dslib',name)
    if os.path.isdir(local_path):
      return local_path
  # then the system path
  system_path = os.path.join(sys.prefix, "share", "dslib", name)
  if os.path.isdir(system_path):
    return system_path

  # then the system path local (ubuntu dists)
  system_path = os.path.join(sys.prefix, "local", "share", "dslib", name)
  if os.path.isdir(system_path):
    return system_path

  raise ValueError("Could not find data dir '%s'" % name)