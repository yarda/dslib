'''
Utility for converting timestring used in 
databoxes into time structures.
'''
import time

TIME_FORMAT = '%y%m%d%H%M%SZ'


def now():
  '''
  Returns actual GMT time
  '''
  return time.gmtime()

def to_time(string_time):
  '''
  Converts time in string from databox to time struct 
  '''
  res_time = time.strptime(string_time, TIME_FORMAT)
  return res_time

def to_seconds_from_epoch(string_time=None):
  '''
  Converts time from databox into seconds from 1/1/70.
  If parameter is None, returns current time (seconds from epoch)
  '''
  if string_time is None:
    return time.mktime(now())
  return time.mktime(to_time(string_time))   

