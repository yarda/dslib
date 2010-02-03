
#*    dslib - Python library for Datove schranky
#*    Copyright (C) 2009-2010  CZ.NIC, z.s.p.o. (http://www.nic.cz)
#*
#*    This library is free software; you can redistribute it and/or
#*    modify it under the terms of the GNU Library General Public
#*    License as published by the Free Software Foundation; either
#*    version 2 of the License, or (at your option) any later version.
#*
#*    This library is distributed in the hope that it will be useful,
#*    but WITHOUT ANY WARRANTY; without even the implied warranty of
#*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#*    Library General Public License for more details.
#*
#*    You should have received a copy of the GNU Library General Public
#*    License along with this library; if not, write to the Free
#*    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
#*
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

