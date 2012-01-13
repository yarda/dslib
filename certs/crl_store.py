
#*    dslib - Python library for Datove schranky
#*    Copyright (C) 2009-2012  CZ.NIC, z.s.p.o. (http://www.nic.cz)
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
Implementing CRL cache
'''

# standard library imports
import urllib2
import logging
import sys
logger = logging.getLogger('certs.crl_store')
import os
import pickle 

# dslib imports
from pyasn1.codec.der import decoder
from pyasn1 import error
from dslib.pkcs7.asn1_models.crl import *

# local imports
import crl_verifier
import timeutil
import fast_rev_cert_parser as fast_parser

CRL_DUMP_DIR = ".crl_dumps"
CRL_DUMP_FILE = ".crl_dump"

CRL_DIST_POINT_EXT_ID = '2.5.29.31'

def extract_crl_distpoints(certificate):
    '''
    extracts CRL dist point information from certificate extensions.
    returns list of tuples (issuer, url)
    '''    
    res = []    
    for ext in certificate.tbsCertificate.extensions:
        if ext.id == CRL_DIST_POINT_EXT_ID:
            for dpinfo in ext.value:
                res.append(dpinfo.dist_point.rstrip(" ;,"))
    return res
    
      


class CRL_dist_point():
    '''
    CRL distribution point
    '''
    
    def __init__(self, url):
        self.url = url
        self.revoked_certs = {}
        self.lastUpdated = None
        self.nextUpdate = None
        self.changed = False

    def __fill_revoked(self, revoked_sn_list):
        '''
        Fills list of revoked certs with new certificates.
        Returns number of added certificates
        '''       
        added_certs = 0
        for revoked in revoked_sn_list:            
            sn = revoked[0]
            if not self.revoked_certs.has_key(sn): 
                # write the revocation time of this key (cert serial number) 
                self.revoked_certs[sn] = revoked[1]
                self.changed = True
                added_certs += 1
        return added_certs
    
    def seconds_from_last_update(self):
        '''
        Returns number of seconds from the last update
        '''
        last = self.lastUpdated
        #format = '%y%m%d%H%M%SZ'        
        t1 = timeutil.to_seconds_from_epoch(last)#time.mktime(time.strptime(last, format))         
        t2 = timeutil.to_seconds_from_epoch()#time.mktime(time.gmtime())
        
        diff = t2 - t1
        return diff
        
    def find_certificate(self, cert_sn):
        '''
        Looks for certificate with certain serial number.
        Returns certificate revocation date if found.
        '''
        if cert_sn in self.revoked_certs:
          return self.revoked_certs[cert_sn]
        return None
        
    
    def update_revoked_list(self, crl):   
        '''
        Updates current list of revoked certificates with data from the 
        downloaded and parsed crl. 
        Returns number of added certificates
        '''
        thisUpdate = str(crl.getComponentByName("tbsCertList").\
                            getComponentByName("thisUpdate"))
        nextUpdate = str(crl.getComponentByName("tbsCertList").\
                            getComponentByName("nextUpdate"))
        self.lastUpdated = thisUpdate
        self.nextUpdate = nextUpdate
        revoked = crl.getComponentByName("tbsCertList").\
                        getComponentByName("revokedCertificates")
        # parse the unparsed content for revokedCerts        
        revoked_sns = fast_parser.parse_all(revoked._value)

        return self.__fill_revoked(revoked_sns)
    
        
class CRL_issuer():
        
    def __init__(self, name):
        self.name = name
        self.dist_points = []
        self.changed = False
        
    def __decode_crl(self, der_data):
        crl = decoder.decode(der_data, asn1Spec=RevCertificateList())[0]
        return crl
    
    def __download_crl(self, url):
        logger.debug("Downloading CRL from %s" % url)
        # we construct an urlopener using proxy settings
        from dslib.network import ProxyManager
        prox_hand = ProxyManager.HTTP_PROXY.create_proxy_handler()
        prox_auth_hand = ProxyManager.HTTP_PROXY.create_proxy_auth_handler()
        opener = urllib2.build_opener()
        if prox_hand:
          opener.add_handler(prox_hand)
        if prox_auth_hand:
          opener.add_handler(prox_auth_hand)
        try:
          f = opener.open(url, timeout=10)
          c = f.read()
          logger.debug("Downloading finished")
          return c
        except:
          logger.warning("Downloading crl from %s failed!" % url)
          return None
      
    def find_dpoint(self, url):
        for dpoint in self.dist_points:
            if dpoint.url == url:
                return dpoint
        return None
    
    
    def add_dist_point(self, url):
        dpoint = self.find_dpoint(url)
        if dpoint is None:
            if not url.startswith('http://'):
              logger.warning("Only HTTP distribution ports supported")
              logger.warning("CDP %s not added" % url)
              return None
            dpoint = CRL_dist_point(url)       
            self.dist_points.append(dpoint)
            self.changed = True
            return dpoint
        else:
            logger.warning('Issuer already contains this dist point')
            return None
    
    def init_dist_point(self, url, verification=None):
        '''
        Initializes CDP - downloads and parses CRL.
        Returns number of certificates added to revoked
        certificates list.
        '''
        dpoint = self.find_dpoint(url)
        if dpoint is not None:
            self.changed = True
            if dpoint.lastUpdated is None:
                logger.debug("Initializing dpoint %s", url)
                downloaded = self.__download_crl(url)
                if downloaded is None:
                  return False, 0
                crl = self.__decode_crl(downloaded)
                if (verification is not None):                    
                    verified = crl_verifier.verify_crl(crl, verification)
                    if not verified:
                        logger.warning('CRL verification failed')
                        return True, 0
                    else:
                        logger.info("CRL verified")
                return True, dpoint.update_revoked_list(crl)
            else:
              logger.warning("CDP %s is already initialized. Try to refresh it" % url)
              return True, 0
        else:
            logger.error("Distpoint %s not found. Has it already been added?"%url)
            return True, 0
            
    def certificate_revoked(self, cert_sn):
        '''
        Looks in each distpoint for certificate with
        cert_sn serial number. Returns date of revocation or None
        '''
        if not len(self.dist_points):
          logger.info("This issuer has no CDP")
        for dpoint in self.dist_points:
            rev_date = dpoint.find_certificate(cert_sn)
            if rev_date is not None:
                logger.debug("Certificate %s revoked on %s" % (cert_sn, rev_date))
                return rev_date
        #return "100330140210T"
        return None
    
    def refresh_issuer(self, verification=None, force_crl_download=False):
        '''
        Refresh CDPs of this issuer. Goes through
        CDPS, tries to refresh them. Stops after first successful refresh.
        Returns result of download attempt and number of added certificates
        '''
        logger.info("Refreshing issuer %s" % self.name)
        for dp in self.dist_points:
          success, added_certs = self.refresh_dist_point(dp.url, \
                                                         verification,\
                                                         force_crl_download)
          if success:            
            return True, added_certs
          else:
            logger.warning("CDP %s failed to download" % dp.url)
        # refreshing of each CDP failed
        return False, 0    
        
    def refresh_dist_point(self, url, verification=None, force_download=False):
        '''
        Refreshes CRL of distribution point specified by url.
        If the time of thisUpdate of downloaded CRL is the same 
        as time in lastUpdate of current version, does not do anything.
        Returns boolean value telling the result of download attempt and number of added certificates
        '''
        dpoint = self.find_dpoint(url)
        if dpoint is not None:
            last_updated = dpoint.lastUpdated
            logger.debug("Refreshing dpoint %s", url)
            # check time of next update - if it is in the future, return True,0
            # download only in case when nextUpdate time passed               
            if force_download:
              logger.debug("Force download parameter set, ignoring nextUpdate parameter of CRL")             
            else:
              # if force download was not set, check the nextUpdate parameter
              if dpoint.nextUpdate:
                next_time = timeutil.to_time(dpoint.nextUpdate)         
                current_time = timeutil.now()
                if current_time >= next_time:
                  logger.info("Next update time passed, downloading CRL")
                else:
                  logger.info("Next update scheduled on %s, not downloading anything" % dpoint.nextUpdate)
                  return True, 0
              else:
                logger.info("No previous download recorded, downloading CRL")
            # download CRL
            downloaded = self.__download_crl(url)
            if downloaded is None:
              return False, 0
            # decode it and get the update time
            crl = self.__decode_crl(downloaded)
            if (verification is not None):                    
                verified = crl_verifier.verify_crl(crl, verification)
                if not verified:
                    logger.warning('CRL verification failed')
                    return True, 0
                else:
                    logger.info("CRL verified")
            else:
              logger.info("CRL verification not performed, no certificate provided")
            downloaded_update_time = str(crl.getComponentByName("tbsCertList").getComponentByName("thisUpdate"))
            # if there was new crl issued, commit changes to local copy
            if dpoint.lastUpdated != downloaded_update_time:
                logger.info("New CRL detected, current version: %s, new version: %s",\
                             dpoint.lastUpdated, downloaded_update_time)
                added_certs = dpoint.update_revoked_list(crl)
                logger.info("Added %d new revoked certificate serial numbers" % added_certs)
                if added_certs:
                    self.changed = True
                return True, added_certs
            else:
                logger.info("Downloaded CRL is the same as current, no changes in list of revoked certificates")
                return True, 0
    
    
class CRL_cache():
    '''
    Represents cache of CRLs. Contains issuers of CRLs.
    The are identified by their name - string format of Name
    object.
    '''
        
    def __init__(self):
      self.issuers = []    
      self.changed = False
        
    def add_issuer(self, issuer_name):
        '''
        Adds new issuer of CRLs.
        Returns CRL_issuer instance or None, if issuer 
        already exists.
        '''
        iss = self.get_issuer(issuer_name)
        if iss is None:
            iss = CRL_issuer(issuer_name)        
            self.issuers.append(iss)
            self.changed = True
            return iss
        else:
            logger.warn('Cache already contains this issuer')
            return None
    
    def get_issuer(self, issuer_name):
        '''
        Returns issuer with specified name or None
        '''
        for issuer in self.issuers:
            if issuer.name == issuer_name:
                return issuer
        logger.warning("Issuer %s not found in cache" % issuer_name)
        return None
    
    def is_certificate_revoked(self, issuer_name, cert_sn):
        '''
        Returns date of revocation of the certificate from
        specified issuer. If certificate is not revoked, returns None
        '''        
        iss = self.get_issuer(issuer_name)
        if iss is None:
            raise Exception("Issuer %s not found" % issuer_name)
        rev_date = iss.certificate_revoked(cert_sn)
        if rev_date is None:
          return False
        else:
          return True
      
    def certificate_rev_date(self, issuer_name, cert_sn):
        '''
        Returns certificate revocation date (UTC string).
        If certificate is not revoked, returns None
        '''
        iss = self.get_issuer(issuer_name)
        if iss is None:
            iss = self.add_issuer(issuer_name)
            #raise Exception("Issuer %s not found" % issuer_name)
        rev_date = iss.certificate_revoked(cert_sn)
        return rev_date
        
    def pickle(self):   
        '''
        Stores the cache instance into a file
        ''' 
        # check if we have to pickle
        has_to_pickle = False
        if self.changed:
            has_to_pickle = True
        else:
            for iss in self.issuers:
                if iss.changed:
                    has_to_pickle = True
                    break
        if not has_to_pickle:
            logging.info("No changes since last load, pickling aborted")
            return
        
        self.changed = False
        import os.path
        if not os.path.exists(CRL_DUMP_DIR):
          logger.debug("Creating directory %s to pickle the CRL cache" % CRL_DUMP_DIR)
          os.mkdir(CRL_DUMP_DIR)
        path_to_cache = os.path.join(CRL_DUMP_DIR, CRL_DUMP_FILE)
        logger.debug("Opening file %s to write the CRL cache" % CRL_DUMP_FILE)
        f = open(path_to_cache, "w")
        pickle.dump(self, f, pickle.HIGHEST_PROTOCOL)
        f.close()
        logger.debug("CRL cache stored to file %s" % path_to_cache)
        
       
    @classmethod
    def unpickle(self,fname):
        '''
        Loads cache instance from a file
        '''
        f = open(fname, "rb")
        cache = pickle.load(f)
        f.close()   
        return cache
    
def _restore_cache():
    try:
        crl_fname = os.path.join(CRL_DUMP_DIR, CRL_DUMP_FILE)
        cache = CRL_cache.unpickle(crl_fname)
        return cache
    except Exception, ex:
        logger.warning(ex)
        logger.warning("Cache restore failed")        
        return None




class CRL_cache_manager():
  _crl_cache = None
  
  @classmethod
  def get_cache(self): 
    #global _crl_cache
       
    if self._crl_cache is None:
      # try to restore cache
      cache = _restore_cache()
      # if restoring failed   
      if cache is None:    
        logger.info("CRL cache not found locally, returning empty cache")  
        self._crl_cache = CRL_cache()
      else:
        logger.info("Cache restored from local storage")
        self._crl_cache = cache
    return self._crl_cache

    