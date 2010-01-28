'''
Implementing CRL cache
'''
import httplib
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('certs.crl_store')
logger.setLevel(logging.DEBUG)

import crl_verifier
import os


from pyasn1.codec.der import decoder
from pyasn1 import error

from pkcs7.asn1_models.crl import *

import pickle 
CRL_DUMP_DIR = ".crl_dumps"
CRL_DUMP_FILE = ".crl_dump"
CRL_ISSUER_PREF = ".iss_"
CRL_ISSUER_DIR_PREF = ".dir_iss_"
CRL_DPOINT_PREF  = ".dp_"

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
            #sn = revoked.getComponentByName("userCertificate")._value
            sn = revoked#.getComponentByPosition(0)._value
            if not self.revoked_certs.has_key(sn):
                #time = str(revoked.getComponentByName("revocationDate"))
                #time = str(revoked.getComponentByPosition(1))
                self.revoked_certs[sn] = None#time
                self.changed = True
                added_certs += 1
        return added_certs
        
    def find_certificate(self, cert_sn):
        '''
        Looks for certificate with certain serial number.
        Returns certificate serial number if found.
        '''
        if cert_sn in self.revoked_certs:
          return cert_sn
        return None
        #for sn in self.revoked_certs.keys():
        #    if sn == cert_sn:
        #        return sn, self.revoked_certs[sn]
        #return None, None
    
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
        # parse the unparsed content fo revokedCerts
        import fast_rev_cert_parser as fast_parser
        revoked_sns = fast_parser.parse_all(revoked._value)
        return self.__fill_revoked(revoked_sns)
        
    def pickle(self, fname):
        self.changed = False
        f = open(fname, "w")
        pickle.dump(self, f)
        f.close()        
    
    @classmethod
    def unpickle(self, fname):
        f = open(fname, "r")
        me = pickle.load(f)
        f.close()
        return me
        
class CRL_issuer():
        
    def __init__(self, name):
        self.name = name
        self.dist_points = []
        self.changed = False
        
    def __decode_crl(self, der_data):
        crl = decoder.decode(der_data, asn1Spec=RevCertificateList())[0]
        return crl
    
    def __clean_path(self, path):
        return path.rstrip(" ;,")
    
    def __parse_url(self, crl_url):
        url = crl_url
        if url.startswith("http://"):
            url = url[7:]
        slash = url.find('/')
        hostname = url[:slash]
        path = url[slash:]
        return hostname, path
    
    def __download_crl(self, url):
        logger.debug("Downloading CRL from %s" % url)
        hostname, path = self.__parse_url(url)
        path = self.__clean_path(path)
        con = httplib.HTTPConnection(hostname)
        con.request("GET", path)
        resp = con.getresponse()
        c = resp.read()
        logger.debug("Downloading finished")
        return c
    
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
                crl = self.__decode_crl(downloaded)
                if (verification is not None):                    
                    verified = crl_verifier.verify_crl(crl, verification)
                    if not verified:
                        logger.warning('CRL verification failed')
                        return 0
                    else:
                        logger.info("CRL verified")
                return dpoint.update_revoked_list(crl)
        else:
            logger.error("Distpoint %s not found. Has it already been added?"%url)
            return 0
            
    def is_certificate_revoked(self, cert_sn):
        '''
        Looks in each distpoint for certificate with
        cert_sn serial number. Returns date of revocation or None
        '''
        if not len(self.dist_points):
          logger.info("This issuer has no CDP")
        for dpoint in self.dist_points:
            sn = dpoint.find_certificate(cert_sn)
            if sn is not None:
                logger.debug("Certificate %s revoked in %s" % (cert_sn, dpoint.url))
                return sn
        return None
            
        
    def refresh_dist_point(self, url, verification=None):
        '''
        Refreshes CRL of distribution point specified by url.
        If the time of thisUpdate of downloaded CRL is the same 
        as time in lastUpdate of current version, does not do anything.
        Returns number of added certificates
        '''
        dpoint = self.find_dpoint(url)
        if dpoint is not None:
            last_updated = dpoint.lastUpdated
            logger.debug("Refreshing dpoint %s", url)
            # download crl
            downloaded = self.__download_crl(url)
            # decode it and get the update time
            crl = self.__decode_crl(downloaded)
            if (verification is not None):                    
                verified = crl_verifier.verify_crl(crl, verification)
                if not verified:
                    logger.warning('CRL verification failed')
                    return 0
                else:
                    logger.info("CRL verified")
            downloaded_update_time = str(crl.getComponentByName("tbsCertList").getComponentByName("thisUpdate"))
            # if there was new crl issued, commit changes to local copy
            if dpoint.lastUpdated != downloaded_update_time:
                logger.info("New CRL detected, current version: %s, new version: %s",\
                             dpoint.lastUpdated, downloaded_update_time)
                added_certs = dpoint.update_revoked_list(crl)
                logger.info("Added %d new revoked certificate serial numbers" % added_certs)
                if added_certs:
                    self.changed = True
                return added_certs
            else:
                logger.info("Downloaded CRL is the same as current, no changes in list of revoked certificates")
                return 0
    
    
    def pickle(self, fname, issuer_id):
        self.changed = False
        import hashlib
        f = open(fname, "w")
        pickle.dump(self, f)
        f.close()
        
        for i in xrange(len(self.dist_points)):
            dpoint = self.dist_points[i]            
            s = hashlib.sha1()
            s.update(dpoint.url)
            fname = s.hexdigest()
            if (dpoint.changed):
                dpoint.pickle(CRL_DUMP_DIR+ "/"+\
                              CRL_ISSUER_DIR_PREF+str(issuer_id)+\
                              "/"+CRL_DPOINT_PREF+str(i))
    
    @classmethod
    def unpickle(self, from_file):
        f = open(from_file, "r")
        issuer = pickle.load(f)
        f.close()                  
        return issuer

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
        return None
    
    def is_certificate_revoked(self, issuer_name, cert_sn):
        '''
        Returns date of revocation of the certificate from
        specified issuer.
        '''        
        iss = self.get_issuer(issuer_name)
        if iss is None:
            raise "Issuer %s not found" % issuer_name
        sn = iss.is_certificate_revoked(cert_sn)
        if sn:
          return True
        else:
          return False
        
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
        f = open(CRL_DUMP_DIR+"/"+CRL_DUMP_FILE, "w")
        pickle.dump(self, f, pickle.HIGHEST_PROTOCOL)
        f.close()
        
        
    @classmethod
    def unpickle(self,fname):
        '''
        Loads cache instance from a file
        '''
        f = open(fname, "r")
        cache = pickle.load(f)
        f.close()   
        return cache

def _restore_dpoints(dir):
    dps = []
    fnames = os.listdir(dir)
    for fname in fnames:
        dp = CRL_dist_point.unpickle(dir+"/"+fname)
        dps.append(dp)
    return dps
    
def _restore_cache():
    try:
        crl_fname = CRL_DUMP_DIR+"/"+CRL_DUMP_FILE
        cache = CRL_cache.unpickle(crl_fname)
        return cache
    except Exception as ex:
        logger.warning(ex)
        logger.warning("Cache restore failed")        
        return None




class CRL_cache_manager():
  _crl_cache = None
  
  @classmethod
  def get_cache(self): 
    global _crl_cache
       
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

    