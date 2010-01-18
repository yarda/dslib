'''
Implementing CRL cache
'''
import httplib
import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('certs.crl_store')

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
                res.append((dpinfo.issuer, dpinfo.dist_point.rstrip(" ;,")))
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

    def __fill_revoked(self, revoked_list):
        for revoked in revoked_list:
            #sn = revoked.getComponentByName("userCertificate")._value
            sn = revoked.getComponentByPosition(0)._value
            if not self.revoked_certs.has_key(sn):
                #time = str(revoked.getComponentByName("revocationDate"))
                time = str(revoked.getComponentByPosition(1))
                self.revoked_certs[sn] = time
        
    def find_certificate(self, cert_sn):
        '''
        Looks for certificate with certain serial number.
        Returns certificate serial number and time of revocation,
        if found.
        '''
        for sn in self.revoked_certs.keys():
            if sn == cert_sn:
                return sn, self.revoked_certs[sn]
        return None, None
    
    def update_revoked_list(self, crl):   
        '''
        Updates current list of revoked certificates with data from the 
        downloaded and parsed crl
        '''
        thisUpdate = str(crl.getComponentByName("tbsCertList").\
                            getComponentByName("thisUpdate"))
        nextUpdate = str(crl.getComponentByName("tbsCertList").\
                            getComponentByName("nextUpdate"))
        self.lastUpdated = thisUpdate
        self.nextUpdate = nextUpdate
        revoked = crl.getComponentByName("tbsCertList").\
                        getComponentByName("revokedCertificates")
        self.__fill_revoked(revoked)
        
    def pickle(self, fname):
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
    
    dist_points = []
    
    def __init__(self, name):
        self.name = name
    
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
        hostname, path = self.__parse_url(url)
        path = self.__clean_path(path)
        con = httplib.HTTPConnection(hostname)
        con.request("GET", path)
        resp = con.getresponse()
        c = resp.read()
        return c
    
    def find_dpoint(self, url):
        for dpoint in self.dist_points:
            if dpoint.url == url:
                return dpoint
        return None
    
    def add_dist_point(self, url):
        dpoint = self.find_dpoint(url)
        if dpoint is None:
            dpoint = CRL_dist_point(url)       
            self.dist_points.append(dpoint)
            return dpoint
        else:
            raise 'Issuer already contains this dist point'
    
    def init_dist_point(self, url):
        dpoint = self.find_dpoint(url)
        if dpoint is not None:
            if dpoint.lastUpdated is None:
                logger.debug("Initializing dpoint %s", url)
                downloaded = self.__download_crl(url)
                crl = self.__decode_crl(downloaded)
                dpoint.update_revoked_list(crl)
    
    def is_certificate_revoked(self, cert_sn):
        '''
        Looks in each distpoint for certificate with
        cert_sn serial number. Returns date of revocation or None
        '''
        for dpoint in self.dist_points:
            sn, date = dpoint.find_certificate(cert_sn)
            if sn is not None:
                logger.debug("Certificate %s revoked in %s" % (cert_sn, dpoint.url))
                return date
        return None
            
        
    def refresh_dist_point(self, url):
        '''
        Refreshes CRL of distribution point specified by url.
        If the time of thisUpdate of downloaded CRL is the same 
        as time in lastUpdate of current version, does not do anything
        '''
        dpoint = self.find_dpoint(url)
        if dpoint is not None:
            last_updated = dpoint.lastUpdated
            logger.debug("Refreshing dpoint %s", url)
            downloaded = self.__download_crl(url)
            found = downloaded.find(last_updated, 0, 5000)
            if found == -1:
                logger.debug("Last update value was not found at the begginging of CRL, probably new list")
                crl = self.__decode_crl(downloaded)
                downloaded_update_time = str(crl.getComponentByName("tbsCertList").getComponentByName("thisUpdate"))
                if dpoint.lastUpdated != downloaded_update_time:
                    dpoint.update_revoked_list(crl)
            else:
                logger.debug("Last update value was found in the beggining of CRL = our copy is actual")
                return
    
    
    def pickle(self, fname):
        import hashlib
        f = open(fname, "w")
        pickle.dump(self, f)
        f.close()
        
        for i in xrange(len(self.dist_points)):
            dpoint = self.dist_points[i]
            s = hashlib.sha1()
            s.update(dpoint.url)
            fname = s.hexdigest()
            dpoint.pickle(CRL_DUMP_DIR+ "/"+\
                          CRL_ISSUER_DIR_PREF+str(i)+\
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
        
    issuers = []
        
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
    
    def is_certificate_revoked(self, issuer, cert_sn):
        '''
        Returns date of revocation of the certificate from
        specified issuer.
        '''        
        iss = self.get_issuer(issuer)
        if iss is None:
            raise "Issuer %s not found" % issuer
        date = iss.is_certificate_revoked(cert_sn)
        return date
        
    def pickle(self):   
        '''
        Stores the cache instance into a file
        ''' 
        try:
            os.mkdir(CRL_DUMP_DIR)            
            for i in xrange(len(self.issuers)):
                os.mkdir(CRL_DUMP_DIR+"/"+CRL_ISSUER_DIR_PREF+str(i))
        except:
            pass
        f = open(CRL_DUMP_DIR+"/"+CRL_DUMP_FILE, "w")
        pickle.dump(self, f, pickle.HIGHEST_PROTOCOL)
        f.close()
        iss_id = 0
        for issuer in self.issuers:
            issuer.pickle(CRL_DUMP_DIR + "/" + \
                          CRL_ISSUER_PREF + str(iss_id))
            iss_id += 1
    
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
    
def restore_cache():
    try:
        crl_fname = CRL_DUMP_DIR+"/"+CRL_DUMP_FILE
        cache = CRL_cache.unpickle(crl_fname)
        map = []
        fnames = os.listdir(CRL_DUMP_DIR)
        for fname in fnames:        
            if fname.startswith(".iss_"):
                # remember number of processed file
                # to know the order in which the issuers
                # were added to cache
                number = int(fname[::-1][0])
                map.append(number)
                iss = CRL_issuer.unpickle(CRL_DUMP_DIR+"/"+fname)
                cache.add_issuer(iss.name)
        # restore issuers     
        for fname in fnames:
            if fname.startswith(CRL_ISSUER_DIR_PREF):
                # get the right issuer from cache
                # we know this from map built in previous cycle
                number = int(fname[::-1][0])
                idx = map.index(number)
                issuer = cache.issuers[idx]
                dpoints = _restore_dpoints(CRL_DUMP_DIR+"/"+fname)
                issuer.dist_points = dpoints
        return cache
    except:
        logger.warning("Cache restore failed")
        return None
    
    