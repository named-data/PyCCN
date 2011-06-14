
# Front ccn_parsed_ContentObject.
# Sort of. 
import _pyccn
 
class ContentObject(object):
    def __init__(self):
        self.name = None
        self.content = None
        self.signedInfo = None
        self.digestAlgorithm = None # Default
        
        # generated
        self.signature = None
        self.verified = False
        
        # pyccn
        self.ccn = None # Reference to CCN object
        self.ccn_data_dirty = False 
        self.ccn_data = None  # backing charbuf
        self.ccn_data_parsed = None  # PCO
        self.ccn_data_components = None  # PCO    
    
    # this is the finalization step     
    def sign(self, key):
        self.ccn_data = _pyccn._pyccn_ContentObject_to_ccn(self, key)
        self.ccn_data_dirty = False

    def verify(self):
        # ccn_verify_content
        pass
    
    def matchesInterest(self, interest):
        #ccn_content_matches_interest
        pass

    def __setattr__(self, name, value):
        if name=='name' or name=='content' or name=='signedInfo' or name=='digestAlgorithm':
            self.ccn_data_dirty=True 
        object.__setattr__(self, name, value)
    
    def __getattribute__(self, name):
        if name=="ccn_data":
            if object.__getattribute__(self, 'ccn_data_dirty'):
                print "Call sign() to finalize before accessing ccn_data for a ContentObject"
        return object.__getattribute__(self, name)  
                
    # Where do we support versioning and segmentation?
    

class Signature(object):
    def __init__(self):
        self.digestAlgorithm = None
        self.witness = None
        self.signatureBits = None
        # pyccn
        self.ccn_data_dirty = False 
        self.ccn_data = None  # backing charbuf
    
    def __get_ccn(self):
        pass

    def __setattr__(self, name, value):
        if name=='witness' or name=='signatureBits' or name=='digestAlgorithm':
            self.ccn_data_dirty=True 
        object.__setattr__(self, name, value)
    
    def __getattribute__(self, name):
        if name=="ccn_data":
            if object.__getattribute__(self, 'ccn_data_dirty'):
                self.ccn_data = _pyccn._pyccn_Signature_to_ccn(self)
                self.ccn_data_dirty = False
        return object.__getattribute__(self, name) 
        
class SignedInfo(object):
    def __init__(self):
        self.publisherPublicKeyDigest = None     # SHA256 hash
        self.timeStamp = None   # CCNx timestamp
        self.type = None  # enum 
        self.freshnessSeconds = None
        self.finalBlockID = None
        self.keyLocator = None
        # pyccn
        self.ccn_data_dirty = False 
        self.ccn_data = None  # backing charbuf
    
    def __setattr__(self, name, value):
        if name != "ccn_data" and name != "ccn_data_dirty":
            self.ccn_data_dirty=True 
        object.__setattr__(self, name, value)
    
    def __getattribute__(self, name):
        if name=="ccn_data":
            if object.__getattribute__(self, 'ccn_data_dirty'):
                self.ccn_data = _pyccn._pyccn_SignedInfo_to_ccn(self)
                self.ccn_data_dirty = False
        return object.__getattribute__(self, name) 
    
    def __get_ccn(self):
        pass
        # Call ccn_signed_info_create
        
        