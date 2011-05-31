
import _pyccn

# Iterate through components and check types when serializing. 
# Serialize strings without the trailing 0

# Expose the container types?
# Allow init with a uri or a string?

# Byte Array http://docs.python.org/release/2.7.1/library/functions.html#bytearray

# do the appends need to include tags? 

# support standards? for now, just version & segment? 
# http://www.ccnx.org/releases/latest/doc/technical/NameConventions.html

# incorporate ccn_compare_names for canonical ordering?
#
class Name(object):
    def __init__(self, components=list()):
        self.components = components  # list of blobs
        self.version = None      # need put/get handlers for attr
        self.segment = None 
        
        # pyccn
        self.ccn_data_dirty = False 
        self.ccn_data = None  # backing charbuf
        
    # can we do this in python
    def appendNonce(self):
        pass
    
    def appendNumeric(self):   # tagged numerics p4 of code 
        pass
    
    def __iconcat__(self, c):
        self.components.append(c)    
        self.ccn_data_dirty = True
        
    def __setattr__(self, name, value):
        if name=='components' or name=='version' or name=='segment' or name=='ccn_data':
            self.ccn_data_dirty=True 
        object.__setattr__(self, name, value)
    
    def __getattribute__(self, name):
        if name=="ccn_data":
            if object.__getattribute__(self, 'ccn_data_dirty'):
                self.ccn_data = _pyccn._pyccn_Name_to_ccn(self)
                self.ccn_data_dirty = False
        return object.__getattribute__(self, name)
        
    # Should be called if ccn_name is accessed and ccn_name_dirty is true
    def __get_ccn(self):  
        # name_init() 
        # and so on...       
        pass


