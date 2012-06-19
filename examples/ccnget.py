# importing libraries
import sys
import pyccn
 
# Defining Method 
class ccnget(pyccn.Closure):    
    # Initialization call to initialize the necessary variables
    def __init__(self,name):
        self.handle = pyccn.CCN()
        self.name = pyccn.Name(name)
    
    # start call to initiate the process 
    def start(self):
		
                # call to buid and express interest
                self.requestContent()
                # enter ccn loop (upcalls won't be called without it)
		# -1 means wait forever
                self.handle.run(-1)
                
    def requestContent(self):
                # building an interest
                templ = pyccn.Interest()
                # expressing interest 
		self.handle.expressInterest(self.name, self, templ)
               
    # Called when we receive interest
    # once data is received signal ccn_run() to exit
    def upcall(self, kind, upcallInfo): 
                # Now we process the content according to the kind recieved from upcall 
		
                # Checks for the final upcall ensuring content is delivered
                if kind == pyccn.UPCALL_FINAL: 
			return pyccn.RESULT_OK
                # Checks for the upcall which conveys interest time put 
		if kind == pyccn.UPCALL_INTEREST_TIMED_OUT: 
			print("Got timeout!")
			return pyccn.RESULT_OK
                # Checks for upcalls which conveys confirmation of however,
                # it may be bad or unverified even 
		if not kind in [pyccn.UPCALL_CONTENT,
						pyccn.UPCALL_CONTENT_BAD]:
			print("Received invalid kind type: %d" % kind)
			sys.exit(100)
                # Check for upcalls which conveys bad content
                if kind == pyccn.UPCALL_CONTENT_BAD:
			print("*** VERIFICATION FAILURE *** %s" % response_name)

		# Check for upcalls confirming data corresponding to our interest
                if kind == pyccn.UPCALL_CONTENT:  
                        # Accessing content object
                        cont = upcallInfo.ContentObject
                        # Printin the content within content object
                        print(cont.content)
                        # finish run() by changing its timeout to 0
                        sys.exit(0)
                
                return pyccn.RESULT_OK    
        
def usage():
	print("Usage: %s <URI> " % sys.argv[0])
	print("Get one content item  matching the name prefix and write content to stdout")
        sys.exit(1)

if __name__ == '__main__':
	if len(sys.argv) != 2: #Checking the number of arguments to ccnget
            usage()
        
       	name = sys.argv[1]
        
	print("Retrieving content object from %s " % (name))
	Get = ccnget(name)
	Get.start()
        
        
