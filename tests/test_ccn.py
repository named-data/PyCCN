# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */

import unittest

from pyccn import CCN, _pyccn
from threading import Timer
from datetime import datetime

class Basic(unittest.TestCase):

    def test_raiseIfNotConnected (self):

        handle = _pyccn.create()        
        self.assertRaises (_pyccn.CCNError, _pyccn.run, handle, 100) # "ccn_run() should fail when not connected"
        del handle
        
    def test_setRunTimeout (self):
        c = CCN()
        c.run(0)
        
        def change_timeout():
            # print("Changing timeout!")
            c.setRunTimeout(1000)
        
        t = Timer(0.1, change_timeout)
        t.start()
        
        org_start = datetime.now()
        while True:
                self.assertLess ((datetime.now() - org_start).seconds, 3) # setRunTimeout() failed
        
        	start = datetime.now()
        	c.run(5)
        	diff = datetime.now() - start
        
        	if diff.seconds * 1000000 + diff.microseconds > 500000:
        		break
        	# print("working: ", diff)

    def test_ccn_connect_disconnect (self):

        handle = _pyccn.create()

        self.assertRaises (_pyccn.CCNError, _pyccn.disconnect, handle) # "Closing an unopened connection should fail"

        _pyccn.connect(handle)
        _pyccn.disconnect(handle)

        self.assertRaises (_pyccn.CCNError, _pyccn.disconnect, handle) # "Closing handle twice shouldn't work"

        del handle

        c = CCN()
        _pyccn.disconnect (c.ccn_data)
        del c

if __name__ == '__main__':
    unittest.main()
