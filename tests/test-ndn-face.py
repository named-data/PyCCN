# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */

import unittest

from ndn import Face, _ndn
from threading import Timer
from datetime import datetime

class Basic(unittest.TestCase):

    def test_raiseIfNotConnected (self):

        handle = _ndn.create()        
        self.assertRaises (_ndn.CCNError, _ndn.run, handle, 100)
        del handle
        
    def test_setRunTimeout (self):
        c = Face ()
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

    def test_ndn_face_connect_disconnect (self):

        handle = _ndn.create()

        self.assertRaises (_ndn.CCNError, _ndn.disconnect, handle) # "Closing an unopened connection should fail"

        _ndn.connect(handle)
        _ndn.disconnect(handle)

        self.assertRaises (_ndn.CCNError, _ndn.disconnect, handle) # "Closing handle twice shouldn't work"

        del handle

        c = Face()
        _ndn.disconnect (c.ccn_data)
        del c

if __name__ == '__main__':
    unittest.main()
