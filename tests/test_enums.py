# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */

import unittest
import ndn.utils as utils

class Enums(unittest.TestCase):

    def test_basic (self):
        class Test1(utils.Enum):
            pass

        VAL1 = Test1.new_flag('VAL1', 1)
        VAL2 = Test1.new_flag('VAL2', 2)
        VAL3 = Test1.new_flag('VAL3', 3)

        self.assertEqual ("%r %r %r" % (VAL1, VAL2, VAL3), 
                          "<flags VAL1 of type test_enums.Test1> <flags VAL2 of type test_enums.Test1> <flags VAL3 of type test_enums.Test1>")
        
        self.assertEqual (VAL1, 1)
        self.assertEqual (repr(VAL1), '<flags VAL1 of type test_enums.Test1>')
        self.assertEqual (VAL2, 2)
        self.assertEqual (repr(VAL2), '<flags VAL2 of type test_enums.Test1>')
        self.assertEqual (VAL3, 3)
        self.assertEqual (repr(VAL3), '<flags VAL3 of type test_enums.Test1>')

        class Test2(utils.Flag):
            pass

        FLAG1 = Test2.new_flag('FLAG1', 4)
        FLAG2 = Test2.new_flag('FLAG2', 2)
        FLAG3 = Test2.new_flag('FLAG3', 16)

        self.assertEqual ("%r %r %r" % (FLAG1, FLAG2, FLAG3), 
                          "<flags FLAG1 of type test_enums.Test2> <flags FLAG2 of type test_enums.Test2> <flags FLAG3 of type test_enums.Test2>")
        self.assertEqual (FLAG1, 4)
        self.assertEqual (repr(FLAG1), '<flags FLAG1 of type test_enums.Test2>')
        self.assertEqual (FLAG2, 2)
        self.assertEqual (repr(FLAG2), '<flags FLAG2 of type test_enums.Test2>')
        self.assertEqual (FLAG3, 16)
        self.assertEqual (repr(FLAG3), '<flags FLAG3 of type test_enums.Test2>')
        
        FLAG123 = FLAG1 | FLAG2 | FLAG3
        self.assertEqual (FLAG123, 22)
        self.assertEqual (repr(FLAG123), '<flags FLAG3 | FLAG2 | FLAG1 of type test_enums.Test2>')

        FLAG23 = FLAG123 ^ FLAG1
        self.assertEqual (FLAG23, 18)
        self.assertEqual (repr(FLAG23), '<flags FLAG3 | FLAG2 of type test_enums.Test2>')
        
        FLAG2_ = FLAG123 & FLAG2
        self.assertEqual (FLAG2_, 2)
        self.assertEqual (repr(FLAG2_), '<flags FLAG2 of type test_enums.Test2>')
        
        self.assertEqual ("%r %r %r" % (VAL1, VAL2, VAL3), 
                          "<flags VAL1 of type test_enums.Test1> <flags VAL2 of type test_enums.Test1> <flags VAL3 of type test_enums.Test1>")
        self.assertEqual (VAL1, 1)
        self.assertEqual (repr(VAL1), '<flags VAL1 of type test_enums.Test1>')
        self.assertEqual (VAL2, 2)
        self.assertEqual (repr(VAL2), '<flags VAL2 of type test_enums.Test1>')
        self.assertEqual (VAL3, 3)
        self.assertEqual (repr(VAL3), '<flags VAL3 of type test_enums.Test1>')

    def test_contentType (self):
        class ContentType(utils.Enum):
            pass

        CONTENT_DATA = ContentType.new_flag('CONTENT_DATA', 0x0C04C0)
        CONTENT_ENCR = ContentType.new_flag('CONTENT_ENCR', 0x10D091)
        CONTENT_GONE = ContentType.new_flag('CONTENT_GONE', 0x18E344)
        CONTENT_KEY = ContentType.new_flag('CONTENT_KEY', 0x28463F)
        CONTENT_LINK = ContentType.new_flag('CONTENT_LINK', 0x2C834A)
        CONTENT_NACK = ContentType.new_flag('CONTENT_NACK', 0x34008A)
        
        self.assertEqual (ContentType(0x28463F), CONTENT_KEY)

if __name__ == '__main__':
    unittest.main()
