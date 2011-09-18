#
# Copyright (c) 2011, Regents of the University of California
# BSD license, See the COPYING file for more information
# Written by: Derek Kulinski <takeda@takeda.tk>
#

import time, threading
from pyccn import Key
from ChatNet import ChatNet, ChatServer

class ChatNoGUI(object):
	def callback(self, nick, text):
		print("<%s> %s" % (nick, text))

	def main(self):
		chatnet = ChatNet("/chat", self.callback)
		chatsrv = ChatServer("/chat")

		t = threading.Thread(target=chatsrv.listen)
		t.start()

		i = 0
		while True:
			message = "number %d" % i
			print("Sending: %s" % message)
			r = chatnet.pullData()
			chatsrv.send_message(message)
			i += 1
			time.sleep(1)

ui = ChatNoGUI()
ui.main()
