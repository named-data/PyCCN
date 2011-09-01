import time
from ChatNet import ChatNet

class ChatNoGUI(object):
	def callback(self, nick, text):
		print("<%s> %s" % (nick, text))

	def main(self):
		chatnet = ChatNet("/chat/room", self.callback)

		while True:
			r = chatnet.pullData()
			time.sleep(1)

ui = ChatNoGUI()
ui.main()
