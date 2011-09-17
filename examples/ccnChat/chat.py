#
# Copyright (c) 2011, Regents of the University of California
# BSD license, See the COPYING file for more information
# Written by: Derek Kulinski <takeda@takeda.tk>
#

import curses, curses.wrapper, curses.textpad, threading, time
from ChatNet import ChatNet, ChatServer

class ChatGUI(object):
	def __init__(self, prefix):
		self.prefix = prefix

		self.stdscr = None
		self.max_size = None
		self.chat_sc_border = None
		self.chat_sc = None
		self.input_sc_border = None
		self.input_sc = None
		self.textbox = None

	def window_setup(self):
		self.max_size = self.stdscr.getmaxyx()
		max_y, max_x = self.max_size

		# Input
		self.input_sc_border = curses.newwin(3, max_x, max_y - 3, 0)
		self.input_sc_border.border()
		self.input_sc_border.noutrefresh()
		self.input_sc = curses.newwin(1, max_x - 2, max_y - 2, 1)
		self.textbox = curses.textpad.Textbox(self.input_sc)

		# Output
		self.chat_sc_border = curses.newwin(max_y - 3, max_x)
		self.chat_sc_border.border()
		self.chat_sc_border.noutrefresh()
		self.chat_sc = curses.newwin(max_y - 5, max_x - 2, 1, 1)
		self.chat_sc.scrollok(True)
		self.chat_sc.noutrefresh()

	def write(self, text):
		self.chat_sc.addstr(text + "\n")
		self.chat_sc.noutrefresh()

	def callback(self, nick, text):
		self.write("<%s> %s" % (nick, text))
		curses.doupdate()

	def input_thread(self):
		server = ChatServer(self.prefix)
		thread = threading.Thread(target=server.listen)
		thread.start()

		while True:
			text = self.textbox.edit()
			self.input_sc.erase()
			if text == "":
				continue
			#self.write(text)
			server.send_message(text)

	def curses_code(self, stdscr):
		self.stdscr = stdscr
		self.window_setup()
		curses.doupdate()

		chatnet = ChatNet(self.prefix, self.callback)
		thread = threading.Thread(target=self.input_thread)
		thread.start()
		while True:
			chatnet.pullData()
			time.sleep(1)

if __name__ == '__main__':
	gui = ChatGUI("/chat")
	curses.wrapper(gui.curses_code)
