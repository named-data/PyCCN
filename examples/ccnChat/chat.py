#
# Copyright (c) 2011, Regents of the University of California
# All rights reserved.
# Written by: Derek Kulinski <takeda@takeda.tk>
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the Regents of the University of California nor
#       the names of its contributors may be used to endorse or promote
#       products derived from this software without specific prior written
#       permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL REGENTS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
# OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
