#!/usr/bin/env python
# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# Copyright (c) 2013, Regents of the University of California
#                     Alexander Afanasyev
#
# BSD license, See the doc/LICENSE file for more information
#
# Author: Alexander Afanasyev <alexander.afanasyev@ucla.edu>
#

from Face import *
from Interest import *
from Name import *
import Closure
import datetime
import threading
import time

import logging
_LOG = logging.getLogger ("ndn.LocalPrefixDiscovery")

try:
    from apscheduler.scheduler import Scheduler
except:
    pass

class LocalPrefixDiscovery:
#private:
    __slots__ = ["_subscribers", "_currentPrefix", "_needStopDiscovery", 
                 "_scheduler", "_timeouts", "_face", "_evenLoop", "_eventLoopThread",
                 "_periodicity"]
    
# public:
    def __init__ (self, periodicity = 30): # 30 seconds
        self._periodicity = periodicity
        self._subscribers = {}
        self._currentPrefix = Name ()
        self._needStopDiscovery = True
        self._scheduler = Scheduler ()
        self._scheduler.start ()
        self._timeouts = 0
        self._face = Face ()
        self._eventLoop = ndn.EventLoop (self._face)

    def subscribe (self, tag, callback):
        self._subscribers[tag] = callback
        if (len (self._subscribers.values ()) == 1):
            self._start ()

    def unsubscribe (self, tag):
        del self._subscribers[tag]
        if (len (self._subscribers.values ()) == 0):
            self._stop ()

    def shutdown (self):
        self._stop ()
        self._scheduler.shutdown ()

#private:
    def _start (self):
        self._needStopDiscovery = False
        self._eventLoopThread = threading.Thread (target = self._ccn_loop_ignoring_errors)
        self._eventLoopThread.start ()

        nextDiscovery = datetime.datetime.now () + datetime.timedelta (seconds = 1)
        self._scheduler.add_date_job(self._requestLocalPrefix, nextDiscovery)

    def _stop (self):
        self._needStopDiscovery = True
        self._eventLoop.stop ()
        self._eventLoopThread.join ()        

    def _ccn_loop_ignoring_errors (self):
        while not self._needStopDiscovery:
            try:
                self._eventLoop.run ()
            except:
                if not self._needStopDiscovery:
                    self._face.disconnect ()
                    time.sleep (self._periodicity)
                    self._face.connect ()

    def _requestLocalPrefix (self):
        self._timeouts = 0
        self._face.expressInterestForLatest (Name ("/local/ndn/prefix"),
                                             self._onLocalPrefix, self._onTimeout)

    def _onLocalPrefix (self, baseName, interest, data, kind):
        try:
            name = Name (str (data.content).strip(' \t\n\r'))
        except:
            pass

        if (name != self._currentPrefix):
            for subscriber in self._subscribers.values ():
                subscriber (self._currentPrefix, name)
            self._currentPrefix = name

        if not self._needStopDiscovery:
            nextDiscovery = datetime.datetime.now () + datetime.timedelta (seconds = self._periodicity)
            self._scheduler.add_date_job(self._requestLocalPrefix, nextDiscovery)

        return Closure.RESULT_OK

    def _onTimeout (self, baseName, interest):
        if self._timeouts < 3:
            self._timeouts = self._timeouts + 1
            return Closure.RESULT_REEXPRESS
        else:
            # do stuff
            name = Name ()
            if (name != self._currentPrefix):
                for subscriber in self._subscribers.values ():
                    subscriber (self._currentPrefix, name)
                self._currentPrefix = name
            
            if not self._needStopDiscovery:
                nextDiscovery = datetime.datetime.now () + datetime.timedelta (seconds = self._periodicity)
                self._scheduler.add_date_job(self._requestLocalPrefix, nextDiscovery)
            return Closure.RESULT_OK
