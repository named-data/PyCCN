/*
 * Copyright (c) 2011, Regents of the University of California
 * BSD license, See the COPYING file for more information
 * Written by: Derek Kulinski <takeda@takeda.tk>
 *             Jeff Burke <jburke@ucla.edu>
 */

#ifndef PYTHON_HDR_H
#  define	PYTHON_HDR_H

/* Python 3.2.1 throws bunch of warnings when compiling with -Wextra */

#  if defined(__GNUC__)
#    pragma GCC diagnostic ignored "-Wunused-parameter"
#  endif

#  include <Python.h>

#  if defined(__GNUC__)
#    pragma GCC diagnostic warning "-Wunused-parameter"
#  endif

#endif	/* PYTHON_HDR_H */

