/*
 * File:   methods.h
 * Author: takeda
 *
 * Created on July 4, 2011, 12:48 AM
 */

#ifndef METHODS_H
#  define	METHODS_H

PyObject *Key_from_ccn(struct ccn_pkey* key_ccn);

PyObject *initialize_methods(const char* name);

#endif	/* METHODS_H */

