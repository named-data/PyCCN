/*
 * File:   converters.h
 * Author: takeda
 *
 * Created on July 3, 2011, 8:53 PM
 */

#ifndef CONVERTERS_H
#  define	CONVERTERS_H

void __ccn_exclusion_filter_destroy(void* p);
struct ccn_charbuf *ExclusionFilter_to_ccn(PyObject* py_ExclusionFilter);
PyObject *ExclusionFilter_from_ccn(struct ccn_charbuf* ExclusionFilter);

void __ccn_interest_destroy(void* p);
void __ccn_parsed_interest_destroy(void* p);
struct ccn_charbuf *Interest_to_ccn(PyObject* py_interest);
PyObject *Interest_from_ccn(struct ccn_charbuf* interest);
PyObject *Interest_from_ccn_parsed(struct ccn_charbuf* interest, struct ccn_parsed_interest* pi);
PyObject *SigningParams_from_ccn(struct ccn_signing_params* signing_params);

PyObject *UpcallInfo_from_ccn(struct ccn_upcall_info* ui);


PyObject *ContentObject_from_ccn(struct ccn_charbuf* content_object);

#endif	/* CONVERTERS_H */
