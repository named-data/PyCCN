/*
 * File:   converters.h
 * Author: takeda
 *
 * Created on July 3, 2011, 8:53 PM
 */

#ifndef CONVERTERS_H
#  define	CONVERTERS_H

struct ccn_charbuf *Name_to_ccn(PyObject* py_name);
PyObject *Name_from_ccn(PyObject *py_ccn_name);
PyObject *Name_from_ccn_tagged_bytearray(const unsigned char* buf, size_t size);

void __ccn_key_destroy(void* p);
struct ccn_pkey *Key_to_ccn_private(PyObject* py_key);
PyObject *Key_from_ccn(struct ccn_pkey* key_ccn);
void __ccn_key_locator_destroy(void* p);
struct ccn_charbuf *KeyLocator_to_ccn(PyObject* py_key_locator);
PyObject *KeyLocator_from_ccn(struct ccn_charbuf* key_locator);
void __ccn_exclusion_filter_destroy(void* p);
struct ccn_charbuf *ExclusionFilter_to_ccn(PyObject* py_ExclusionFilter);
PyObject *ExclusionFilter_from_ccn(struct ccn_charbuf* ExclusionFilter);

void __ccn_interest_destroy(void* p);
void __ccn_parsed_interest_destroy(void* p);
struct ccn_charbuf *Interest_to_ccn(PyObject* py_interest);
PyObject *Interest_from_ccn(struct ccn_charbuf* interest);
PyObject *Interest_from_ccn_parsed(struct ccn_charbuf* interest, struct ccn_parsed_interest* pi);
void __ccn_signature_destroy(void* p);
struct ccn_charbuf *Signature_to_ccn(PyObject* py_signature);
PyObject *Signature_from_ccn(struct ccn_charbuf* signature);
void __ccn_signed_info_destroy(void* p);
struct ccn_charbuf* SignedInfo_to_ccn(PyObject* py_signed_info);
PyObject *SignedInfo_from_ccn(struct ccn_charbuf* signed_info);
PyObject *SigningParams_from_ccn(struct ccn_signing_params* signing_params);

PyObject *UpcallInfo_from_ccn(struct ccn_upcall_info* ui);
PyObject *ContentObject_from_ccn_parsed(struct ccn_charbuf* content_object,
		struct ccn_parsed_ContentObject* parsed_content_object,
		struct ccn_indexbuf* components);

PyObject *ContentObject_from_ccn(struct ccn_charbuf* content_object);

#endif	/* CONVERTERS_H */
