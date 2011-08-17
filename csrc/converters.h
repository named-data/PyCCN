/*
 * File:   converters.h
 * Author: takeda
 *
 * Created on July 3, 2011, 8:53 PM
 */

#ifndef CONVERTERS_H
#  define	CONVERTERS_H

PyObject *SigningParams_from_ccn(struct ccn_signing_params* signing_params);
PyObject *UpcallInfo_from_ccn(struct ccn_upcall_info* ui);

#endif	/* CONVERTERS_H */
