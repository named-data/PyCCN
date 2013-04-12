#
# Copyright (c) 2011, Regents of the University of California
# BSD license, See the COPYING file for more information
# Written by: Derek Kulinski <takeda@takeda.tk>
# Updated by: Wentao Shang <wentao@cs.ucla.edu>
#

from . import _pyccn, Name

def new_state():
	return _pyccn.nc_new_state()

def generate_application_key(master_key, app_name):
	policy = app_name # policy currently needs to be equal to app_name
	appid = _pyccn.nc_app_id(app_name)
	app_key = _pyccn.nc_app_key(master_key, appid, policy)

	return app_key

def authenticate_command(state, name, app_name, app_key):
	signed_name = _pyccn.nc_authenticate_command(state, name.ccn_data, app_name, app_key)
	return Name(ccn_data = signed_name)

def authenticate_command_sig(state, name, app_name, key):
	signed_name = _pyccn.nc_authenticate_command_sig(state, name.ccn_data, app_name, key.ccn_data_private)
	return Name(ccn_data = signed_name)

def verify_command(state, name, max_time, **args):
	if args.has_key('pub_key'):
		args['pub_key'] = args['pub_key'].ccn_data_public
	return _pyccn.nc_verify_command(state, name.ccn_data, max_time, **args)
