# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

VERSION='0.2.1'
APPNAME='PyNDN'

from waflib import Configure, Build, Options

def options(opt):
    opt.load('compiler_c python ndnx')
    opt.add_option('--debug',action='store_true',default=False,dest='debug',help='''debugging mode''')

def configure(conf):
    conf.load('compiler_c python ndnx')

    if conf.options.debug:
        conf.define ('_DEBUG', 1)
        conf.add_supported_cflags (cflags = ['-std=c99',
                                             '-O0',
                                             '-Wall',
                                             '-Wno-unused-variable',
                                             '-g3',
                                             '-Wno-unused-private-field', # only clang supports
                                             '-fcolor-diagnostics',       # only clang supports
                                             '-Qunused-arguments'         # only clang supports
                                             ])
    else:
        conf.add_supported_cflags (cflags = ['-std=c99', '-O3', '-g'])

    conf.check_ndnx ()
    conf.check_openssl ()


    conf.check_python_version ((2,7))
    conf.check_python_headers ()

    # cflags = "-std=c99 -Wall -Wextra -Winvalid-pch -Wstrict-prototypes -Wmissing-prototypes -Wshadow -fdiagnostics-show-option -Wno-unknown-pragmas"
    # ldflags = "-avoid-version -module @PYTHON_LDFLAGS@

    try:
        if not conf.find_program ('nosetests', mandatory = False):
            if not conf.find_program ('nosetests-%s' % conf.env['PYTHON_VERSION'], var = "NOSETESTS", mandatory = False):
                Logs.warning ('Unittests are disabled. Please install `nose\' module', var = "NOSETESTS")
    except:
        pass


def build (bld):
    bld.shlib (features = "pyext",
               target = "_ndn",
               source = bld.path.ant_glob (["csrc/**/*.c"]),
               use = "NDNX SSL",
               install_path='${PYTHONARCHDIR}/ndn'
               )

    bld (features = "pyext",
         source = bld.path.ant_glob (["ndn/**/*.py"]),
         install_from = "."
         )

@Configure.conf
def add_supported_cflags(self, cflags):
    """
    Check which cflags are supported by compiler and add them to env.CFLAGS variable
    """
    self.start_msg('Checking allowed flags for c compiler')

    supportedFlags = []
    for flag in cflags:
        if self.check_cc (cflags=[flag], mandatory=False):
            supportedFlags += [flag]

    self.end_msg (' '.join (supportedFlags))
    self.env.CFLAGS += supportedFlags


class TestContext(Build.BuildContext):
	'''tests the project'''
	cmd='test'
	def execute(self):
            super (TestContext, self).execute ()

            self.restore()
            if not self.all_envs:
                self.load_envs()

            if not self.env['NOSETESTS']:
                self.fatal ("nosetests program is necessary to run tests (e.g., `port install py27-nose' or `easy_install nose')")

            try:
                import sys
                sys.path.append (self.env['PYTHONARCHDIR'])
                import ndn
            except:
                self.fatal ("In order to run tests, PyNDN needs to be installed (run ./waf install or sudo ./waf install first)")

            try:
                import subprocess
                subprocess.call ("PYTHONPATH=\"%s\" %s -v" % (self.env['PYTHONARCHDIR'], self.env['NOSETESTS']), shell=True)
            except:
                raise
                self.fatal ("Tests failed")
            finally:
                self.store()
