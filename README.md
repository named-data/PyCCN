PyNDN - NDN bindings for Python (formerly known as PyCCN)
========================================================

**PyNDN** (PyCCN) is intended to be a rather "thin" implementation, which supports Python
objects corresponding to the major NDN entities - Interest, ContentObject, and
so on, as well as some support objects.  The C code is mostly just responsible
for marshaling data back and forth between the formats, though there are some
useful functions for key generation/access included.

These are mapped more or less directly from the NDN wire format, and the
Python objects are, in fact, backed by a cached version of the wire format
or native C object, a Python CObject kept in ``self.ccn_data``. Accessing the
attribute regenerates this backing CObject if necessary - those mechanics
are in the Python code.

The Interest and ContentObject objects also cache their parsed versions
as well

1. Build and install instructions
---------------------------------

### 1.1 DEPENDENCIES

- NDNx 0.1 (CCNx 0.7.2 with NDN extensions: http://github.com/named-data/ccnx)
- OpenSSL (need to be linked to the same version used by libndn (libccn)
- Python 2.7+ (tested with 2.7.0 and 3.2.1)

### 1.2 CONFIGURING AND BUILDING

To configure:

    ./waf configure

Relevant options:

* ``--ndnx=<PATH>`` - path to NDNx (CCNx) distribution directory
* ``--openssl=<PATH>`` - path to correct version of ``openssl``)

To build the code:

    ./waf

### 1.3 TESTING

To run tests for the suite:

    ./waf test


### 1.4 INSTALLING

The package will be installed in site-packages of the selected python.

    sudo ./waf install

2. Using the Python bindings
----------------------------

All of the files are contained inside of ``ndn`` package. To use you can call:

    import ndn

3. Platform specific notes
--------------------------

### 3.1 All platforms

- when configuring make sure you compile **PyNDN** with the same ``openssl`` library as
  you compiled NDNx with. To specify alternative version, use ``--openssl=<PATH>`` flag.
  For example:

        /waf configure --openssl=/opt/local
        ./waf
        sudo ./waf install

  A sign of linking with wrong library is getting segment violation on
  ``signing.py`` testcase.

### 3.2 MacOS X

- when building python from sources you need to run ./configure --enable-shared
  otherwise you might experience crash with message:

        "Fatal Python error: PyThreadState_Get: no current thread"

  when trying to ``import ndn``. I'm looking into ways to make code also work
  when python is statically compiled.

- On MacOS X 10.7 (Lion) while compiling the module you'll get bunch of
  warnings about openssl functions being deprecatead. This is OK. The message
  is because Apple decided to replace ``openssl`` with their own implementation
  called Common Crypto and want to discourage developers from using ``OpenSSL``.
  If you don't want to see the warnings you might want to point to alternative
  version (e.g., from ``MacPorts``) using ``--openssl=<PATH>`` flag.  Remember that you
  need to compile **PyNDN** with the same version of ``OpenSSL`` that you compiled NDNx
  otherwise **PyNDN** will crash when trying to sign Content Objects.
