Welcome to PyVARIoT's documentation!
====================================

This is the client API for `PyVARIoT <https://github.com/cve-search/variot>`_:

  foo


Installation
------------

The package is available on PyPi, so you can install it with::

  pip install pyvariot


Usage
-----

You can use `pyvariot` as a python script::

    $ variot -h

    usage: pyvariot [-h] [--url URL] [--apikey APIKEY]
                (--vulnerability_id VULNERABILITY_ID | --exploit_id EXPLOIT_ID)

    Get a vulnerability or an exploit by ID.

    options:
      -h, --help            show this help message and exit
      --url URL             URL of the instance.
      --apikey APIKEY       Your personal API key.
      --vulnerability_id VULNERABILITY_ID
                            ID of the vulnerability.
      --exploit_id EXPLOIT_ID
                            ID of the exploit.

Or as a library:

.. toctree::
   :glob:

   api_reference


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
