### v0.10.0 (2023-10-04)

  * Add support to use a permanent Token.

### v0.9.2 (2023-08-25)

  * Fix bug using BaseFacade

### v0.9.1 (2023-08-20)

  * Fix bug using old Facade instead of BaseFacade

### v0.9.0 (2023-08-20)

  * Add isort and Black as formatter
  * Add static BaseFacade class to allow access to API class and BaseMain options

### v0.8.0 (2023-07-04)

  * Remove support for Python 3.8.
  * Add set of `raw_*` methods that do not process results.

### v0.7.0 (2023-05-08)

  * Migrated to Python 3.10, Python 2 is not supported anymore
  * Resource class methods respect additional `**kwargs` and `extra_headers` parameters and pass them on to the underlying `requests` methods
  * Fix to support `http://` schema in the server url

### v0.6.0 (2022-10-30)

  * Add USE_DASHES option to automatically replace underscores ("_") with dashes ("-")
  * Refactor to pass options to Resource class

### v0.5.0 (2022-05-16)

  * Allow `delete()` method to accept optional `payload`

### v0.4.1 (2022-03-13)

  * Fix BaseMain Login method
  * Fix PYPI error

### v0.3.0 (2022-03-13)

  * Add missing PYPI long description
  * Add base_main helper

### v0.2.0 (2022-03-09)

  * Add method to be able to support resource names with "-" in the name
  * Support Login based on usernames or email keys
  * Drop support for Python 2. Test on v3.8 and v3.9

### v0.1.2 (2020-06-01)

  * Remove dependency on unitest2

### v0.1.0 (2017-05-06)

  * First release
