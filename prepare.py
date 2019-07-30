import os, shutil, site

sitedir = None
if hasattr(site, 'getsitepackages'):
    # normal execution
    sitepackages = site.getsitepackages()
    sitedir = sitepackages[0]
else:
    # workaround for virtualenv
    from distutils.sysconfig import get_python_lib
    sitepackages = [get_python_lib()]
    sitedir = sitepackages[0]
