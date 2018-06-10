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
install_pkg_dir = os.path.join(sitedir, 'bbc1')
target_dir = os.path.join(install_pkg_dir, 'core')
os.makedirs(target_dir, exist_ok=True)
dst_path = os.path.join(target_dir, 'libbbcsig.so')
shutil.copy('libs/libbbcsig.so', dst_path)

