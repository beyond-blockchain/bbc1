import os, shutil, site

sitedir = site.getsitepackages()[0]
install_pkg_dir = os.path.join(sitedir, 'bbc1')
target_dir = os.path.join(install_pkg_dir, 'core')
os.makedirs(target_dir, exist_ok=True)
dst_path = os.path.join(target_dir, 'libbbcsig.so')
shutil.copy('libs/libbbcsig.so', dst_path)

