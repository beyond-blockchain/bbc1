import subprocess
from os import path
from setuptools import setup
from setuptools.command.install import install


here = path.abspath(path.dirname(__file__))

with open('README.rst') as f:
    readme = f.read()


class MyInstall(install):
    def run(self):
        try:
            subprocess.call(['/bin/sh', 'prepare.sh'], cwd=here)
            subprocess.call(['python', 'prepare.py'], cwd=here)
        except Exception as e:
            print(e)
            print("Error compiling openssl.")
            exit(1)
        else:
            install.run(self)


bbc1_requires = [
                 'pyOpenSSL>=16.2.0',
                 'jinja2==2.8.1',
                 'Flask>=0.10.1',
                 'requests>=2.12.4',
                 'pytest>=3.0.5',
                 'gevent>=1.2.1',
                 'populus',
                 'msgpack-python>=0.4.8']

bbc1_packages = ['bbc1', 'bbc1.core', 'bbc1.core.ethereum', 'bbc1.common', 'bbc1.common.libbbcsig', 'bbc1.app']

bbc1_commands = [
                 'bbc1/core/bbc_core.py',
                 'utils/bbc_ping.py',
                 'utils/bbc_system_conf.py',
                 'utils/subsystem_tool.py',
                 'examples/file_proof/file_proof.py']

bbc1_classifiers = [
                    'Development Status :: 4 - Beta',
                    'Programming Language :: Python :: 3.5',
                    'Programming Language :: Python :: 3.6',
                    'Topic :: Software Development']

setup(
    name='bbc1',
    version='0.9',
    description='A core system of Beyond Blockchain One',
    long_description=readme,
    url='https://github.com/beyond-blockchain/bbc1',
    author='beyond-blockchain.org',
    author_email='bbc1-dev@beyond-blockchain.org',
    license='Apache License 2.0',
    classifiers=bbc1_classifiers,
    cmdclass={'install': MyInstall},
    packages=bbc1_packages,
    scripts=bbc1_commands,
    install_requires=bbc1_requires,
    zip_safe=False)

