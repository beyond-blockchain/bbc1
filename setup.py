import subprocess
import sys
import os
from os import path
from setuptools import setup
from setuptools.command.install import install

VERSION = "1.5.1"

here = path.abspath(path.dirname(__file__))

with open('README.rst') as f:
    readme = f.read()


class MyInstall(install):
    def run(self):
        try:
            subprocess.call(['python', 'prepare.py'], cwd=here)
        except Exception as e:
            print(e)
            print("Error compiling openssl.")
            exit(1)
        else:
            install.run(self)


class VerifyVersionCommand(install):
    """Custom command to verify that the git tag matches our version"""
    description = 'verify that the git tag matches our version'

    def run(self):
        tag = os.getenv('CIRCLE_TAG')

        if tag != "v%s" % VERSION:
            info = "Git tag: {0} does not match the version of this app: {1}".format(
                tag, "v%s" % VERSION
            )
            sys.exit(info)


bbc1_requires = [
                 'pyOpenSSL>=16.2.0',
                 'jinja2>=2.8.1',
                 'requests>=2.12.4',
                 'gevent>=1.2.1',
                 'cryptography>=2.1.4',
                 'pytest>=5.3.0',
                 'msgpack-python>=0.4.8',
                 'mysql-connector-python>=8.0.5',
                 'py-bbclib>=1.6',
                 'greenlet',
                 'bson',
                 'Flask>=0.10.1,<=1.0.1'
                ]

bbc1_packages = ['bbc1', 'bbc1.core']

bbc1_commands = [
                 'bbc1/core/bbc_core.py',
                 'utils/bbc_domain_config.py',
                 'utils/bbc_domain_update.py',
                 'utils/bbc_info.py',
                 'utils/bbc_ping.py',
                 'utils/domain_key_setup.py',
                 'utils/id_create.py',
                 'utils/db_migration_tool.py',
                 'examples/file_proof/file_proof.py']

bbc1_classifiers = [
                    'Development Status :: 4 - Beta',
                    'Programming Language :: Python :: 3.5',
                    'Programming Language :: Python :: 3.6',
                    'Programming Language :: Python :: 3.7',
                    'Topic :: Software Development']

setup(
    name='bbc1',
    version=VERSION,
    description='A core system of Beyond Blockchain One',
    long_description_content_type='text/markdown',
    long_description=readme,
    url='https://github.com/beyond-blockchain/bbc1',
    author='beyond-blockchain.org',
    author_email='bbc1-dev@beyond-blockchain.org',
    license='Apache License 2.0',
    classifiers=bbc1_classifiers,
    cmdclass={'install': MyInstall, 'verify': VerifyVersionCommand},
    packages=bbc1_packages,
    scripts=bbc1_commands,
    install_requires=bbc1_requires,
    zip_safe=False)

