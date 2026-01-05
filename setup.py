import sys
import platform
import glob
from setuptools import setup, find_packages, Extension
from os.path import abspath, dirname, join

here = abspath(dirname(__file__))

with open(join(here, 'README.md'), encoding='utf-8') as f:
    README = f.read()
reqs = []
utils = glob.glob('src/ipasn/pyasn-utils/*.py')

__version__ = None
exec(open('pyasn/_version.py').read())  # load the actual __version__

setup(
    name='pyasn',
    version=__version__,
    maintainer='Hadi Asghari',
    maintainer_email='hd.asghari@gmail.com',
    url='https://github.com/hadiasghari/pyasn',
    description='Offline IP address to Autonomous System Number lookup module.',
    long_description=README,
    license='MIT',
    classifiers=[
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Networking',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
    ],
    keywords='ip asn autonomous system bgp whois prefix radix python routing networking',
    install_requires=reqs,
    data_files=[],
    scripts=utils,
    setup_requires=[],
    packages=find_packages(exclude=['tests', 'tests.*']),
    zip_safe=False,
    extras_require={'test': ['pytest'],}
)


