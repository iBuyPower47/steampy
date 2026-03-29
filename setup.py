from setuptools import setup
import sys

if not sys.version_info[0] == 3 and sys.version_info[1] < 8:
    sys.exit('Python < 3.8 is not supported')

version = '1.1.2'

setup(
    name='steampy',
    packages=['steampy', 'test', 'examples', ],
    version=version,
    description='A Steam lib for trade automation',
    author='Michał Bukowski',
    author_email='gigibukson@gmail.com',
    license='MIT',
    url='https://github.com/bukson/steampy',
    download_url='https://github.com/bukson/steampy/tarball/' + version,
    keywords=['steam', 'trade', ],
    classifiers=[],
    install_requires=[
        "certifi==2021.10.8",
        "chardet",
        "requests",
        "beautifulsoup4",
        "rsa"
    ],
)
