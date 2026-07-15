from setuptools import find_packages, setup
import sys

if sys.version_info < (3, 8):
    sys.exit('Python < 3.8 is not supported')

version = '1.1.3'
repository_url = 'https://github.com/iBuyPower47/steampy'

setup(
    name='steampy',
    packages=find_packages(include=['steampy', 'steampy.*', 'protobufs', 'protobufs.*', 'test', 'test.*', 'examples', 'examples.*']),
    version=version,
    description='A Steam lib for trade automation',
    author='Michał Bukowski',
    author_email='gigibukson@gmail.com',
    license='MIT',
    url=repository_url,
    download_url=f'{repository_url}/tarball/{version}',
    project_urls={
        'Source': repository_url,
        'Original Upstream': 'https://github.com/bukson/steampy',
    },
    python_requires='>=3.8',
    keywords=['steam', 'trade', ],
    classifiers=[],
    install_requires=[
        "requests",
        "beautifulsoup4",
        "rsa",
        "protobuf>=3.20.0",
    ],
)
