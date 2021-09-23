from distutils.core import setup

setup(
    name='vacdec',
    version='',
    packages=[''],
    url='',
    license='',
    author='Hanno Böck',
    author_email='',
    description='',
    python_requires='>=3.7, <4',
    install_requires=['Pillow','base45', 'cbor2','pyzbar', 'cose', 'cryptojwt', 'pyasn1'],
    scripts=['vacdec'],
)
