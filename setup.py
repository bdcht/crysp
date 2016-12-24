from setuptools import setup, find_packages

setup(
    name='crysp',
    version='0.9',
    description='Crypto Stuff in Python',
    long_description='some of my crypto-related facilities...',
    url='https://github.com/bdcht/crysp',
    author='Axel Tillequin',
    author_email='bdcht3@gmail.com',
    license='GPLv2',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
    ],
    keywords='cryptography development',
    packages=find_packages(),
    install_requires=[],
    extras_require={
      'test': ['pytest'],
      'full': ['matplotlib','grandalf'],
    },
    package_data={
    },
    data_files=[],
    entry_points={
    },
)
