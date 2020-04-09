import os
from setuptools import find_packages, setup

os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='rijndael',
    version='0.1',
    packages=find_packages(),
    test_suite='rijndael.tests',
    include_package_data=True,
    author='Timur Grishin',
    author_email='grishin.t@gmail.com',
    license='MIT',
    description='Rijndael encryption algorithm in python.',
    url='https://github.com/timur989898',
    classifiers=[
        'Environment :: Console',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: Unix',
        'Programming Language :: Python'
    ],
)
