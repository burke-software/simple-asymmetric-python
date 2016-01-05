from setuptools import setup, find_packages

setup(
    name="simple-asymmetric",
    version="0.1",
    author="David Burke",
    author_email="david@burkesoftware.com",
    description=("An easy way to do combined AES and RSA encryption with python"),
    license="Apache License 2.0",
    keywords="encryption",
    url="https://github.com/burke-software/simple-asymmetric-python",
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Intended Audience :: Developers',
    ],
    install_requires=[
        'pycrypto',
    ]
)
