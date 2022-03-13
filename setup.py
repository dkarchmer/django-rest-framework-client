import pathlib
from setuptools import find_packages, setup
import version

# The directory containing this file
HERE = pathlib.Path(__file__).parent

# The text of the README file
README = (HERE / "README.md").read_text()

setup(name='django-rest-framework-client',
    version=version.version,
    description='Python client for a DjangoRestFramework based web site',
    long_description=README,
    long_description_content_type="text/markdown",
    url='https://github.com/dkarchmer/django-rest-framework-client',
    author='David Karchmer',
    author_email="dkarchmer@gmail.com",
    license='MIT',
    packages=find_packages(exclude=("tests",)),
    install_requires=[
        'requests',
    ],
    python_requires=">=3.7,<4",
    keywords=["django", "djangorestframework", "drf", "rest-client",],
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],
    zip_safe=False)
