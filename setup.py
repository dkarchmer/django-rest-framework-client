from setuptools import setup

setup(name='django-rest-framework-client',
    version='0.1.0',
    description='Python client for a DjangoRestFramework based web site',
    url='https://github.com/dkarchmer/django-rest-framework-client',
    author='David Karchmer',
    author_email="dkarchmer@gmail.com",
    license='MIT',
    packages=[
        'drf_client',
    ],
    install_requires=[
        'requests',
    ],
    keywords=["django", "djangorestframework", "Rest",],
    classifiers=[
        "Programming Language :: Python",
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules"
    ],
    zip_safe=False)