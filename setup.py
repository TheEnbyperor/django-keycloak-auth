#!/usr/bin/env python

from setuptools import setup, find_packages

setup(name='django-keycloak-auth',
      version='1.1.1',
      author='Q 🦄',
      author_email='q@magicalcodewit.ch',
      install_requires=['python-keycloak-client @ git+https://github.com/AS207960/python-keycloak-client.git@0267dfa9021eaf478330dedbce587c7a5016a3b3#egg=python-keycloak-client'],
      packages=find_packages(),
      package_data={
        "django_keycloak_auth": ["words.txt"]
      }
)

