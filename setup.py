#!/usr/bin/env python

from setuptools import setup, find_packages

setup(name='django-keycloak-auth',
      version='1.0',
      author='Q 🦄',
      author_email='q@magicalcodewit.ch',
      install_requires=['python-keycloak-client @ git+https://github.com/AS207960/python-keycloak-client.git@22d87577f4637133146c376dbb99553035b340ab#egg=python-keycloak-client'],
      packages=find_packages(),
      package_data={
        "django_keycloak_auth": ["words.txt"]
      }
)

