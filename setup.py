#!/usr/bin/env python

from setuptools import setup, find_packages

setup(name='django-keycloak-auth',
      version='1.1',
      author='Q 🦄',
      author_email='q@magicalcodewit.ch',
      install_requires=['python-keycloak-client @ git+https://github.com/AS207960/python-keycloak-client.git@20ff6b75e12dbb34d53814ef12e942f08546b6ec#egg=python-keycloak-client'],
      packages=find_packages(),
      package_data={
        "django_keycloak_auth": ["words.txt"]
      }
)

