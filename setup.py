#!/usr/bin/env python

from setuptools import setup, find_packages

setup(name='django-keycloak-auth',
      version='1.0',
      author='Q 🦄',
      author_email='q@magicalcodewit.ch',
      install_requires=['python-keycloak-client'],
      dependency_links=['https://github.com/Peter-Slump/python-keycloak-client/tarball/master#egg=python-keycloak-client'],
      packages=find_packages(),
     )

