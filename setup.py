from setuptools import setup, find_packages
import sys, os

version = '1.0.3dev'

def read(*rnames):
    return open(os.path.join(os.path.dirname(__file__), *rnames)).read()

long_description = (
    read('README.rst')
    + '\n' +
    read('CHANGES')
    )


setup(name='django-ldap-pixiedust',
      version=version,
      description="Makes django_auth_ldap more sprinkly",
      long_description=long_description,
      classifiers=[], # Get strings from http://pypi.python.org/pypi?%3Aaction=list_classifiers
      keywords='',
      author='Doug Winter',
      author_email='doug.winter@isotoma.com',
      url='',
      license='',
      packages=find_packages(exclude=['ez_setup', 'examples', 'tests']),
      include_package_data=True,
      zip_safe=False,
      install_requires=[
        'django-auth-ldap',
      ],
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
