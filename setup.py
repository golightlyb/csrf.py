from setuptools import setup

setup(name='csrf',
    version='0.1b1',
    description='simply generate & validate BREACH-resistant CSRF tokens',
    long_description='simply generate & validate BREACH-resistant CSRF tokens',
    url='https://github.com/golightlyb/csrf.py',
    author='Ben Golightly',
    author_email='golightly.ben@googlemail.com',
    maintainer='Tawesoft Ltd',
    maintainer_email='opensource@tawesoft.co.uk',
    license='GNU All-Permissive License',
    packages=['csrf'],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Internet :: WWW/HTTP',
        'Operating System :: Unix',
    ],
    zip_safe=True)
