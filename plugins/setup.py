from setuptools import setup, find_packages

setup(
    name='d3c',
    version='0.8',
    description='DDDC plugin',
    install_requires=['defusedxml', 'pandas', 'openpyxl', 'pyspellchecker==0.7.2'],
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
)
