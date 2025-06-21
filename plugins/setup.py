from setuptools import setup, find_packages

setup(
    name='d3c',
    version='1.9',
    description='DDDC plugin',
    install_requires=['defusedxml', 'numpy', 'pandas', 'openpyxl', 'pyspellchecker==0.7.2', 'regex'],
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
)
