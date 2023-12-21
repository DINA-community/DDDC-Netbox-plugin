from setuptools import find_packages, setup

setup(
    name='d3c',
    version='0.92',
    description='DDDC plugin',
    # The fix version selection ensures the usage of Netbox 3.6.0
    install_requires=['defusedxml', 'numpy==1.24.0', 'pandas==2.0.1', 'openpyxl', 'pyspellchecker==0.7.2', 'regex==2023.8.8'],
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
)
