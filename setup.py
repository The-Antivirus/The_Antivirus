from setuptools import setup, find_packages

setup(
    name="The_Antivirus", 
    version="0.1.2",  
    author="Daniel Grosso", 
    author_email="danielka17.grosso@gmail.com",  
    description="Antivirus software with ddos prevemtion and firewall",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/The-Antivirus/The_Antivirus",  
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",  
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[
    ],
)