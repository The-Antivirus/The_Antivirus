from setuptools import setup, find_packages

setup(
    name="The_Antivirus",  # Replace with your package name
    version="0.1.0",  # Initial version
    author="Daniel Grosso",  # Replace with your name
    author_email="danielka17.grosso@gmail.com",  # Replace with your email
    description="Antivirus software with ddos prevemtion and firewall",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/The-Antivirus/The_Antivirus",  # Replace with your GitHub repo URL
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",  # Replace with your license
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[
    ],
)