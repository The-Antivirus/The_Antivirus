from setuptools import setup, find_packages

setup(
    name="The_Antivirus",
    version="0.1.2",
    author="Daniel Grosso",
    author_email="danielka17.grosso@gmail.com",
    description="Antivirus software with DDoS prevention and firewall",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/The-Antivirus/The_Antivirus",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[
        "psutil>=5.9.0",
        "PyQt6",
    ],
    entry_points={
        "console_scripts": [
            "the-antivirus=ui:main",  # Entry point for running the application
        ],
    },
)