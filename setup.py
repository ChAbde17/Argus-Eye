from setuptools import setup, find_packages

setup(
    name="argus-eye",
    version="1.0.0",
    author="CH ABDE",
    description="High-Performance Asynchronous Reconnaissance & Attack Surface Scanner",
    packages=find_packages(),
    install_requires=[
        "httpx>=0.25.0",
        "dnspython>=2.4.0",
        "rich>=13.6.0",
    ],
    entry_points={
        "console_scripts": [
            "argus-eye=main:main",
        ],
    },
    python_requires=">=3.8",
)
