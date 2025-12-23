from setuptools import setup, find_packages

setup(
    name="arachne",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "stem>=1.8.2",
        "requests>=2.31.0",
        "selenium>=4.15.0",
        "beautifulsoup4>=4.12.2",
        "pydantic>=2.5.0",
        "loguru>=0.7.2",
        "click>=8.1.7",
    ],
    entry_points={
        "console_scripts": [
            "arachne=src.cli.main:cli",
        ],
    },
)
