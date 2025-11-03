from setuptools import setup, find_packages

setup(
    name="secret-scanner",
    version="0.1.0",
    description="A cross-platform secret scanner for source code",
    packages=find_packages(),
    install_requires=[
        "click>=8.1.0",
        "pathspec>=0.12.0",
        "charset-normalizer>=3.3.0",
    ],
    entry_points={
        "console_scripts": [
            "secret-scanner=secret_scanner.cli:main",
        ],
    },
    python_requires=">=3.8",
)


