from setuptools import setup, find_packages

setup(
    name="pqctlog",
    version="0.1.0",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    install_requires=[
        "requests>=2.28.1",
        "cryptography>=38.0.1",
        "opensearch-py>=2.0.0",
        "python-dotenv>=0.21.0",
        "PyYAML>=6.0",
        "tqdm>=4.64.1",
        "asn1crypto>=1.5.1",
    ],
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "pqctlog=main:main",
        ],
    },
)
