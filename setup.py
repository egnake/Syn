from setuptools import find_packages, setup

setup(
    name="syn",
    version="1.1.0",
    description="SYN - AI-Powered Autonomous Security Scanner & Pentest Framework",
    author="Egnake",
    python_requires=">=3.10",
    packages=find_packages(exclude=("tests", "tests.*")),
    include_package_data=True,
    package_data={
        "syn": [
            "models/*.joblib",
            "models/model_checksums.json",
        ]
    },
    install_requires=[
        "scapy",
        "numpy",
        "scikit-learn",
        "joblib",
        "rich",
    ],
    entry_points={
        "console_scripts": [
            "syn=syn.cli:main",
        ]
    },
)
