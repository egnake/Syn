from setuptools import setup, find_packages

setup(
    name="syn",
    version="1.0.0",
    description="SYN - Yapay Zeka Destekli Profesyonel Port Tarayıcı ve Pentest Aracı",
    author="Egnake",
    packages=find_packages(),
    install_requires=[
        "scapy",
        "numpy",
        "pandas",
        "scikit-learn",
        "joblib",
        "tqdm",
        "rich",
        "colorama",
        "requests",
        "aiofiles"
    ],
    entry_points={
        "console_scripts": [
            "syn=syn.cli:main",
        ]
    },
)
