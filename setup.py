#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name="cyberbattlesim_cloud_gen",
    version="0.1.0",
    description="A framework for network generation and visualization in CyberBattleSim.",
    author="Your Name or Team Name",
    author_email="your_email@example.com",
    url="https://github.com/your_username/cyberbattlesim-network-gen",  # Replace with your repository URL
    packages=find_packages(exclude=["tests", "*.tests", "*.tests.*", "tests.*"]),
    install_requires=[
        "numpy>=1.21.0",
        "pandas>=1.3.0",
        "matplotlib>=3.4.0",
        "tqdm>=4.50.0",
        "loguru>=0.5.0",
        "invoke>=1.5.0",
        "PyYAML>=5.4.0",
        "networkx>=2.6.0",  # If used for network visualization or manipulation
    ],
    extras_require={
        "dev": [
            "pytest>=6.0",
            "flake8>=3.8",
            "black>=22.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "generate-network=cyberbattlesim.network_generators.main:main",  # Replace with the appropriate module and function
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
        "Intended Audience :: Science/Research",
    ],
    python_requires=">=3.8",
)
