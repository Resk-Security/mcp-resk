#!/usr/bin/env python
from setuptools import setup, find_packages

# Read README.md content for the long description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="mcp-resk",
    version="0.1.0",
    author="RESK Team",
    author_email="your.email@example.com",  # Replace with your email
    description="RESK-MCP is an open-source Python library designed to add a robust security and management layer over the official MCP Library.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-username/mcp-resk",  # Replace with your GitHub repo URL
    project_urls={
        "Bug Tracker": "https://github.com/your-username/mcp-resk/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.10",
    install_requires=[
        "fastapi>=0.115.12",
        "mcp[cli]>=1.9.0",
        "pydantic>=2.11.4",
        "pyjwt[crypto]>=2.10.1",
        "python-dotenv>=1.1.0",
        "pyyaml>=6.0.2",
        "requests>=2.32.3",
        "slowapi>=0.1.9",
        "types-pyyaml>=6.0.12.20250516",
        "uvicorn>=0.34.2",
    ],
    extras_require={
        "dev": [
            "build>=1.2.2.post1",
            "flake8>=7.2.0",
            "mypy>=1.15.0",
            "pytest>=8.3.5",
            "pytest-asyncio>=0.26.0",
            "types-pyyaml>=6.0.12.20250516",
        ],
    },
    entry_points={
        "console_scripts": [
            "resk-mcp=resk_mcp.server:main",
        ],
    },
) 