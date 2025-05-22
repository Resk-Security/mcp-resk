# RESK-MCP: Secure Model Context Protocol Layer

[![PyPI version](https://img.shields.io/pypi/v/mcp-resk.svg)](https://pypi.org/project/mcp-resk/)
[![Python Versions](https://img.shields.io/pypi/pyversions/mcp-resk.svg)](https://pypi.org/project/mcp-resk/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Downloads](https://static.pepy.tech/badge/mcp-resk)](https://pepy.tech/project/mcp-resk)
[![GitHub issues](https://img.shields.io/github/issues/Resk-Security/mcp-resk.svg)](https://github.com/Resk-Security/mcp-resk/issues)
[![GitHub Stars](https://img.shields.io/github/stars/Resk-Security/mcp-resk?style=social)](https://github.com/Resk-Security/mcp-resk/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/Resk-Security/mcp-resk?style=social)](https://github.com/Resk-Security/mcp-resk/network/members)
[![Documentation Status](https://readthedocs.org/projects/mcp-resk/badge/?version=latest)](https://mcp-resk.readthedocs.io/en/latest/?badge=latest)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![GitHub last commit](https://img.shields.io/github/last-commit/Resk-Security/mcp-resk.svg)](https://github.com/Resk-Security/mcp-resk/commits/main)
[![PyPI - Implementation](https://img.shields.io/pypi/implementation/mcp-resk.svg)](https://pypi.org/project/mcp-resk/)
[![LLM Security](https://img.shields.io/badge/LLM%20Security-Enhanced-brightgreen.svg)](https://github.com/Resk-Security/mcp-resk)

RESK-MCP is an open-source Python library that adds a robust security and management layer over the official [Model Context Protocol (MCP) Python SDK](https://github.com/modelcontextprotocol/python-sdk). It provides enhanced security features, monitoring capabilities, and tools for managing MCP interactions.

## Features

- **JWT Authentication**: Secure MCP server endpoints with JSON Web Tokens
- **Input Validation**: Validate all incoming MCP requests using Pydantic
- **PII Detection**: Basic detection of Personally Identifiable Information in request parameters
- **Prompt Injection Protection**: Detection of common prompt injection phrases
- **Rate Limiting**: Configurable per-user or per-IP rate limits using `slowapi`
- **Token-Based Context Management**: Limit request size based on estimated token count
- **Interaction Tracking**: Monitor calls to tools, resources, and prompts
- **Dashboard**: Web-based visualization of MCP interactions and server configuration
- **Easy Configuration**: Simple setup using environment variables
- **HTTPS Support**: Built-in SSL/TLS configuration

## Installation

```bash
# Clone the repository (if contributing or running from source)
git clone https://github.com/Resk-Security/mcp-resk.git
cd mcp-resk

# Create and activate virtual environment
python -m venv venv

# On Windows
# .\venv\Scripts\activate

# On macOS/Linux
# source venv/bin/activate

# Install dependencies using uv (recommended)
uv pip install -r requirements.txt

# For development with editable install
uv pip install -e .

# If contributing or running tests
uv pip install -e ".[dev]"
```

> **Note**: We use [uv](https://github.com/astral-sh/uv) as the recommended package installer because it's significantly faster than pip and provides better dependency resolution. It's also used in our CI/CD workflow.

## Configuration

Create a `.env` file in your project root:

```env
# Required
JWT_SECRET="your-super-secure-jwt-secret-key-here"

# Optional configurations
RATE_LIMIT="100/minute"  # Format: "count/period" (e.g., "5/second", "1000/hour")
MAX_TOKEN_PER_REQUEST="4000"
LOG_LEVEL="INFO"

# For HTTPS
# SSL_KEYFILE="./key.pem"
# SSL_CERTFILE="./cert.pem"
```

### ⚠️ JWT Security Warning

The security of your MCP server relies heavily on the strength of your JWT secret:

- **NEVER** use simple, predictable, or default JWT secrets in production
- Use a strong, randomly generated secret with high entropy (at least 32 characters)
- Do not store JWT secrets in your code or commit them to version control
- Rotate JWT secrets periodically in production environments
- Consider using environment-specific secrets for different deployments
- If you suspect a JWT secret has been compromised, rotate it immediately

The `JWT_SECRET` is used to sign and verify all authentication tokens. A compromised secret would allow attackers to forge valid tokens and bypass your authentication system entirely.

## Usage Example

```python
# main.py
import os
from dotenv import load_dotenv
from resk_mcp import SecureMCPServer, create_jwt_token

load_dotenv()

# Initialize the secure server
server = SecureMCPServer(name="MySecureCalculatorApp")

# Define a sample tool
@server.tool(name="calculator/add")
async def add(a: int, b: int) -> int:
    """Adds two numbers."""
    return a + b

@server.resource(path_pattern="info/version")
async def get_version() -> dict:
    """Returns the application version."""
    return {"version": "1.0-secure"}

if __name__ == "__main__":
    # Generate a test token
    jwt_secret = os.getenv("JWT_SECRET")
    if not jwt_secret:
        print("Error: JWT_SECRET not found. Please set it in .env file.")
        exit(1)
    
    test_user_id = "user@example.com"
    token = create_jwt_token(user_id=test_user_id, secret_key=jwt_secret)
    print(f"Test Token: Bearer {token}\n")

    # Start the server
    ssl_key_path = os.getenv("SSL_KEYFILE")
    ssl_cert_path = os.getenv("SSL_CERTFILE")
    
    if ssl_key_path and ssl_cert_path:
        server.run_server(port=8001, ssl_keyfile=ssl_key_path, ssl_certfile=ssl_cert_path)
    else:
        server.run_server(port=8001)
```

## Dashboard

Access the analytics dashboard at `http://localhost:8001/dashboard`. It provides:

- Real-time visualization of MCP interactions
- Server configuration details
- Lists of registered tools, resources, and prompts

![Dashboard Server Info](static/images/dashboard-server-info.png)

## Testing

```bash
# Run tests
uv run pytest

# Run all checks (linting, type checking, tests)
python run_checks.py
```

## Project Structure

```
resk-mcp/
├── resk_mcp/                 # Main library code
│   ├── server.py             # SecureMCPServer implementation
│   ├── auth.py               # JWT authentication
│   ├── validation.py         # Input validation and security
│   ├── context.py            # Context management
│   └── dashboard.py          # Dashboard routes
├── static/                   # Dashboard UI assets
├── tests/                    # Test suite
├── .env.example              # Example configuration
├── requirements.txt          # Dependencies
└── README.md
```

## CI/CD Workflow

This project uses GitHub Actions for continuous integration and deployment:

- **Automated Testing**: All pushes and PRs to the `main` branch trigger tests on Python 3.9 and 3.10
- **Code Quality**: Includes linting with flake8 and type checking with mypy
- **Package Publishing**: Tagged versions (format `v*`) are automatically published to PyPI
- **Release Creation**: GitHub Releases are automatically created for each tagged version

The workflow configuration is defined in `.github/workflows/python-package.yml`.

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to your branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

> **Note**: This project uses `main` as the default branch. All PRs should be made against the `main` branch.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This library provides basic security features. For production systems, ensure comprehensive security audits and consider more advanced techniques for PII and prompt injection detection tailored to your specific use case. 