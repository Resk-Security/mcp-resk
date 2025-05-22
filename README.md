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
pip install resk-mcp
```

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

## Troubleshooting

### JWT Authentication: "Signature verification failed"

If you encounter `WARNING:resk_mcp.server:Authentication failed for /mcp_secure: Invalid token: Signature verification failed` errors when running test_client.py against example_server.py, it means the JWT (JSON Web Token) sent by the client could not be verified by the server. This almost always indicates a mismatch in the JWT_SECRET used to sign the token (client-side or how the token was originally generated) and the JWT_SECRET used by the server to verify it.

#### How JWT Authentication is Setup in this Example:

**Server-Side (example_server.py):**

- The server relies on a JWT_SECRET for signing and verifying tokens.
- This secret is primarily configured via a .env file at the root of the project. The resk_mcp/config.py module loads this secret into the application's settings (settings.jwt_secret).
- When example_server.py starts, it generates a test JWT using this settings.jwt_secret and prints it to the console. This is the token your test_client.py should be using.

**Client-Side (test_client.py):**

- The test_client.py has a hardcoded AUTH_TOKEN variable.
- This token is sent in the Authorization header for requests to the secure MCP endpoint.

#### The Mismatch:

The "Signature verification failed" error occurs if the AUTH_TOKEN in test_client.py was not generated using the exact same JWT_SECRET that example_server.py is currently configured with (via its .env file).

#### How to Fix It:

**Ensure JWT_SECRET is Configured for the Server:**

1. Create a file named .env in the root directory of this project (e.g., alongside example_server.py).
2. Add your desired secret key to it:
   ```
   JWT_SECRET="your_very_strong_and_unique_secret_key_here"
   ```
3. Important: If you change this secret, any previously generated tokens (including the one in test_client.py) will become invalid.

**Run the Server (example_server.py):**

Execute `python example_server.py`.

**Copy the Correct Token from Server Logs:**

1. Look for a log message from the server similar to this:
   ```
   INFO:example-server:Token de test généré (utilisant JWT_SECRET du .env): eyJhbGciOiJIUzI1NiI...[long_token_string]...
   ```
   (The message might be slightly different if you changed the log language/format, but it will contain the generated token.)
2. Carefully copy the entire token string (it's usually very long).

**Update test_client.py:**

1. Open test_client.py.
2. Find the line:
   ```python
   AUTH_TOKEN = "some_old_or_incorrect_token_here"
   ```
3. Replace the old token string with the new token you just copied from the server logs.
   ```python
   AUTH_TOKEN = "eyJhbGciOiJIUzI1NiI...[the_new_long_token_string_you_copied]..."
   ```

**Run the Client (test_client.py):**

Now, execute `python test_client.py`.
The authentication errors should be gone, and your client should be able to communicate with the server successfully.

**Key Takeaway:** The AUTH_TOKEN used by the client must be a token that was signed with the exact same JWT_SECRET that the server is currently using for verification. The easiest way to ensure this in this example setup is to always use the token printed by example_server.py on startup.

## Detailed Configuration

RESK-MCP uses environment variables for configuration. Create a `.env` file in the root of your project with the following (at a minimum):

```env
# .env
JWT_SECRET="your-super-secure-jwt-secret-key-here"

# Rate Limiting (default: "100/minute")
# Examples: "5/second", "1000/hour", "20/day"
RATE_LIMIT="100/minute"

# Optional for HTTPS:
# SSL_KEYFILE="./key.pem"
# SSL_CERTFILE="./cert.pem"

# Optional for context management and logging:
# MAX_TOKEN_PER_REQUEST="4000"
# LOG_LEVEL="INFO"
```

- **JWT_SECRET**: A strong, random secret key for signing JWT tokens. This is critical for security.
- **RATE_LIMIT**: Defines the rate limit for requests. The format is count/period (e.g., 100/minute, 5/second). Defaults to 100/minute. Rate limiting is primarily based on the user_id from the JWT, falling back to IP address if the token is invalid or missing.
- **SSL_KEYFILE**: Path to your SSL private key file (e.g., key.pem).
- **SSL_CERTFILE**: Path to your SSL certificate file (e.g., cert.pem).
- **MAX_TOKEN_PER_REQUEST**: Approximate maximum tokens allowed per request (default: 4000).
- **LOG_LEVEL**: Logging level (e.g., DEBUG, INFO, WARNING, ERROR, CRITICAL, default: INFO).

### Generating SSL Certificates (for HTTPS)

For local development, you can generate self-signed certificates using OpenSSL:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/CN=localhost"
```

For production, obtain certificates from a trusted Certificate Authority (CA) like Let's Encrypt.

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
