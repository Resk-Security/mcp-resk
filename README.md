# RESK-MCP: Secure Model Context Protocol Layer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

RESK-MCP is an open-source Python library designed to add a robust security and management layer over the official [Model Context Protocol (MCP) Python SDK](https://github.com/modelcontextprotocol/python-sdk). It provides features inspired by RESK-LLM, including prompt injection protection, PII detection, context management, and a dashboard to visualize MCP element interactions.

## Features

- **JWT Authentication**: Secure your MCP server endpoints with JSON Web Tokens.
- **Input Validation**: Validate incoming MCP requests using Pydantic.
- **PII Detection**: Basic detection of Personally Identifiable Information (PII) in request parameters.
- **Prompt Injection Protection**: Basic detection of common prompt injection phrases.
- **Rate Limiting**: Protect your server from abuse with per-user or per-IP rate limits (using `slowapi`). Configurable via `RATE_LIMIT` environment variable (e.g., "100/minute").
- **Token-Based Context Management**: Limit request size based on an estimated token count to prevent abuse.
- **Interaction Tracking**: Monitor calls to tools, resources, and prompts.
- **Dashboard**: A comprehensive web-based dashboard (using FastAPI and Chart.js) to visualize interaction counts for MCP elements and monitor server configuration.
- **Easy Configuration**: Configure secrets and parameters using environment variables.
- **HTTPS Support**: Instructions for running the server with SSL/TLS.

## Installation

1.  **Clone the repository (if you're contributing or running from source):
    ```bash
    git clone https://github.com/<your-github-username>/resk-mcp.git
    cd resk-mcp
    ```

2.  **Create a virtual environment and activate it:**
    ```bash
    # Using Python's built-in venv
    python -m venv venv
    
    # On Windows
    # .\venv\Scripts\activate
    
    # On macOS/Linux
    # source venv/bin/activate
    
    # Alternatively, use uv to create and activate a virtual environment
    # uv venv
    # uv venv activate
    ```

3.  **Install dependencies using uv (recommended):**
    ```bash
    # Install uv if you don't have it already
    # curl -LsSf https://astral.sh/uv/install.sh | sh

    # Install dependencies
    uv pip install -r requirements.txt
    
    # For development with editable install
    uv pip install -e .
    
    # If you plan to contribute or run tests
    uv pip install -e ".[dev]"
    ```

   **Alternative installation using pip:**
    ```bash
    pip install -r requirements.txt
    
    # For development with editable install
    pip install -e .
    ```

## Configuration

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

-   `JWT_SECRET`: A strong, random secret key for signing JWT tokens. **This is critical for security.**
-   `RATE_LIMIT`: Defines the rate limit for requests. The format is `count/period` (e.g., `100/minute`, `5/second`). Defaults to `100/minute`. Rate limiting is primarily based on the `user_id` from the JWT, falling back to IP address if the token is invalid or missing.
-   `SSL_KEYFILE`: Path to your SSL private key file (e.g., `key.pem`).
-   `SSL_CERTFILE`: Path to your SSL certificate file (e.g., `cert.pem`).
-   `MAX_TOKEN_PER_REQUEST`: Approximate maximum tokens allowed per request (default: 4000).
-   `LOG_LEVEL`: Logging level (e.g., DEBUG, INFO, WARNING, ERROR, CRITICAL, default: INFO).

### Generating SSL Certificates (for HTTPS)

For local development, you can generate self-signed certificates using OpenSSL:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/CN=localhost"
```

For production, obtain certificates from a trusted Certificate Authority (CA) like Let's Encrypt.

## Usage

Here's how to use `SecureMCPServer` to create a secure MCP application:

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
    print(f"Executing add tool with: a={a}, b={b}")
    return a + b

@server.resource(path_pattern="info/version")
async def get_version() -> dict:
    """Returns the application version."""
    return {"version": "1.0-secure"}

if __name__ == "__main__":
    # Generate a test token for a user (in a real app, this would be part of your auth flow)
    # Ensure JWT_SECRET is loaded from .env or set in environment
    jwt_secret = os.getenv("JWT_SECRET")
    if not jwt_secret:
        print("Error: JWT_SECRET not found. Please set it in .env file or environment.")
        exit(1)
    
    test_user_id = "user@example.com"
    token = create_jwt_token(user_id=test_user_id, secret_key=jwt_secret)
    print(f"Generated Test Token for {test_user_id}: Bearer {token}\n")

    ssl_key_path = os.getenv("SSL_KEYFILE")
    ssl_cert_path = os.getenv("SSL_CERTFILE")

    print("Starting RESK-MCP server...")
    print(f"Dashboard available at: http(s)://localhost:8001/dashboard")
    print(f"Secure MCP endpoint at: http(s)://localhost:8001/mcp_secure")
    
    if ssl_key_path and ssl_cert_path:
        print(f"Running with HTTPS. Key: {ssl_key_path}, Cert: {ssl_cert_path}")
        server.run_server(port=8001, ssl_keyfile=ssl_key_path, ssl_certfile=ssl_cert_path)
    else:
        print("Running with HTTP. For HTTPS, set SSL_KEYFILE and SSL_CERTFILE in .env")
        server.run_server(port=8001)

```

**To run this example:**

1.  Save the code above as `main.py` in your project root.
2.  Ensure you have a `.env` file configured as described above.
3.  Run the server: `python main.py`

### Accessing the Secure Endpoint

You'll need a valid JWT token to access the `/mcp_secure` endpoint. The example server prints a test token upon startup.

Example using `curl` (replace `<your_token>` with the actual token):

```bash
# If running HTTP
curl -X POST http://localhost:8001/mcp_secure \
     -H "Authorization: Bearer <your_token>" \
     -H "Content-Type: application/json" \
     -d '{
         "method": "tool/calculator/add",
         "params": {"a": 5, "b": 7},
         "id": 1
     }'

# If running HTTPS (with self-signed cert, add -k or --insecure)
curl -k -X POST https://localhost:8001/mcp_secure \
     -H "Authorization: Bearer <your_token>" \
     -H "Content-Type: application/json" \
     -d '{
         "method": "tool/calculator/add",
         "params": {"a": 5, "b": 7},
         "id": 1
     }'
```

### Basic Issues

## Troubleshooting JWT Authentication: "Signature verification failed"

If you encounter `WARNING:resk_mcp.server:Authentication failed for /mcp_secure: Invalid token: Signature verification failed` errors when running `test_client.py` against `example_server.py`, it means the JWT (JSON Web Token) sent by the client could not be verified by the server. This almost always indicates a mismatch in the `JWT_SECRET` used to sign the token (client-side or how the token was originally generated) and the `JWT_SECRET` used by the server to verify it.

**How JWT Authentication is Setup in this Example:**

1.  **Server-Side (`example_server.py`):**
    *   The server relies on a `JWT_SECRET` for signing and verifying tokens.
    *   This secret is primarily configured via a `.env` file at the root of the project. The `resk_mcp/config.py` module loads this secret into the application's settings (`settings.jwt_secret`).
    *   When `example_server.py` starts, it generates a test JWT using this `settings.jwt_secret` and prints it to the console. This is the token your `test_client.py` *should* be using.

2.  **Client-Side (`test_client.py`):**
    *   The `test_client.py` has a hardcoded `AUTH_TOKEN` variable.
    *   This token is sent in the `Authorization` header for requests to the secure MCP endpoint.

**The Mismatch:**

The "Signature verification failed" error occurs if the `AUTH_TOKEN` in `test_client.py` was *not* generated using the exact same `JWT_SECRET` that `example_server.py` is currently configured with (via its `.env` file).

**How to Fix It:**

1.  **Ensure `JWT_SECRET` is Configured for the Server:**
    *   Create a file named `.env` in the root directory of this project (e.g., alongside `example_server.py`).
    *   Add your desired secret key to it:
        ```env
        JWT_SECRET="your_very_strong_and_unique_secret_key_here"
        ```
    *   **Important:** If you change this secret, any previously generated tokens (including the one in `test_client.py`) will become invalid.

2.  **Run the Server (`example_server.py`):**
    *   Execute `python example_server.py`.

3.  **Copy the Correct Token from Server Logs:**
    *   Look for a log message from the server similar to this:
        ```
        INFO:example-server:Token de test généré (utilisant JWT_SECRET du .env): eyJhbGciOiJIUzI1NiI...[long_token_string]...
        ```
        *(The message might be slightly different if you changed the log language/format, but it will contain the generated token.)*
    *   Carefully copy the **entire token string** (it's usually very long).

4.  **Update `test_client.py`:**
    *   Open `test_client.py`.
    *   Find the line:
        ```python
        AUTH_TOKEN = "some_old_or_incorrect_token_here"
        ```
    *   Replace the old token string with the **new token you just copied** from the server logs.
        ```python
        AUTH_TOKEN = "eyJhbGciOiJIUzI1NiI...[the_new_long_token_string_you_copied]..."
        ```

5.  **Run the Client (`test_client.py`):**
    *   Now, execute `python test_client.py`.
    *   The authentication errors should be gone, and your client should be able to communicate with the server successfully.

**Key Takeaway:** The `AUTH_TOKEN` used by the client *must* be a token that was signed with the *exact same `JWT_SECRET`* that the server is currently using for verification. The easiest way to ensure this in this example setup is to always use the token printed by `example_server.py` on startup.

### Accessing the Dashboard

Open your browser and navigate to `http://localhost:8001/dashboard` (or `https://localhost:8001/dashboard` if using HTTPS) to see the interaction counts and server information.

The dashboard consists of two main tabs:

1. **Analytics Tab**: Displays visualizations of tool, resource, and prompt usage with interactive charts.

2. **Server Info Tab**: Provides detailed information about your RESK-MCP server configuration:
   - Server name and title
   - Authentication method and JWT expiration
   - Rate limit configuration
   - Server uptime
   - Lists of all registered tools, resources, and prompts

![RESK-MCP Dashboard - Server Information View](static/images/dashboard-server-info.png)

*The screenshot above shows the Server Information tab displaying configuration details and registered MCP tools including calculator/add and greeting/hello.*

You can refresh the data using the "Refresh Data" button at the bottom of the dashboard. The dashboard is protected by basic authentication which can be configured in the `config.yaml` file:

```yaml
# --- Dashboard Settings ---
dashboard:
  # Authentication for the dashboard
  auth:
    # Enable authentication for dashboard
    enabled: true
    # Default username for dashboard access
    username: "admin"
    # Default password for dashboard access
    password: "admin"
    # Session expiration time in minutes
    session_expire_minutes: 60
```

The dashboard authentication is separate from the MCP authentication system and provides a simple way to protect your monitoring interface. For production use, consider using stronger passwords.

#### Dashboard Features:

- **Real-time updates** of MCP interaction counts
- **Visual charts** for quick analysis of tool, resource, and prompt usage
- **Server configuration overview** with essential parameters
- **Tool discovery** through comprehensive listing of registered MCP elements
- **Session-based authentication** with configurable timeout

To customize the dashboard appearance or add more features, modify the HTML/JavaScript files in the `static/` directory.

## Cursor Integration Example

To use a tool from your `SecureMCPServer` within Cursor (or any MCP client that supports HTTP/JSON transport and custom headers):

1.  **Ensure your `SecureMCPServer` is running** (e.g., using `python main.py`). Make sure it's accessible from where Cursor is running (e.g., `localhost` if on the same machine).

2.  **Obtain a valid JWT token.** The example `main.py` prints one upon startup if you uncomment the generation part or implement your own user authentication flow that issues tokens.

3.  **Configure Cursor (or your MCP client):**
    *   **Server URL/Endpoint**: This will be your `/mcp_secure` endpoint (e.g., `http://localhost:8001/mcp_secure` or `https://localhost:8001/mcp_secure`).
    *   **Authentication**: The client needs to send the JWT token in the `Authorization` header as a Bearer token.

4.  **Example Cursor Prompt to Test the Calculator Tool:**

    If Cursor allows specifying custom headers for MCP connections, you would configure it to use your server's `/mcp_secure` URL and add an `Authorization: Bearer <your_token>` header.

    Once connected, you could try a prompt like this (assuming the `calculator/add` tool is registered):

    ```
    @my_secure_mcp_server
    Use the calculator/add tool to add 5 and 7.
    What is the result?
    ```

    *(The exact syntax `@my_secure_mcp_server` depends on how you name and register the server connection in Cursor or your specific MCP client.)*

    **Note on standard MCP clients and `FastMCP` transports:**
    The `SecureMCPServer` in this library, particularly the `/mcp_secure` endpoint, is designed for HTTP/JSON based MCP interactions. Standard `FastMCP` often uses other transports like stdio or SSE directly. For those transports, integrating JWT, rate limiting, and other security features would require modifying or wrapping FastMCP's core transport handling logic more deeply. The current rate limiting implementation leverages FastAPI middleware and applies to the defined HTTP `/mcp_secure` endpoint.

## Running Tests

To run the unit tests using uv (recommended):

```bash
uv run pytest
```

Or to run with verbose output:

```bash
uv run pytest -v
```

Alternative with pip:

```bash
pytest
```

This will discover and run tests in the `tests/` directory.

## Running All Local Checks

For convenience, a script is provided to run all local checks in one go:

```bash
# Make the script executable (Unix/Linux/macOS)
chmod +x run_checks.py

# Run all checks
python run_checks.py
```

This will:
1. Install the package with development dependencies
2. Run linting with flake8
3. Run type checking with mypy
4. Run tests with pytest

The script provides colorized output to easily see which checks passed or failed.

## Project Structure

```
resk-mcp/
├── resk_mcp/                 # Main library code
│   ├── __init__.py
│   ├── server.py             # SecureMCPServer class
│   ├── auth.py               # JWT authentication helpers
│   ├── validation.py         # Input validation, PII, prompt injection
│   ├── context.py            # Context management
│   └── dashboard.py          # Dashboard FastAPI routes
├── static/
│   ├── dashboard.html        # Analytics dashboard with charts
│   ├── login.html            # Authentication page for dashboard
│   └── images/               # Dashboard screenshots and images
├── tests/
│   ├── __init__.py
│   ├── test_auth.py
│   ├── test_validation.py
│   ├── test_context.py
│   └── test_server.py        # Server and endpoint tests
├── .env.example              # Example environment file
├── main.py                   # Example usage (as shown above)
├── requirements.txt
├── README.md
└── LICENSE
```

## Contributing

Contributions are welcome! Please feel free to submit issues, fork the repository, and create pull requests.

1.  Fork the Project
2.  Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3.  Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4.  Push to the Branch (`git push origin feature/AmazingFeature`)
5.  Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This library provides basic security features. For production systems, ensure comprehensive security audits and consider more advanced techniques for PII and prompt injection detection tailored to your specific use case. 