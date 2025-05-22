# Security Policy

## Reporting a Vulnerability

The mcp-resk team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose your findings.

### How to Report a Vulnerability

Please report security vulnerabilities by emailing us at **security@resk-security.com**.

When reporting, please include:

- A description of the vulnerability
- Steps to reproduce the issue
- Potential impact of the vulnerability
- Any potential mitigations if known

### What to Expect

Once a vulnerability report is received, we will:

1. Confirm receipt of your report within 48 hours
2. Provide an initial assessment of the report within 5 business days
3. Keep you informed about our progress resolving the issue
4. Credit you for your discovery (unless you prefer to remain anonymous)

### Responsible Disclosure

We kindly ask that:

- You give us reasonable time to address the issue before any public disclosure
- You don't exploit the vulnerability beyond what's necessary to demonstrate the issue
- You don't access or modify user data without explicit permission

## Supported Versions

We provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Security Best Practices

When using mcp-resk, please follow these security best practices:

1. **JWT Secret Management**: Always use a strong, random JWT secret. Never commit this to version control.
2. **Rate Limiting**: Configure appropriate rate limits for your use case.
3. **HTTPS**: In production, always enable HTTPS with valid certificates.
4. **Regular Updates**: Keep your mcp-resk installation up to date with the latest security patches.

## Attribution

Thank you to all security researchers who help keep mcp-resk secure. We appreciate your contributions to the safety of our community. 