# simple-test

A simple penetration testing tool for web applications. Use only on systems you own or have explicit permission to test.

## Features

- **JWT Forge** – Create forged JWTs using a known secret (e.g. hardcoded JWT_SECRET)
- **CORS Test** – Check if APIs allow requests from arbitrary origins
- **XSS Payloads** – Generate and copy XSS payloads for CMS/v-html testing
- **Upload Test** – Test file upload endpoints for missing validation (.exe, .php, .svg, .html)
- **API Probe** – Probe endpoints with no auth, invalid token, or forged JWT

## Quick Start

```bash
cd simple-test
npm install
npm start
```

Open http://localhost:3333 in your browser.

## Usage

1. **JWT Forge**: Paste your JWT_SECRET (hex string from Terraform/config), edit the payload (e.g. add `role: "admin"`), click "Forge JWT", then "Test Against API" with your Strapi admin URL.
2. **CORS Test**: Enter your Strapi API URL and click "Test CORS". If the request succeeds, CORS may be misconfigured.
3. **XSS Payloads**: Click a payload to copy it, then paste into Strapi rich text fields that render with `v-html`.
4. **Upload Test**: Enter your upload-cv endpoint URL, then test with .exe, .svg, .php, or .html to check for validation bypass.
5. **API Probe**: Test endpoints with different auth scenarios to find broken access control.

## Disclaimer

Use only for authorized security testing. Unauthorized access to computer systems is illegal.
