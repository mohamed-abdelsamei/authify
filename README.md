# Authify

Authify is a command-line tool that acts as an OIDC client, allowing users to login and obtain access tokens.

## Features

- Login using OpenID Connect (OIDC) - Done
- Fetch access tokens - Done
- Refresh tokens - In Progress
- Retrieve user information - Done

## Installation

To install Authify, clone the repository and build the project using Cargo:

```sh
git clone https://github.com/mohamed-abdelsamei/authify.git
cd authify
cargo build --release
```

## Usage

To use Authify, run the following command with the necessary arguments:

```sh
./authify --issuer <issuer-url> --client-id <client-id> --client-secret <client-secret> [--redirect-url <redirect-url>] [--scope <scope>] [--state <state>] [--refresh-token <refresh-token>]
```

### Example

```sh
./authify --issuer https://example.com --client-id myclientid --client-secret myclientsecret --redirect-url http://127.0.0.1:3030/callback --scope "openid profile email"
```

### Google Auth Example

To authenticate using Google, run the following command:

```sh
./authify --issuer https://accounts.google.com --client-id your-google-client-id --client-secret your-google-client-secret --redirect-url http://127.0.0.1:3030/callback --scope "openid profile email"
```

## Arguments

- `--issuer`: The issuer URL of the OIDC provider.
- `--client-id`: The client ID registered with the OIDC provider.
- `--client-secret`: The client secret registered with the OIDC provider.
- `--redirect-url`: The redirect URL for the OIDC provider (default: `http://127.0.0.1:3030/callback`).
- `--scope`: The scope of the access request (default: `openid`).
- `--state`: An optional state parameter to maintain state between the request and callback.
- `--refresh-token`: An optional refresh token to obtain a new access token.

## TODO Features

| Feature         | Description                          | Status       |
|-----------------|--------------------------------------|--------------|
| Login using OIDC| Allow users to login using OIDC      | Done         |
| Fetch tokens    | Fetch access tokens                  | Done         |
| Refresh tokens  | Implement automatic token refreshing | In Progress  |
| Retrieve info   | Retrieve user information            | Done         |
| PKCE Flow       | Support Proof Key for Code Exchange  | To Do        |

## Building and Running

To build the project, run:

```sh
cargo build --release
```

To execute the built binary, run:

```sh
./target/release/authify --issuer <issuer-url> --client-id <client-id> --client-secret <client-secret> [--redirect-url <redirect-url>] [--scope <scope>] [--state <state>] [--refresh-token <refresh-token>]
```

## Help

For more details on the available arguments, run:

```sh
./authify --help
```

## License

This project is licensed under the MIT License.