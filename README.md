# SOK API

SOK API is an API for a competition system, providing endpoints for managing users, challenges, submissions, announcements, and competition. It is built using Node.js and Express.js, and it is released under the MIT license.

## Environment Variables

To run SOK API, you need to set several environment variables in a .env file. Here is a list of the required environment variables and their descriptions:

Competition Configuration

-   **SOK_CONFIG** - Path to a .yaml file with configuration settings.

PostgreSQL Configuration

-   **PG_HOST** - PostgreSQL host.
-   **PG_PORT** - PostgreSQL port.
-   **PG_USER** - PostgreSQL username.
-   **PG_PASSWORD** - PostgreSQL password.
-   **PG_DB** - PostgreSQL database name.

SMTP Configuration

-   **SMTP_HOST** - SMTP server host for sending emails.
-   **SMTP_FROM** - Email address from which emails will be sent.
-   **SMTP_PORT** - SMTP server port.
-   **SMTP_USER** - SMTP server username.
-   **SMTP_PASSWORD** - SMTP server password.

Client Configuration

-   **CLIENT_URL** - URL of the client application that will consume the API.

JWT Configuration

-   **TOKEN_SECRET** - A 64-byte hexadecimal string used for JWT (JSON Web Token) encryption.

Admin Account Configuration

-   **ADMIN_NAME** - Name of the admin account.
-   **ADMIN_EMAIL** - Email address of the admin account.
-   **ADMIN_PASS** - Password for the admin account.

pgAdmin (optional)

-   **PGADMIN_LISTEN** - Address on which pgAdmin will listen.
-   **PGADMIN_EMAIL** - Email for the pgAdmin account.
-   **PGADMIN_PASSWORD** - Password for the pgAdmin account.

## Getting Started

To get started with SOK API, follow these steps:

1. Clone this repository to your local machine.
    ```sh
    git clone https://github.com/JakubZojdzik/SOK-client.git
    ```
2. Create a .env file in the root directory of the project and set the required environment variables as described above.
3. Start api in dev mode using docker-compose:
    ```sh
    docker-compose up -d
    ```

## Docker Compose

Docker Compose will run the following containers:

-   **api** - The API server on `3000` port.
-   **postgres** - PostgreSQL database server on port specified in `PG_PORT` environment variable.
-   **pgadmin** - pgAdmin web interface on port `5050`.

## SOK Client

You can find Client for this project in [this repository](https://github.com/JakubZojdzik/SOK-client)

## License

This project is licensed under the [MIT License](LICENSE).

## Contributing

If you find a bug or have an idea for an improvement, please create an issue or submit a pull request.
