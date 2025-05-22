# WebsiteDRF API Documentation

This project is a Django REST Framework (DRF) based web application with custom user authentication, account activation, password reset, and account deletion features.

---

## Installation Guide

1. **Clone the repository:**
    ```bash
    git clone https://github.com/xesab/WebsiteDRF
    cd WebsiteDRF
    ```

2. **Create and activate a virtual environment:**
    ```bash
    python -m venv venv
    # On Windows:
    venv\Scripts\activate
    # On macOS/Linux:
    source venv/bin/activate
    ```

3. **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4. **Set up environment variables:**
    - Copy `.env.example` to `.env` and update the values as needed.

5. **Apply migrations:**
    ```bash
    python manage.py migrate
    ```

6. **Create a superuser (optional, for admin access):**
    ```bash
    python manage.py createsuperuser
    ```

7. **Run the development server:**
    ```bash
    uvicorn website.asgi:application --host 0.0.0.0 --port 8000 --reload
    ```


## Authentication

All endpoints use JWT authentication unless otherwise specified.

### Register

- **POST** `/users/register`
- Registers a new user and sends an activation email.
- **Body:**
  - `user_name` (string, required)
  - `email` (string, required)
  - `password` (string, required)
  - `full_name` (string, required)
- **Response:** 201 Created, user data

### Activate Account

- **POST** `/users/activate`
- Activates a user account using the token sent via email.
- **Body:**
  - `token` (string, required)
- **Response:** 200 OK, account activated

### Login

- **POST** `/users/login`
- Authenticates a user and returns JWT tokens.
- **Body:**
  - `email` (string, required)
  - `password` (string, required)
- **Response:** 200 OK, access and refresh tokens

### Refresh Token

- **POST** `/users/get-access-token`
- Refreshes the JWT access token.
- **Body:**
  - `refresh` (string, required)
- **Response:** 200 OK, new access token

### Logout (Blacklist Token)

- **POST** `/users/logout`
- Blacklists the refresh token.
- **Body:**
  - `refresh` (string, required)
- **Response:** 205 Reset Content

---

## User Profile

### Get Profile

- **GET** `/users/profile`
- Returns the authenticated user's profile.
- **Auth:** Required (JWT)
- **Response:** 200 OK, user data

### Update Profile

- **PATCH** `/users/profile`
- Updates the authenticated user's profile (except email and username).
- **Auth:** Required (JWT)
- **Body:** Any updatable user fields except `email` and `user_name`
- **Response:** 200 OK, updated user data

---

## Password Management

### Forgot Password

- **POST** `/users/forgot-password`
- Sends a password reset email to the user.
- **Body:**
  - `email` (string, required)
- **Response:** 200 OK

### Reset Password

- **POST** `/users/forget-password/confirm`
- Resets the user's password using the token sent via email.
- **Body:**
  - `token` (string, required)
  - `password` (string, required)
- **Response:** 200 OK, password reset

### Change Password

- **POST** `/users/change-password`
- Changes the authenticated user's password.
- **Auth:** Required (JWT)
- **Body:**
  - `old_password` (string, required)
  - `new_password` (string, required)
- **Response:** 200 OK

---

## Account Deletion

### Request Account Deletion

- **GET** `/users/delete-account`
- Sends an account deletion confirmation email.
- **Auth:** Required (JWT)
- **Response:** 200 OK

### Confirm Account Deletion

- **POST** `/users/delete-account/confirm`
- Deletes the user account using the token sent via email.
- **Body:**
  - `token` (string, required)
- **Response:** 200 OK, account deleted

---

## Error Handling

- All endpoints return appropriate HTTP status codes and error messages in JSON format.
- Common error codes: 400 (Bad Request), 401 (Unauthorized), 403 (Forbidden), 404 (Not Found)

---

## Email Templates

- Activation, password reset, and account deletion emails use HTML templates located in `users/templates/`.

---

## Logging

- Logs are written to `website.log` (all logs) and `website_error.log` (errors).
- Logging configuration is in [`website/settings/logging.py`](website/settings/logging.py).

---

## Settings

- Environment-specific settings are in `website/settings/` (`development.py`, `production.py`, etc.).
- Uses `.env` for secrets and configuration.

---

## Models

- **User:** Custom user model with fields: `email`, `user_name`, `full_name`, `user_type`, etc.
- **GeneratedToken:** Stores one-time tokens for activation, password reset, and account deletion.

---

## Running the Project

1. Install dependencies:  
   `pip install -r requirements.txt`
2. Set up `.env` with required variables.
3. Run migrations:  
   `python manage.py migrate`
4. Start the server:  
   `python manage.py runserver`

---

## API Endpoints Summary

| Method | Endpoint                        | Description                        | Auth Required |
|--------|---------------------------------|------------------------------------|--------------|
| POST   | `/users/register`               | Register new user                  | No           |
| POST   | `/users/activate`       | Activate account                   | No           |
| POST   | `/users/login`                  | Login and get tokens               | No           |
| POST   | `/users/get-access-token`       | Refresh JWT access token           | No           |
| POST   | `/users/logout`                 | Blacklist refresh token            | Yes          |
| GET    | `/users/profile`                | Get user profile                   | Yes          |
| PATCH  | `/users/profile`                | Update user profile                | Yes          |
| POST   | `/users/forgot-password`        | Request password reset             | No           |
| POST   | `/users/forget-password/confirm`| Reset password                     | No           |
| POST   | `/users/change-password`        | Change password                    | Yes          |
| GET    | `/users/delete-account`         | Request account deletion           | Yes          |
| POST   | `/users/delete-account/confirm` | Confirm account deletion           | No           |

---

## License

See [LICENSE](LICENSE) for details.