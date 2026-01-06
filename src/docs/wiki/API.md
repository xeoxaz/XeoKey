# API Documentation

Complete reference for all API endpoints in XeoKey.

**Navigation**: [Home](Home) | [Installation](Installation) | [Configuration](Configuration) | [Security](Security)

## Base URL

All endpoints are relative to the server base URL (default: `http://localhost:3000`).

## Authentication Endpoints

### Login

**GET `/login`**
- **Description**: Display login page
- **Authentication**: Not required
- **Response**: HTML login form

**POST `/login`**
- **Description**: Authenticate user
- **Authentication**: Not required
- **Request Body**:
  - `username` (string, required)
  - `password` (string, required)
- **Response**:
  - Success: Redirects to dashboard
  - Failure: Error message

### Registration

**GET `/register`**
- **Description**: Display registration page
- **Authentication**: Not required
- **Response**: HTML registration form

**POST `/register`**
- **Description**: Create new user account
- **Authentication**: Not required
- **Request Body**:
  - `username` (string, required, 3-20 characters, alphanumeric + underscore/hyphen)
  - `password` (string, required, min 8 characters, must contain letter and number)
- **Response**:
  - Success: Redirects to login
  - Failure: Error message

### Logout

**POST `/logout`**
- **Description**: Logout current user
- **Authentication**: Required
- **Response**: Redirects to login page

## Password Management Endpoints

### List Passwords

**GET `/passwords`**
- **Description**: List all passwords for the authenticated user
- **Authentication**: Required
- **Query Parameters**: None
- **Response**: HTML page with list of passwords (sorted by most viewed/copied)

### Add Password

**GET `/passwords/add`**
- **Description**: Display add password form
- **Authentication**: Required
- **Response**: HTML form for adding a new password

**POST `/passwords/add`**
- **Description**: Create new password entry
- **Authentication**: Required
- **Request Body** (Form Data):
  - `website` (string, required)
  - `username` (string, optional)
  - `email` (string, optional)
  - `password` (string, required)
  - `notes` (string, optional)
  - `csrfToken` (string, required)
- **Response**:
  - Success: Redirects to password details page
  - Failure: Error message

### View Password Details

**GET `/passwords/:id`**
- **Description**: View password details (increments view count)
- **Authentication**: Required
- **URL Parameters**:
  - `id` (string, required) - Password entry ID
- **Response**: HTML page with password details

### Update Password

**POST `/passwords/:id/update`**
- **Description**: Update password entry
- **Authentication**: Required
- **URL Parameters**:
  - `id` (string, required) - Password entry ID
- **Request Body** (Form Data):
  - `website` (string, required)
  - `username` (string, optional)
  - `email` (string, optional)
  - `password` (string, required)
  - `notes` (string, optional)
  - `csrfToken` (string, required)
- **Response**:
  - Success: Redirects to password details page
  - Failure: Error message

### Delete Password

**POST `/passwords/:id/delete`**
- **Description**: Delete password entry
- **Authentication**: Required
- **URL Parameters**:
  - `id` (string, required) - Password entry ID
- **Request Body** (Form Data):
  - `csrfToken` (string, required)
- **Response**:
  - Success: Redirects to passwords list
  - Failure: Error message

### Track Password Copy

**POST `/passwords/:id/copy`**
- **Description**: Track password copy event (increments copy count)
- **Authentication**: Required
- **URL Parameters**:
  - `id` (string, required) - Password entry ID
- **Response**: JSON response with success status

## Analytics Endpoints

### Get Analytics Data

**GET `/api/analytics`**
- **Description**: Get analytics data for the last 30 days
- **Authentication**: Required
- **Response**: JSON object with analytics data
  ```json
  {
    "events": [
      {
        "date": "2024-01-01",
        "views": 10,
        "copies": 5,
        "additions": 2,
        "edits": 1,
        "deletions": 0,
        "errors": 0
      }
    ],
    "total": {
      "views": 100,
      "copies": 50,
      "additions": 20,
      "edits": 10,
      "deletions": 5,
      "errors": 0
    }
  }
  ```

### Get Server Status

**GET `/api/status`**
- **Description**: Get server and database status
- **Authentication**: Required
- **Response**: JSON object with status information
  ```json
  {
    "server": {
      "uptime": 3600,
      "status": "running"
    },
    "database": {
      "connected": true,
      "uptime": 3600,
      "status": "connected"
    }
  }
  ```

## Dashboard

**GET `/`**
- **Description**: Main dashboard with analytics, charts, and recent passwords
- **Authentication**: Required
- **Response**: HTML dashboard page

## Error Responses

All endpoints may return error responses:

- **401 Unauthorized**: Authentication required
- **403 Forbidden**: CSRF token invalid or rate limit exceeded
- **404 Not Found**: Resource not found
- **500 Internal Server Error**: Server error

## Rate Limiting

Some endpoints are protected by rate limiting:
- Login: 5 attempts per 15 minutes per IP
- Registration: 5 attempts per 15 minutes per IP

## CSRF Protection

All POST endpoints require a valid CSRF token in the request body. The token is generated per session and can be obtained from the page form.

## Security Headers

All responses include security headers:
- `Content-Security-Policy`
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Strict-Transport-Security` (HTTPS only)
- `X-XSS-Protection: 1; mode=block`

For more security information, see the [Security Guide](Security).

---

**Navigation**: [Home](Home) | [Installation](Installation) | [Configuration](Configuration) | [Security](Security)

