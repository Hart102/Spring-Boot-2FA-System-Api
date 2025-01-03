# Spring Boot API: User Authentication and Profile Management

This Spring Boot API provides essential features for 
user registration, user authentication, and 
OTP-based email verification and secure access token handling.

---

## Features

1. **User Registration**
    - Users can register by providing their email, password, and other details.

2. **User Login**
    - Users can log in using their email and password.
    - Upon successful login, a new OTP is sent to their email for verification.

3. **OTP Verification**
    - Users submit the received OTP to verify their identity.
    - The system responds with:
        - **Success**: Access token and user data.
        - **Error**: An appropriate error message if the OTP is invalid or expired.

4. **Get User Profile**
    - An endpoint to retrieve user profile details.
    - Requires a valid access token for authorization.

---

### Api Doc:
https://springboot-two-way-authentication-sys.onrender.com/swagger-ui/index.html