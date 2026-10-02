# Login Attempt Control System

A defensive Python authentication control mechanism that tracks failed login
attempts by username/IP, applies progressive delays, enforces a 15-minute
temporary lockout after 5 consecutive failures, and records security audit
events.

## Features

- Failed login counter by username + IP
- Progressive delay after failed attempts
- 15-minute lockout after 5 consecutive failures
- Successful login resets the failed-attempt counter
- Security audit logging
- Simulated brute-force test

## Requirements

- Python 3.9+
- No external packages required

## Run

```bash
python login_control.py
```

## Expected Test

The simulated brute-force loop sends repeated invalid credentials.

Expected behavior:

1. Failures are counted.
2. Progressive delays are applied.
3. The fifth consecutive failure triggers a 15-minute lockout.
4. Further authentication is blocked while locked.
5. Lockout is recorded in `security_audit.log`.

## Security Note

This project is a local defensive demonstration. Production authentication
systems should use a persistent datastore, secure password hashing such as
Argon2/bcrypt, distributed rate limiting, and appropriate account recovery
controls.
