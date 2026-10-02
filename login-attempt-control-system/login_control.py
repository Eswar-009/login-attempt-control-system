import time
import logging
from collections import defaultdict
from dataclasses import dataclass

MAX_FAILURES = 5
LOCKOUT_SECONDS = 15 * 60
PROGRESSIVE_DELAY_BASE = 1.0

logging.basicConfig(
    filename="security_audit.log",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

@dataclass
class AccountState:
    failed_attempts: int = 0
    locked_until: float = 0.0
    delay_until: float = 0.0

class LoginAttemptControl:
    def __init__(self):
        self.accounts = defaultdict(AccountState)
        self.credentials = {"admin": "SecurePass123!"}

    def _key(self, username, ip):
        return f"{username}|{ip}"

    def is_locked(self, username, ip):
        state = self.accounts[self._key(username, ip)]
        return time.time() < state.locked_until

    def authenticate(self, username, password, ip):
        key = self._key(username, ip)
        state = self.accounts[key]
        now = time.time()

        if now < state.locked_until:
            remaining = int(state.locked_until - now)
            logging.warning(
                "LOCKOUT_BLOCKED username=%s ip=%s remaining_seconds=%s",
                username, ip, remaining
            )
            return False, f"Account locked. Try again in {remaining} seconds."

        if now < state.delay_until:
            remaining = round(state.delay_until - now, 2)
            return False, f"Rate limited. Retry after {remaining} seconds."

        if username in self.credentials and self.credentials[username] == password:
            state.failed_attempts = 0
            state.delay_until = 0
            logging.info("LOGIN_SUCCESS username=%s ip=%s", username, ip)
            return True, "Login successful."

        state.failed_attempts += 1
        logging.warning(
            "LOGIN_FAILURE username=%s ip=%s failed_attempts=%s",
            username, ip, state.failed_attempts
        )

        if state.failed_attempts >= MAX_FAILURES:
            state.locked_until = now + LOCKOUT_SECONDS
            logging.error(
                "ACCOUNT_LOCKED username=%s ip=%s duration_seconds=%s",
                username, ip, LOCKOUT_SECONDS
            )
            return False, "Account locked for 15 minutes after 5 failed attempts."

        delay = PROGRESSIVE_DELAY_BASE * (2 ** (state.failed_attempts - 1))
        state.delay_until = now + delay
        return False, (
            f"Invalid credentials. Failure {state.failed_attempts}/{MAX_FAILURES}. "
            f"Progressive delay: {delay:.0f}s."
        )

def simulate_bruteforce():
    system = LoginAttemptControl()
    username = "admin"
    ip = "192.0.2.10"

    print("=== Simulated Brute-Force Test ===")
    for attempt in range(1, 8):
        # Test harness clears progressive delay so the simulation can
        # demonstrate the lockout threshold without waiting in real time.
        system.accounts[system._key(username, ip)].delay_until = 0
        success, message = system.authenticate(username, "WrongPassword!", ip)
        print(f"Attempt {attempt}: {message}")
        if system.is_locked(username, ip):
            print("RESULT: LOCKOUT ENFORCED")
            break

if __name__ == "__main__":
    simulate_bruteforce()
