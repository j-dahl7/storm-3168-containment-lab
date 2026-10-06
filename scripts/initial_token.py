"""Bounded acquisition before a credential is frozen; never a probe refresh."""
from __future__ import annotations
from datetime import datetime, timezone
import math
import re
import time


class CredentialHTTPError(RuntimeError):
    def __init__(self, status, code, numeric_codes):
        self.status = status if type(status) is int and 100 <= status <= 599 else 0
        self.code = code if isinstance(code, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", code) else ""
        self.numeric_codes = [n for n in numeric_codes if type(n) is int][:5] if isinstance(numeric_codes, (list, tuple)) else []
        super().__init__("Credential endpoint returned a sanitized HTTP failure")


class CredentialTransportError(RuntimeError):
    def __init__(self):
        super().__init__("Credential operation transport failure")


class InitialTokenError(RuntimeError):
    pass


def acquire_initial_token(issue, *, validate, record, budget_seconds=300,
                          clock=time.monotonic, sleeper=time.sleep):
    """issue(timeout_seconds) returns a response dict; successful token returned once.

    Only known secret propagation (invalid_client/AADSTS7000215), transport,
    throttling and HTTP5xx are retryable. Each attempt is bounded by remaining
    time. No response body, URL, client ID, secret or token enters an attempt row.
    """
    if type(budget_seconds) not in {int, float} or not math.isfinite(budget_seconds) or not 0 < budget_seconds <= 300:
        raise InitialTokenError("Initial-token budget must be positive and at most 300 seconds")
    started = clock()
    deadline = started + budget_seconds
    previous_row = None
    for attempt in range(1, 33):
        remaining = deadline - clock()
        if remaining <= 0:
            if previous_row is not None:
                previous_row["terminal_reason"] = "budget_exhausted_before_next_attempt"
                record(dict(previous_row))
            raise InitialTokenError("Initial-token acquisition budget exhausted; no token frozen")
        row = {"attempt": attempt, "phase": "initial_pre_freeze", "started_at": datetime.now(timezone.utc).isoformat(),
               "request_timeout_seconds": round(min(30, remaining), 3), "budget_seconds": budget_seconds,
               "outcome": "request_started", "retryable": False, "delay_seconds": 0}
        record(dict(row))
        result = None
        try:
            result = issue(min(30, remaining))
            if clock() > deadline:
                raise InitialTokenError("Initial-token response exceeded the pre-freeze budget")
            if not isinstance(result, dict) or not isinstance(result.get("access_token"), str):
                raise InitialTokenError("Initial token endpoint returned an invalid response")
            token = result["access_token"]
            claims = validate(token)
            row.update(outcome="token_validated", finished_at=datetime.now(timezone.utc).isoformat(), elapsed_seconds=round(clock() - started, 3), token_frozen=True)
            record(dict(row))
            return token, claims
        except CredentialHTTPError as exc:
            propagation = exc.status in {400, 401} and exc.code == "invalid_client" and 7000215 in exc.numeric_codes
            row.update(outcome="http_error", http_status=exc.status, error_code=exc.code, numeric_error_codes=exc.numeric_codes,
                       retryable=propagation or exc.status == 429 or 500 <= exc.status <= 599,
                       reason="secret_propagation" if propagation else "throttled" if exc.status == 429 else "service_error" if exc.status >= 500 else "nonretryable_http_error")
        except CredentialTransportError:
            row.update(outcome="transport_error", retryable=True, reason="transport")
        except BaseException as exc:
            row.update(outcome="interrupted_or_invalid_response", finished_at=datetime.now(timezone.utc).isoformat(), elapsed_seconds=round(clock() - started, 3), token_frozen=False)
            record(dict(row))
            if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                raise
            raise InitialTokenError("Initial-token request/validation failed; no token frozen") from None
        finally:
            if isinstance(result, dict):
                result.clear()
        remaining = max(0, deadline - clock())
        delay = 15 if row.get("reason") == "secret_propagation" else min(30, 5 * 2 ** min(attempt - 1, 3))
        retry = row["retryable"] and remaining > 0 and attempt < 32
        row.update(finished_at=datetime.now(timezone.utc).isoformat(), elapsed_seconds=round(clock() - started, 3),
                   delay_seconds=min(delay, remaining) if retry else 0, token_frozen=False,
                   terminal_reason=None if retry else "nonretryable_failure" if not row["retryable"] else "budget_or_attempt_limit")
        record(dict(row))
        previous_row = row
        if not retry:
            raise InitialTokenError("Initial-token acquisition stopped; inspect sanitized attempt records") from None
        sleeper(row["delay_seconds"])
    raise InitialTokenError("Initial-token attempt limit reached; no token frozen")
