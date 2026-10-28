"""Step-up client for the principal's device: list, approve and deny PCA step-ups.

A step-up is a co-signature request: an action whose risk needs more than the agent's signature. The principal's device
signs the step-up's threshold message with its Ed25519 key and the instance anchors the action once enough roles have signed.

* ``dashboard_url`` plus a dashboard bearer token (a service key or a console session token) serve
  ``GET/POST .../pca/stepups`` (list, deny). Deny needs an owner or admin role.
* ``instance_url`` (the Atlas instance the agent talks to) serves the public, self-authenticating
  ``POST /v1/pca/stepups/<id>/cosign``; the device signature is the credential.

The device key is a SOFTWARE key (the PCA principal key must be Ed25519): the seed lives in the :class:`SecretStore` you
give it. :class:`FileSecretStore` writes a mode-0600 file; for a phone or desktop app back it with the platform keystore
and gate approvals behind user presence. Signing uses the optional ``cryptography`` package when installed (constant time);
otherwise the built-in pure-Python signer, which is not constant time.

Standard library only; HTTP redirects are refused so a bearer token never follows a redirect to another host.
"""
from __future__ import annotations

import calendar
import json
import os
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, List, Optional, Tuple

from . import ed25519
from .pca import b64u, decode_b64u_strict

Transport = Callable[[str, str, dict, Optional[bytes]], Tuple[int, str]]


class StepUpError(Exception):
    """Base of every step-up client error."""


class NoDeviceKey(StepUpError):
    """No principal key is stored on this device."""


class InvalidSecret(StepUpError):
    """The secret is not a base64url 32-byte Ed25519 seed."""


class InvalidThresholdMessage(StepUpError):
    """The step-up's threshold message is not canonical base64url."""


class PrincipalMismatch(StepUpError):
    """The server refused the signature (403): this key is not the grant's principal."""


class ApiError(StepUpError):
    """The server answered with an error status."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class TransportError(StepUpError):
    """The request failed on the network or the answer was unreadable."""


# ---- the device key --------------------------------------------------------------------------------------------------

class SecretStore:
    """Where the 32-byte Ed25519 seed is persisted: ``load() -> bytes | None``, ``save(seed)``, ``delete()``."""

    def load(self) -> Optional[bytes]:  # pragma: no cover - protocol
        raise NotImplementedError

    def save(self, secret: bytes) -> None:  # pragma: no cover - protocol
        raise NotImplementedError

    def delete(self) -> None:  # pragma: no cover - protocol
        raise NotImplementedError


class MemorySecretStore(SecretStore):
    """In-memory store, for tests and previews only."""

    def __init__(self) -> None:
        self._v: Optional[bytes] = None

    def load(self) -> Optional[bytes]:
        return self._v

    def save(self, secret: bytes) -> None:
        self._v = bytes(secret)

    def delete(self) -> None:
        self._v = None


class FileSecretStore(SecretStore):
    """A file holding the seed as base64url, created with mode 0600."""

    def __init__(self, path: str) -> None:
        self._path = path

    def load(self) -> Optional[bytes]:
        try:
            with open(self._path, "r", encoding="ascii") as f:
                return decode_b64u_strict(f.read().strip())
        except FileNotFoundError:
            return None

    def save(self, secret: bytes) -> None:
        fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(b64u(secret))
        os.chmod(self._path, 0o600)

    def delete(self) -> None:
        try:
            os.remove(self._path)
        except FileNotFoundError:
            pass


def _sign(seed: bytes, message: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        return ed25519.sign(seed, message)
    return Ed25519PrivateKey.from_private_bytes(seed).sign(message)


class PrincipalDeviceKey:
    """The principal's Ed25519 device key, held in a :class:`SecretStore`."""

    def __init__(self, store: SecretStore) -> None:
        self._store = store

    @property
    def exists(self) -> bool:
        try:
            return self._store.load() is not None
        except Exception:  # noqa: BLE001
            return False

    def generate(self) -> str:
        """Generate a fresh key (replacing any existing one). Returns the public key (base64url) to register as the grant's principal."""
        seed = secrets.token_bytes(32)
        self._store.save(seed)
        return b64u(ed25519.public_key(seed))

    def import_secret(self, secret_b64u: str) -> str:
        """Import an existing principal secret (a base64url 32-byte seed). It MUST match the grant's principal. Returns the public key."""
        raw = decode_b64u_strict(secret_b64u, 32)
        if raw is None:
            raise InvalidSecret("The secret must be a base64url 32-byte Ed25519 seed.")
        self._store.save(raw)
        return b64u(ed25519.public_key(raw))

    def export_secret(self) -> str:
        """The secret (base64url seed) for backup or migration. Treat it like a password."""
        return b64u(self._seed())

    def public_key(self) -> str:
        """The public key (base64url), as registered on the grant."""
        return b64u(ed25519.public_key(self._seed()))

    def sign(self, message: bytes) -> str:
        """Ed25519-sign `message`; returns the signature as base64url."""
        return b64u(_sign(self._seed(), bytes(message)))

    def delete(self) -> None:
        """Remove the key from storage."""
        self._store.delete()

    def _seed(self) -> bytes:
        seed = self._store.load()
        if seed is None:
            raise NoDeviceKey("No principal device key is stored.")
        if len(seed) != 32:
            raise InvalidSecret("The stored secret is not a 32-byte seed.")
        return seed


# ---- the client ------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class PendingStepUp:
    id: str
    grant_ref: str
    action_verb: str
    action_resource: str
    required_t: int
    #: base64url bytes the device signs
    threshold_message: str
    #: epoch ms
    expires_at: int


@dataclass(frozen=True)
class ApproveResult:
    #: the server's status text (e.g. ``anchored`` or ``pending``)
    status: str
    #: True when the action is now anchored (200 and ``allow``); False on 202: more roles are still required
    anchored: bool
    http_status: int


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a: Any, **k: Any) -> None:  # a 3xx is an error, never followed
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _urllib_transport(timeout: float) -> Transport:
    def go(method: str, url: str, headers: dict, body: Optional[bytes]) -> Tuple[int, str]:
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with _OPENER.open(req, timeout=timeout) as resp:
                return resp.status, resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        except (urllib.error.URLError, OSError) as e:
            raise TransportError(str(e)) from e
    return go


_ISO = re.compile(r"^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?Z$")


def _parse_iso(s: str) -> int:
    """``2026-10-06T18:00:00.123Z`` (fraction optional, always UTC from the API) to epoch ms."""
    m = _ISO.match(s)
    if not m:
        raise ValueError("bad timestamp")
    y, mo, d, h, mi, se = (int(m.group(i)) for i in range(1, 7))
    frac = int((m.group(7) or "0").ljust(3, "0")[:3])
    return calendar.timegm((y, mo, d, h, mi, se, 0, 0, 0)) * 1000 + frac


def _base(url: str) -> str:
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https") or not u.netloc:
        raise ValueError("a step-up URL must be an http(s) URL: %r" % url)
    return url.rstrip("/")


class StepUpClient:
    """Lists, approves and denies PCA step-ups from the principal's device.

    ``token`` is a callable returning the dashboard bearer token (called per request). ``transport(method, url, headers,
    body) -> (status, text)`` replaces the built-in HTTP client (tests, proxies); it raises :class:`TransportError` on a
    network failure. ``now`` is the clock in epoch ms."""

    def __init__(self, dashboard_url: str, instance_url: str, account_id: str, instance_id: str, key: PrincipalDeviceKey,
                 token: Callable[[], str], *, transport: Optional[Transport] = None, now: Optional[Callable[[], int]] = None,
                 timeout: float = 30.0) -> None:
        self._dash, self._inst = _base(dashboard_url), _base(instance_url)
        self._acct, self._instance_id, self.key, self._token = account_id, instance_id, key, token
        self._http = transport or _urllib_transport(timeout)
        self._now = now or (lambda: int(time.time() * 1000))

    def _stepups_url(self) -> str:
        q = urllib.parse.quote
        return "%s/v1/dashboard/accounts/%s/instances/%s/pca/stepups" % (self._dash, q(self._acct, safe=""), q(self._instance_id, safe=""))

    def _call(self, method: str, url: str, headers: dict, body: Optional[bytes] = None) -> Tuple[int, str]:
        status, text = self._http(method, url, headers, body)
        if not 200 <= status < 300:
            msg = "The request failed."
            try:
                msg = json.loads(text)["errors"][0]["message"]
            except Exception:  # noqa: BLE001
                pass
            if status == 403:
                raise PrincipalMismatch(msg)
            raise ApiError(status, msg)
        return status, text

    def _auth(self) -> dict:
        return {"Authorization": "Bearer " + self._token(), "Accept": "application/json"}

    def pending(self) -> List[PendingStepUp]:
        """Pending, not-yet-expired step-ups."""
        _, text = self._call("GET", self._stepups_url() + "?status=pending", self._auth())
        try:
            items = json.loads(text)["stepups"]
            assert isinstance(items, list)
        except Exception as e:  # noqa: BLE001
            raise TransportError("Unreadable step-up list.") from e
        t, out = self._now(), []
        for o in items:
            try:
                exp = _parse_iso(o["expires_at"])
                if exp <= t:
                    continue
                a = o["action"]
                req_t = o["required_t"]
                if isinstance(req_t, bool) or not isinstance(req_t, int):
                    raise ValueError("required_t")
                out.append(PendingStepUp(id=_s(o["id"]), grant_ref=_s(o["grant_ref"]), action_verb=_s(a["verb"]),
                                         action_resource=_s(a["resource"]), required_t=req_t,
                                         threshold_message=_s(o["threshold_message"]), expires_at=exp))
            except Exception as e:  # noqa: BLE001
                raise TransportError("Unreadable step-up entry.") from e
        return out

    def approve(self, step_up: PendingStepUp) -> ApproveResult:
        """Sign the step-up's threshold message with the device key and submit it. Raises :class:`PrincipalMismatch` (server
        403) when this key is not the grant's principal."""
        message = decode_b64u_strict(step_up.threshold_message)
        if message is None:
            raise InvalidThresholdMessage("The step-up's threshold message is not canonical base64url.")
        payload = json.dumps({"role": "principal", "publicKey": self.key.public_key(), "sig": self.key.sign(message)}).encode()
        url = "%s/v1/pca/stepups/%s/cosign" % (self._inst, urllib.parse.quote(step_up.id, safe=""))
        status, text = self._call("POST", url, {"Content-Type": "application/json", "Accept": "application/json"}, payload)
        try:
            obj = json.loads(text)
            obj = obj if isinstance(obj, dict) else {}
        except ValueError:
            obj = {}
        st = obj.get("status")
        # 200 + allow:true = anchored; 202 = more roles still required
        return ApproveResult(status=st if isinstance(st, str) else "", anchored=obj.get("allow") is True, http_status=status)

    def deny(self, step_up: PendingStepUp, reason: Optional[str] = None) -> None:
        """Deny a pending step-up (dashboard endpoint; audited; owner or admin)."""
        url = "%s/%s/deny" % (self._stepups_url(), urllib.parse.quote(step_up.id, safe=""))
        headers = dict(self._auth(), **{"Content-Type": "application/json"})
        self._call("POST", url, headers, json.dumps({} if reason is None else {"reason": reason}).encode())


def _s(v: Any) -> str:
    if not isinstance(v, str):
        raise ValueError("expected a string")
    return v
