import logging
import os

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect

LOG = logging.getLogger("extensions")

# RATE_LIMIT_STORAGE_URI defaults to memory:// so tests and single-worker dev
# work without Redis. Compose sets it to redis://redis:6379.
_STORAGE_URI = os.getenv("RATE_LIMIT_STORAGE_URI", "memory://")
if _STORAGE_URI == "memory://":
    LOG.warning(
        "Rate limiter is using in-memory storage — limits are per-worker only. "
        "Set RATE_LIMIT_STORAGE_URI=redis://<host>:6379 for shared limits."
    )

csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100 per minute"],
    storage_uri=_STORAGE_URI,
)
