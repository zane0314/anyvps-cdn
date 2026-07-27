#!/usr/bin/env python3
from server import main
from substore import (  # re-exported for backward compatibility (tests import app)
    add_no_cache_param,
    add_refresh_param,
    substore_verify_url,
    upload_to_substore,
    verify_subscription,
)

if __name__ == "__main__":
    main()
