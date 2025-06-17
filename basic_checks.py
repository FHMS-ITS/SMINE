"""Asserts that all necessary components are functional."""

import os
import sys


def run_checks():
    if not in_venv():
        print("Please activate the virtual environment. In ~/SMIME run:")
        print("source venv/bin/activate")
        sys.exit(1)
    print("Virtual environment is active")

    if not can_import_modules():
        print("Error importing modules, are you in the correct virtual environment?")
        print(
            "If you created a new virtual environment, you need to install the required packages:"
        )
        print("pip install -r requirements.txt")
        sys.exit(1)
    print("All required modules are importable")

    if not can_import_our_modules():
        print("Error importing our modules, did you set the PYTHONPATH correctly?")
        print("From ~/SMIME run:")
        print("export PYTHONPATH=$(pwd)")
        sys.exit(1)
    print("All our modules are importable")

    if not db_is_okay():
        print("Error running aggregation on MongoDB, please contact authors.")
        sys.exit(1)
    print("MongoDB is functional")

    if not redis_is_okay():
        print("Error accessing redis cache, please contact authors.")
        sys.exit(1)
    print("Redis cache is functional")

    print("All checks passed!")


def in_venv():
    return sys.prefix != sys.base_prefix


def can_import_modules():
    try:
        import pymongo
        import redis
        import requests
        import ujson

        return True
    except ImportError as ex:
        print(repr(ex), file=sys.stderr)
        return False


def can_import_our_modules():
    try:
        import analysis
        import smime_chain_verifier

        return True
    except ImportError as ex:
        print(repr(ex), file=sys.stderr)
        return False


def db_is_okay():
    from analysis.utils.aggregate import aggregate_certs

    try:
        count_certs_pipeline = [{"$sort": {"_id": 1}}, {"$count": "count"}]
        count_result = aggregate_certs(count_certs_pipeline)
        assert count_result
        total_certs = count_result[0].get("count")
        print(f"Total certificates: {total_certs:,}")
        return True
    except Exception as ex:
        print(repr(ex), file=sys.stderr)
        return False


def redis_is_okay():
    from smime_chain_verifier.cache.cache import Cache

    try:
        cache = Cache("localhost")
        cache.get_cached_access_locations()
        return True
    except Exception as ex:
        print(repr(ex), file=sys.stderr)
        return False


if __name__ == "__main__":
    if os.uname().nodename != "smine-artifact-eval":
        print(
            "This script is only intended to run on the machine provided to the AE reviewers."
        )
        sys.exit(1)
    run_checks()
