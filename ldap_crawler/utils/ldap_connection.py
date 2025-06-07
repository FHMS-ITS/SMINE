from __future__ import annotations
import logging
import time
from typing import TYPE_CHECKING
from enum import Enum
import re
import ldap
from ldap.ldapobject import LDAPObject, ReconnectLDAPObject

if TYPE_CHECKING:
    from crawler import LDAPCrawler

DEFAULT_PORT = 389
TLS_PORT = 636

NETWORK_TIMEOUT = 3
OPERATION_TIMEOUT = 20
MAX_SANITY_CHECKS_PER_SEARCH = 3


class RetriesExceeded(Exception):
    pass


class ConnectionMode(Enum):
    AnonymousWithoutBind = 1
    AnonymousViaSimpleAuthentication = 2
    UnauthenticatedBind = 3
    AuthenticatedBind = 4


def get_connection(
    mode: ConnectionMode,
    target,
    username=None,
    password=None,
    protocol_version=ldap.VERSION3,
    start_TLS=False,
    certificate_validation=False,
    retry_max=3,
    retry_delay=10.0,
):
    logging.debug("Getting LDAP Connection Object")
    try:
        conn = ReconnectLDAPObject(target, retry_max=retry_max, retry_delay=retry_delay)
        conn.protocol_version = protocol_version
        conn.set_option(ldap.OPT_NETWORK_TIMEOUT, NETWORK_TIMEOUT)
        conn.set_option(ldap.OPT_TIMEOUT, OPERATION_TIMEOUT)

        if is_implicit_TLS(target) or start_TLS:
            set_tls_options(conn, certificate_validation)
        if start_TLS:
            conn.start_tls_s()

        match mode:
            case ConnectionMode.AnonymousWithoutBind:
                pass  # No further setup required.
            case ConnectionMode.AnonymousViaSimpleAuthentication:
                conn.simple_bind_s("", "")
            case ConnectionMode.UnauthenticatedBind:
                conn.simple_bind_s("cn=*", "")
            case ConnectionMode.AuthenticatedBind:
                conn.simple_bind_s(username, password)

            # If an exact match is not confirmed, this last case will be used if provided.
            case _:
                logging.warning("An invalid connection mode was given.")
                return 999
        return conn
    except ldap.TIMEOUT:
        # Negative error code: client-side error. Do not connect again
        logging.warning("Timeout occured")
        return -999
    except ldap.LDAPError as ldap_error:
        # returns positive or negative error code based on ldap lib
        parsed_ex = _parse_ldap_exception(ldap_error)
        ldap_result_code = parsed_ex.get("result", -999)
        ldap_error_type = parsed_ex.get("error_type", -999)
        logging.warning(f"LDAP Error code: {ldap_result_code} {ldap_error_type}")
        return ldap_result_code
    except Exception as e:
        # Positive error code: server-side error
        logging.error(f"Error:ldap_connection:get_connection: {str(e)}")
        return 999


def is_implicit_TLS(uri):
    tls_pattern = r"^ldaps://\S+:\d+$"
    if re.match(tls_pattern, uri):
        return True
    return False


def _parse_ldap_exception(ldap_ex: ldap.LDAPError) -> dict:
    """Parses the exception raised by the ldap library"""
    error_type: str = ldap_ex.__class__.__name__
    error_dict: dict = ldap_ex.args[0]

    return {
        "error_type": error_type,
        "result": error_dict.get("result", ""),
        "desc": error_dict.get("desc", ""),
        "info": error_dict.get("info", ""),
        "msgid": error_dict.get("msgid", ""),
        "errno": error_dict.get("errno", ""),
    }


def set_tls_options(conn: LDAPObject, certificate_validation: bool):
    if certificate_validation:
        conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
    else:
        # Turn off server certificate validation for a broader test scope.
        conn.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
    # We reuse the TLS context to avoid unnecessary traffic while testing.
    conn.set_option(ldap.OPT_X_TLS_NEWCTX, 0)


def get_naming_contexts(conn: LDAPObject) -> list:
    try:
        naming_contexts = conn.get_naming_contexts()
        if isinstance(naming_contexts, list):
            if not naming_contexts:
                return []
            return list(map(lambda x: x.decode("utf-8"), naming_contexts))
        else:
            return [naming_contexts.decode("utf-8")]
    except ldap.TIMEOUT:  # Local timeout
        # Negative error code: client-side error. Do not connect again
        logging.warning("Timeout occured while fetching naming contexts")
        return -999
    except ldap.LDAPError as ldap_error:
        # returns positive or negative error code based on ldap lib
        parsed_ex = _parse_ldap_exception(ldap_error)
        ldap_result_code = parsed_ex.get("result", -999)
        ldap_error_type = parsed_ex.get("error_type", -999)
        logging.warning(
            f"LDAP Error code while fetching naming contexts: {ldap_result_code} {ldap_error_type}"
        )
        return ldap_result_code
    except Exception as e:
        # return f"Error:ldap_connection:get_connection: {str(e)}"
        # Positive error code: server-side error, keep retrying
        logging.error(f"ERROR:ldap_connection:get_naming_contexts: {str(e)}")
        return 999


def search_wrapper(
    crawler: "LDAPCrawler",
    nc: str,
    ldap_scope: str,
    filter_str: str,
    attrs_list: str,
    sizelimit: int = 0,
    timeout: float | None = None,
) -> tuple[list[tuple[str, dict[str, list[str]]]], Exception | None]:
    """
    Wrapper around search_ext to get values even if an error occurs.

    :return: A list of search results (tuple[dn, attr_dict]) and the exception thrown by the ldap library.
    """
    sanity_check_counter = 0
    if timeout is None:
        timeout = float(OPERATION_TIMEOUT)
    while True:
        start_time = time.time()
        results = []
        try:
            msg_id = crawler.conn.search_ext(
                base=nc,
                scope=ldap_scope,
                filterstr=filter_str,
                attrlist=attrs_list,
                sizelimit=sizelimit,
                timeout=timeout,
            )
            timeout_occured = True
            while (total_time := time.time() - start_time) < timeout:
                result_type, result_data = crawler.conn.result(
                    msg_id,
                    all=0,
                    timeout=timeout - total_time,  # Time remaining until timeout
                )
                start_time = time.time()  # Reset on result
                if result_type == ldap.RES_SEARCH_ENTRY:
                    results.extend(result_data)
                elif result_type == ldap.RES_SEARCH_RESULT:
                    timeout_occured = False
                    break
            if timeout_occured:
                crawler.conn.abandon(msg_id)
                raise ldap.TIMEOUT()  # Used to reach error case
            break
        except (ldap.SERVER_DOWN, ldap.TIMEOUT):  # search_ext does not reconnect
            # Sadly, ldap.TIMEOUT occurs multiple times before the connection
            # realizes it got disconnected.
            try:
                crawler.conn.abandon(msg_id)
            except Exception:
                pass
            logging.warning("Lost connection/timeout during search")
            try:
                # The sanity check causes the full reconnect to run.
                # Since we want a sanity check after reconnect anyway,
                # this is the easiest way to achieve both.
                # The longer timeout is to make the connection realize if it got disconnected ...
                if sanity_check_counter >= MAX_SANITY_CHECKS_PER_SEARCH:
                    return results, RetriesExceeded(
                        f"Max sanity checks ({MAX_SANITY_CHECKS_PER_SEARCH}) for search exceeded"
                    )
                time.sleep(60)  # Wait before sending next request in sanity check
                if crawler._sanity_check(nc, timeout=120):
                    logging.info("Got reconnected!")
                    sanity_check_counter += 1
                else:
                    return results, ldap.SERVER_DOWN()
            except Exception as e:
                return results, e
        except Exception as e:
            return results, e
    if not timeout_occured:
        return results, None
    else:
        # This shouldn't happen anymore
        return results, ldap.TIMEOUT()
