"""
This script contains the core functionality of the LDAP Certificate Crawler.
When executed, it initiates a crawl for a given IP and port.
Once the crawling process is completed, the collected certificates, along with additional crawl metadata,
are written to a JSON file.
"""

import json
import concurrent.futures
import logging
import os
import random
import signal
import sys
import time
import traceback
from string import ascii_lowercase, digits, punctuation, whitespace
from typing import Tuple

import ldap
from ldap.filter import escape_filter_chars
from ldap.ldapobject import ReconnectLDAPObject

from utils import ldap_decoder
from utils.ldap_connection import (
    RetriesExceeded,
    ConnectionMode,
    get_connection,
    get_naming_contexts,
    search_wrapper,
)

# List of attributes to be exclusively returned by the LDAP server for each entry. (no other attributes should be included in the LDAP response)
CERTIFICATE_ATTRIBUTES = [
    "userCertificate;binary",
    "userCertificate",
    "userSMIMECertificate;binary",
    "userSMIMECertificate",
    "cACertificate;binary",
    "cACertificate",
    "crossCertificatePair;binary",
    "crossCertificatePair",
]

NON_TLS_PORT = 389
TLS_PORT = 636
TLS_NETWORK_TIMEOUT = 4.5

MAX_RECURSION_DEPTH = (
    65  # maximum recursion depth for LDAP queries that result in a recursion loop
)
MAX_ERROR_COUNT = 10  # maximum number of unknown exceptions allowed during the entire crawl. This value should be greater than MAX_RETRY_COUNT_FOR_REQUEST
MAX_RETRY_COUNT_FOR_REQUEST = 3  # maximum number of retries per search request/letter in case of an unknown exception
MAX_TIMEOUT_COUNT = (
    10  # maximum number of allowed timeouts before triggering a sanity check
)
MAX_TIMELIMIT_EXCEEDED_COUNT = 30  # maximum number of TimeLimitExceeded exceptions before performing a sanity check or aborting the crawl
TIMELIMIT_WAIT = 5  # number of seconds to wait after a TimeLimitExceeded exception before performing a sanity check or issuing the next search query for the next letter
CONNECTION_MAX_RETRIES = (
    60  # maximum number of retries if connection to the server is lost
)
CONNECTION_RETRY_DELAY = 60  # delay between connection retries
RESULTS_WRITE_RETRY_DELAY = 1800  # 30 minutes. Wait this number of seconds before attempting to write the results file again (e.g. if no space is left on disk)
CONNECTION_MODES = [
    ConnectionMode.AnonymousWithoutBind,
    ConnectionMode.AnonymousViaSimpleAuthentication,
    ConnectionMode.UnauthenticatedBind,
]


class LDAPCrawler:
    """
    A class that performs the crawl of an LDAP server.
    """

    def __init__(
        self,
        conn: ReconnectLDAPObject,
        connection_mode,
        target,
        start_tls,
        attribute="cn",
        condition=None,
    ) -> None:
        """
        Initializes the LDAPCrawler instance.

        :param conn: the ReconnectLDAPObject representing the LDAP connection.
        :param connection_mode: connection mode to be used for the LDAP connection.
        :param target: the ldap server uri.
        :param start_tls: boolean indicating whether the connection should use StartTLS.
        :param attribute: the attribute to be used in LDAP queries (default is 'cn').
        :param condition: an additional condition that must be fulfilled for an entry to be matched.
        """
        self.conn: ReconnectLDAPObject = conn
        self.connection_mode = connection_mode
        self.target = target
        self.start_tls = start_tls
        self.attribute = attribute
        self.condition = condition
        self.server_down = False
        self.error_count = (
            0  # counts unhandled exceptions (reset when search result is received)
        )
        self.timelimit_exceeded_counter = 0  # counts TimeLimitExceeded exceptions
        self.max_results_per_request = 0  # estimated size limit
        self.keyboard_interrupt = False
        self.sanity_check_requests = {}  # {nc: (nc, ldap_scope, filter, attrs, sanity_check_flag)}
        self.results_set = set()

        self.alphabet = self.__init__alphabet__()
        sys.excepthook = self.__init__exception__handling__

        # helper
        self.escaped_whitespace_chars = [
            escape_filter_chars(char, escape_mode=1) for char in whitespace
        ]

        # statistics
        self.general_exception_counter = 0  # counts general exceptions
        self.search_request_counter = 0  # counts all sent search requests
        self.general_exception_list = list()  # general exceptions thrown during crawl
        self.completely_crawled = True
        self.not_completely_crawled_reasons = set()
        self.uncrawlable_cns = list()  # cns which are known to not be crawlable
        self.last_crawled_cn = ""

    def __init__alphabet__(self):
        """
        Initializes the alphabet for the queries
        """
        letters = list(ascii_lowercase)
        others = list(
            digits + punctuation + "\t" + '"' + " "
        )  # "!", "\"", "#", "$", "%", "&", "'", "(", ")", "*", "+", ",", "-", ".", "/", ":", ";", "<", "=", ">", "?", "@", "[", "\\", "]", "^", "_", "`", "{", "|", "}", "~"
        random.shuffle(letters)
        random.shuffle(others)
        alphabet = letters + others
        alphabet = [escape_filter_chars(char, escape_mode=1) for char in alphabet]

        return alphabet

    def __init__exception__handling__(self, exc_type, exc_value, exc_traceback):
        """
        Default exception handling routine
        """
        logging.error(str(exc_type))
        logging.error(str(exc_value))
        logging.error(str(exc_traceback))
        sys.exit()

    def __generic__query(self, nc, prefix=""):
        """
        This method starts the crawl for a given naming context.
        Initially, it performs an LDAP search query for a letter in the alphabet, e.g., cn=a*,
        to retrieve entries that begin with that letter.
        If a search query like cn=a* results in an LDAP SizeLimitExceeded response,
        the method is called recursively with the previous cn as a prefix (e.g., cn=aa*)
        to narrow the search string until the query no longer triggers the size limit and returns
        search results (entries with certificates).

        The method returns the number of collected entries that include certificates
        and stores the list of all certificate entries in self.results_set
        """
        result_count = 0
        self.error_count = 0  # reset error count, because calling this methods recursivly means we received a positive response from the server

        for letter in self.alphabet:
            request_retry_count = 0  # retry counter for this search request

            if self.condition:
                filter_str = (
                    f"(&({self.attribute}={prefix + letter}*)({self.condition}))"
                )
            else:
                filter_str = f"{self.attribute}={prefix + letter}*"

            while request_retry_count < MAX_RETRY_COUNT_FOR_REQUEST:
                try:
                    logging.info(filter_str)
                    # This if statement avoids the recursive function call for a sequence of space characters. Sequence of spaces are treated as one space character resulting in an infinite recursive loop.
                    if (
                        prefix != ""
                        and prefix[-3:] in self.escaped_whitespace_chars
                        and letter in self.escaped_whitespace_chars
                    ):
                        logging.error("SEQUENCE OF WHITESPACES")
                        raise ldap.NO_SUCH_OBJECT()
                    if (
                        len(prefix) >= 10 and len(set(prefix)) == 1
                    ):  # if prefix consists of same character like aaaaaaaaaa, then break
                        logging.error("SEQUENCE OF SAME CHARACTERS")
                        raise ldap.NO_SUCH_OBJECT()
                    self.search_request_counter += 1
                    results, error = search_wrapper(
                        self,
                        nc,
                        ldap.SCOPE_SUBTREE,
                        filter_str,
                        CERTIFICATE_ATTRIBUTES,
                    )
                    result_count += len(results)
                    hashable_results = [
                        (dn, ldap_decoder.make_hashable(attributes_dict))
                        for dn, attributes_dict in results
                    ]

                    new_results = set(hashable_results) - self.results_set
                    if len(new_results) > 0:
                        self.results_set.update(new_results)
                        unhashed_results = [
                            (dn, dict(attributes_list))
                            for dn, attributes_list in new_results
                        ]
                        logging.info(unhashed_results)

                    if (
                        len(results) > self.max_results_per_request
                    ):  # estimate size limit
                        self.max_results_per_request = len(results)

                    if error is not None:
                        raise error
                    # reset error count, in the case of a positive response
                    self.error_count = 0
                    self.timelimit_exceeded_counter = 0
                    # refresh naming context/info for sanity check with last successful request config
                    self.__set_nc_tuple_for_nc(
                        nc,
                        (
                            nc,
                            ldap.SCOPE_SUBTREE,
                            filter_str,
                            CERTIFICATE_ATTRIBUTES,
                            True,
                        ),
                    )
                    self.last_crawled_cn = prefix + letter
                    break  # break while loop if request was successful
                except (ldap.SIZELIMIT_EXCEEDED, ldap.ADMINLIMIT_EXCEEDED) as e:
                    logging.warning(e.__class__.__name__)
                    try:
                        temp_result_count = self.__generic__query(nc, prefix + letter)
                        if temp_result_count == 0:
                            if not any(
                                f"{prefix + letter}" in s for s in self.uncrawlable_cns
                            ):
                                self.uncrawlable_cns.append(f"{prefix + letter}")
                                self.not_completely_crawled_reasons.add(
                                    f"uncrawlable cns ({e.__class__.__name__})"
                                )
                                logging.warning(
                                    f"Can not load entries for cn='{prefix + letter}'. Server-side size limit (probably {self.max_results_per_request}) is smaller than number of entries matching for this cn"
                                )
                        else:
                            result_count += temp_result_count

                    except RecursionError:
                        logging.warning(
                            f"Max recursion depth {MAX_RECURSION_DEPTH} exceeded"
                        )
                    break
                except ldap.NO_SUCH_OBJECT:
                    logging.warning("NO SUCH OBJECT")
                    break
                except RetriesExceeded as e:
                    logging.warning(f"RETRIES EXCEEDED: {e}")
                    break
                except ldap.SERVER_DOWN as server_down_error:
                    logging.warning(f"SERVER DOWN {str(server_down_error)}")
                    logging.info(
                        f"Max Connection Retries: {CONNECTION_MAX_RETRIES}, Retry Delay: {CONNECTION_RETRY_DELAY}"
                    )
                    self.server_down = True
                    self.not_completely_crawled_reasons.add("server down")
                    break
                except (ldap.TIMELIMIT_EXCEEDED, ldap.TIMEOUT) as t_ex:
                    logging.warning(
                        f"{t_ex.__class__.__name__}. Waiting {TIMELIMIT_WAIT} seconds"
                    )
                    self.timelimit_exceeded_counter += 1
                    logging.info(
                        f"TIMELIMIT/TIMEOUT COUNTER: {self.timelimit_exceeded_counter}"
                    )
                    request_retry_count += 1
                    time.sleep(TIMELIMIT_WAIT)

                    if self.timelimit_exceeded_counter >= MAX_TIMELIMIT_EXCEEDED_COUNT:
                        logging.warning(
                            f"MAX_TIMELIMIT_EXCEEDED_COUNT reached with cn='{prefix + letter}'. Performing sanity check."
                        )
                        if not self._sanity_check(nc):
                            logging.warning("Sanity check failed.")
                            self.not_completely_crawled_reasons.add(
                                "timelimit exceeded counter reached"
                            )
                            break  # exit here if sanity check fails

                        logging.info("Sanity check was successful. Continuing...")
                        self.timelimit_exceeded_counter = 0

                    if request_retry_count >= MAX_RETRY_COUNT_FOR_REQUEST:
                        logging.warning(
                            f"Max RETRY count {MAX_RETRY_COUNT_FOR_REQUEST} reached for prefix '{prefix + letter}*'"
                        )
                        self.not_completely_crawled_reasons.add(
                            f"max retry count reached for prefix '{prefix + letter}*' during timelimit handling"
                        )
                    else:
                        logging.info(
                            f"Retry number {request_retry_count + 1} for '{prefix + letter}*'"
                        )
                        continue  # Retry this query

                    try:
                        temp_result_count = self.__generic__query(nc, prefix + letter)
                        if temp_result_count == 0:
                            if not any(
                                f"{prefix + letter}" in s for s in self.uncrawlable_cns
                            ):
                                self.uncrawlable_cns.append(f"{prefix + letter}")
                                # self.completely_crawled = False
                                self.not_completely_crawled_reasons.add(
                                    "uncrawlable cns"
                                )
                                logging.warning(
                                    f"Can not load entries for cn='{prefix + letter}'. Server-side size limit (probably {self.max_results_per_request}) is smaller than number of entries matching for this cn"
                                )
                        else:
                            result_count += temp_result_count

                    except RecursionError:
                        logging.warning(
                            f"Max recursion depth {MAX_RECURSION_DEPTH} exceeded"
                        )
                    break
                except KeyboardInterrupt:
                    logging.info("KEYBOARD INTERRUPT. Exiting...")
                    self.keyboard_interrupt = True
                    self.not_completely_crawled_reasons.add("keyboard interrupt")
                    break
                except Exception as ex:
                    logging.exception("EXCEPTION occurred while sending search request")
                    self.error_count += 1
                    self.general_exception_counter += 1
                    request_retry_count += 1
                    self.general_exception_list.append(
                        f"{ex.__class__.__name__}: {str(ex)}"
                    )

                    if request_retry_count >= MAX_RETRY_COUNT_FOR_REQUEST:
                        logging.warning(
                            f"Max RETRY count {MAX_RETRY_COUNT_FOR_REQUEST} reached for prefix '{prefix + letter}*'"
                        )
                        self.completely_crawled = False
                        self.not_completely_crawled_reasons.add(
                            f"max retry count reached for prefix '{prefix + letter}*'"
                        )
                        break

                    if self.error_count >= MAX_ERROR_COUNT:
                        logging.warning(
                            f"Max ERROR count {MAX_ERROR_COUNT} reached for this server"
                        )
                        self.not_completely_crawled_reasons.add(
                            "max error count reached"
                        )
                        break

                    logging.info(
                        f"Retry number {request_retry_count + 1} for '{prefix + letter}*'"
                    )
                    logging.info(f"Sleeping {CONNECTION_RETRY_DELAY} seconds")
                    time.sleep(CONNECTION_RETRY_DELAY)  # wait before retrying

            if (
                self.error_count >= MAX_ERROR_COUNT
                or self.timelimit_exceeded_counter >= MAX_TIMELIMIT_EXCEEDED_COUNT
                or self.server_down
                or self.keyboard_interrupt
            ):  # Check if crawl should end
                self.completely_crawled = False
                return result_count
        return result_count

    def _sanity_check(self, nc, timeout=60):
        """
        This method performs a sanity check by verifying whether the server still returns entries
        it previously delivered, to ensure that the crawl can safely continue
        """

        nc_tuple = self.__get_nc_tuple_for_nc(nc)
        if nc_tuple is None:
            logging.warning(
                f"Sanity check failed. Could not find nc tuple for nc '{nc}'. Sanity check is bad."
            )
            return False
        nc, ldap_scope, filter_str, attrs_list, sanity_check_flag = nc_tuple

        if not sanity_check_flag:
            logging.warning(
                f"Sanity check failed. This tuple {nc_tuple} can not be use for sanity check. Sanity check is bad."
            )
            return False

        try:
            logging.info(
                f"Doing sanity check for this config: nc: {nc}, filter_str: {filter_str}"
            )
            results = self.conn.search_ext_s(
                base=nc,
                scope=ldap_scope,
                filterstr=filter_str,
                attrlist=attrs_list,
                sizelimit=1,
                timeout=timeout,
            )
            logging.info(
                "Received positive response while performing sanity check. Sanity check is good."
            )
            logging.info(f"Results: {results}")
            return True
        except ldap.SIZELIMIT_EXCEEDED:
            logging.info(
                "SIZELIMIT EXCEEDED while performing sanity check. Sanity check is good."
            )
            return True
        except ldap.ADMINLIMIT_EXCEEDED:
            logging.info(
                "ADMINLIMIT EXCEEDED while performing sanity check. Sanity check is good."
            )
            return True
        except ldap.NO_SUCH_OBJECT:
            logging.info(
                "NO SUCH OBJECT while performing sanity check. Sanity check is good."
            )
            return True
        except ldap.SERVER_DOWN:
            logging.info(
                "SERVER DOWN while performing sanity check. Sanity check is bad."
            )
            return False
        except ldap.TIMEOUT as timeout_ex:
            logging.info(
                f"TIMEOUT Exception while performing sanity check. Sanity check is bad. {str(timeout_ex)}"
            )
            return False
        except ldap.TIMELIMIT_EXCEEDED as timelimit_ex:
            logging.info(
                f"TIMELIMIT EXCEEDED while performing sanity check. Sanity check is bad. {str(timelimit_ex)}"
            )
            return False
        except Exception as ex:
            logging.error(
                f"Error while performing sanity check. Sanity check is bad. {ex.__class__.__name__}: {traceback.format_exc()}"
            )
            return False

    def get_general_exception_count(self):
        return self.general_exception_counter

    def get_search_request_count(self):
        return self.search_request_counter

    def get_general_exception_list(self):
        return self.general_exception_list

    def get_completely_crawled_flag(self):
        return self.completely_crawled

    def get_uncrawlable_cns(self):
        return self.uncrawlable_cns

    def get_not_completely_crawled_reasons(self):
        return list(self.not_completely_crawled_reasons)

    def get_alphabet(self):
        return self.alphabet

    def get_last_crawled_cn(self):
        return self.last_crawled_cn

    def get_estimated_size_limit(self):
        return self.max_results_per_request

    def __init_sanity_check_requests(self, naming_contexts):
        for nc_tuple in naming_contexts:
            nc, _, _, _, _ = nc_tuple
            self.sanity_check_requests[nc] = nc_tuple

    def __get_nc_tuple_for_nc(self, nc):
        return self.sanity_check_requests.get(nc, None)

    def __set_nc_tuple_for_nc(self, nc, nc_tuple):
        self.sanity_check_requests[nc] = nc_tuple

    def crawl(self, naming_contexts: list) -> Tuple[dict, list]:
        """
        This method calls __generic__query for each naming context and handles the transition to the next one
        if a KeyboardInterrupt is raised. The crawl results are aggregated, decoded, and returned.
        """

        sys.setrecursionlimit(MAX_RECURSION_DEPTH)

        logging.info(f"Alphabet: {self.alphabet}")
        self.__init_sanity_check_requests(naming_contexts)

        for nc, _, _, _, _ in naming_contexts:
            logging.info(f"Started crawl for naming context '{nc}'")
            try:
                non_unique_result_count = self.__generic__query(nc)
                logging.info(f"Non-unique result count: {non_unique_result_count}")
            except RecursionError:
                logging.exception(
                    f"ERROR:CRAWLER:CRAWLING:Max recursion depth {MAX_RECURSION_DEPTH} exceeded. Continuing with next naming context..."
                )
                continue
            except Exception:
                # Some naming contexts might have insufficient access.
                logging.exception(
                    f"ERROR:CRAWLER:CRAWLING:An error occured while crawling naming context '{nc}' Continuing with next naming context..."
                )
                continue

            # if keyboard interrupt than start crawl for next nc
            if self.keyboard_interrupt:
                self.keyboard_interrupt = False

                executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
                logging.info("Establishing new connection for new naming context")
                future = executor.submit(
                    get_connection,
                    self.connection_mode,
                    self.target,
                    start_TLS=self.start_tls,
                    retry_max=CONNECTION_MAX_RETRIES,
                    retry_delay=CONNECTION_RETRY_DELAY,
                )
                try:
                    conn = future.result(timeout=TLS_NETWORK_TIMEOUT)
                    executor.shutdown(wait=True)
                except concurrent.futures.TimeoutError:
                    logging.warning("Connection attempt timed out")
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                except Exception as e:
                    logging.error(
                        f"An error occurred while waiting for connection: {e}"
                    )
                    executor.shutdown(wait=False, cancel_futures=True)
                    break

                if not isinstance(
                    conn, ReconnectLDAPObject
                ):  # in any case (server or client-side error) try again
                    logging.warning(
                        f"ERROR:CRAWLER:CONNECTION:{self.connection_mode}:{self.target}:{conn}"
                    )
                    break
                self.conn = conn

        unhashed_results = [
            (dn, ldap_decoder.make_unhashable(attributes_list))
            for dn, attributes_list in self.results_set
        ]
        return ldap_decoder.decode(
            unhashed_results, save=False, attributes_to_decode=CERTIFICATE_ATTRIBUTES
        )


def probe(conn: ReconnectLDAPObject, nc_list: list, filter_str: str) -> list[str]:
    """Ethical Consideration: Tests each naming context for certificates before starting the crawling process"""

    ldap_scope = ldap.SCOPE_SUBTREE
    filter_str = f"(|{filter_str})"
    attrs_to_be_returned = ["cn"]

    ncs_with_certs = []  # format: (nc, filter_str)

    for nc in nc_list:
        try:
            results = conn.search_ext_s(
                nc,
                ldap_scope,
                filter_str,
                attrs_to_be_returned,
                timeout=120,  # longer timeout for probing naming context
                sizelimit=1,  # limit maximum number of resulting entries to one
            )
        except ldap.SIZELIMIT_EXCEEDED:
            logging.info(f"SIZELIMIT EXCEEDED. Naming context '{nc}' has certificates.")
            ncs_with_certs.append(
                (
                    nc,
                    ldap_scope,
                    filter_str,
                    attrs_to_be_returned,
                    True,
                )
            )  # last flag indicates if this nc can be used for sanity check
            continue
        except ldap.ADMINLIMIT_EXCEEDED:
            logging.info(
                f"ADMINLIMIT EXCEEDED. Naming context '{nc}' has certificates."
            )
            ncs_with_certs.append(
                (
                    nc,
                    ldap_scope,
                    filter_str,
                    attrs_to_be_returned,
                    True,
                )
            )
            continue
        except ldap.NO_SUCH_OBJECT:
            logging.info(f"NO SUCH OBJECT. No certificates for naming context '{nc}'")
            continue
        except ldap.TIMEOUT as timeout_ex:
            logging.info(
                f"TIMEOUT Exception occured while probing naming context '{nc}'. Naming context could have certificates. Error: {str(timeout_ex)}"
            )
            ncs_with_certs.append(
                (
                    nc,
                    ldap_scope,
                    filter_str,
                    attrs_to_be_returned,
                    False,
                )  # Can not be used for sanity check
            )
            continue
        except ldap.TIMELIMIT_EXCEEDED as timelimit_ex:
            logging.info(
                f"TIMELIMIT EXCEEDED occured while probing naming context '{nc}'. Naming context could have certificates. Error: {str(timelimit_ex)}"
            )
            ncs_with_certs.append(
                (
                    nc,
                    ldap_scope,
                    filter_str,
                    attrs_to_be_returned,
                    False,
                )  # Can not be used for sanity check
            )
            continue
        except ldap.SERVER_DOWN:
            logging.info(
                f"SERVER DOWN: Can not contact LDAP server while probing nc '{nc}'"
            )
            continue
        except Exception as ex:
            logging.error(
                f"Error occured while probing with naming context '{nc}'. {ex.__class__.__name__}: {str(ex)}"
            )
            continue

        if len(results) > 0:
            logging.info(
                f"Received results. Naming context '{nc}' probably has certificates."
            )
            ncs_with_certs.append(
                (
                    nc,
                    ldap_scope,
                    filter_str,
                    attrs_to_be_returned,
                    True,
                )
            )
            continue

    random.shuffle(ncs_with_certs)
    return ncs_with_certs


def setup_crawl(ip, port):
    """
    Sets up the crawl by probing and attempting connections to the given IP and port
    using different LDAP connection modes. Starts the crawling process if the server
    responds as an LDAP server.
    """

    if port == TLS_PORT:
        target = f"ldaps://{ip}:{TLS_PORT}"
        start_tls = False
    else:
        target = f"ldap://{ip}:{port}"
        start_tls = True

    logging.info(f"Setting up crawl for {ip}:{port}")
    connected = False
    try:
        # Ethical Consideration: Collecting certificates is performed via TLS if possible.
        for cm in CONNECTION_MODES:
            logging.debug(
                f"Attempting to connect via LDAP connection mode {cm.name}, starttls={start_tls}"
            )
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            future = executor.submit(
                get_connection,
                cm,
                target,
                start_TLS=start_tls,
                retry_max=CONNECTION_MAX_RETRIES,
                retry_delay=CONNECTION_RETRY_DELAY,
            )
            try:
                conn = future.result(timeout=TLS_NETWORK_TIMEOUT)
                executor.shutdown(wait=True)
            except concurrent.futures.TimeoutError:
                logging.warning("Connection attempt timed out")
                connected = False
                executor.shutdown(wait=False, cancel_futures=True)
                break
            except Exception as e:
                logging.error(f"An error occurred while waiting for connection: {e}")
                connected = False
                executor.shutdown(wait=False, cancel_futures=True)
                break

            if isinstance(conn, int):
                if conn < 0:  # client-side error
                    connected = False
                    break
                elif (
                    conn > 0 and port == TLS_PORT
                ):  # server-side error. only implicit TLS case
                    connected = False
                    continue  # Try next connection mode

            if (
                not isinstance(conn, ReconnectLDAPObject) and start_tls
            ):  # client-side error. StartTLS case
                start_tls = False  # try without starttls
                logging.debug(f"Trying connection mode {cm.name}, starttls={start_tls}")

                executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
                future = executor.submit(
                    get_connection,
                    cm,
                    target,
                    start_TLS=start_tls,
                    retry_max=CONNECTION_MAX_RETRIES,
                    retry_delay=CONNECTION_RETRY_DELAY,
                )
                try:
                    conn = future.result(timeout=TLS_NETWORK_TIMEOUT)
                    executor.shutdown(wait=True)
                except concurrent.futures.TimeoutError:
                    logging.warning("Connection attempt timed out")
                    start_tls = True
                    executor.shutdown(wait=False, cancel_futures=True)
                    continue
                except Exception as e:
                    logging.error(
                        f"An error occurred while waiting for connection: {e}"
                    )
                    start_tls = True
                    executor.shutdown(wait=False, cancel_futures=True)
                    continue

                if not isinstance(
                    conn, ReconnectLDAPObject
                ):  # in any case (server or client-side error) try again
                    logging.warning(f"ERROR:CRAWLER:CONNECTION:{cm}:{ip}_{port}:{conn}")
                    start_tls = True
                    continue
            logging.info(f"Connection details: {target} {cm.name} starttls={start_tls}")

            executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            future = executor.submit(get_naming_contexts, conn)
            try:
                nc_list = future.result(timeout=TLS_NETWORK_TIMEOUT)
                executor.shutdown(wait=True)
            except concurrent.futures.TimeoutError:
                logging.warning("Getting naming contexts timed out")
                connected = False
                executor.shutdown(wait=False, cancel_futures=True)
                break
            except Exception as e:
                logging.error(
                    f"An error occurred while waiting for naming contexts: {e}"
                )
                connected = False
                executor.shutdown(wait=False, cancel_futures=True)
                break

            if isinstance(nc_list, int):
                if nc_list < 0:  # client-side error
                    connected = False
                    break
                if nc_list > 0:
                    if port != TLS_PORT:  # set starttls=true in non implicit TLS case
                        start_tls = True
                    continue

            if isinstance(nc_list, list):
                if len(nc_list) == 0:  # could be error or empty nc. try again
                    if port != TLS_PORT:  # set starttls=true in non implicit TLS case
                        start_tls = True
                    continue

            logging.info(f"Fetched naming contexts: {nc_list}")
            connected = True
            break

        if not connected:
            logging.error(
                f"ERROR:CRAWLER:CONNECTION:{ip}_{port}:Could not establish connection with different connection modes"
            )
            return -1

    except Exception as error:
        logging.error(f"ERROR:CRAWLER:CONNECTION:{ip}_{port}:{error}")
        return -1

    filter_attr = ""
    for attr in CERTIFICATE_ATTRIBUTES:
        filter_attr += f"({attr}=*)"

    probed_ncs = probe(conn, nc_list, filter_attr)
    if len(probed_ncs) == 0:
        logging.info("Server has no certificates")
        return 2

    start = time.time()
    try:
        generic_crawler = LDAPCrawler(
            conn=conn,
            connection_mode=cm,
            target=target,
            start_tls=start_tls,
            attribute="cn",
            condition=f"|{filter_attr}",
        )
        results = generic_crawler.crawl(probed_ncs)
        ex_counter = generic_crawler.get_general_exception_count()
        request_counter = generic_crawler.get_search_request_count()
        ex_list = generic_crawler.get_general_exception_list()
        completely_crawled = generic_crawler.get_completely_crawled_flag()
        uncrawlable_cns = generic_crawler.get_uncrawlable_cns()
        not_crawlable_reasons = generic_crawler.get_not_completely_crawled_reasons()
        alphabet = generic_crawler.get_alphabet()
        last_crawled_cn = generic_crawler.get_last_crawled_cn()
        estimated_size_limit = generic_crawler.get_estimated_size_limit()
        logging.info(f"Finished crawling: {ip}")
        logging.info(f"Alphabet order: {alphabet}")
        logging.info(f"Estimated size limit: {estimated_size_limit}")
        logging.info(f"Last crawled letter: {last_crawled_cn}")
        logging.info(f"Number of search requests sent: {request_counter:,}")
        logging.info(
            f"Number of general exceptions occured while sending search requests: {ex_counter:,}"
        )
        if ex_list:
            logging.info(f"The following exceptions occured: {' | '.join(ex_list)}")
        if completely_crawled:
            logging.info("This server was completely crawled")
        else:
            logging.warning(
                f"This server WAS NOT completely crawled. Reasons: {not_crawlable_reasons}"
            )
        logging.info(f"uncrawlable cns: {uncrawlable_cns}")
    except Exception as error:
        logging.error(f"ERROR:CRAWLER:CRAWLING:{ip}:{error}")
        logging.error(traceback.print_exc())

    end = time.time()
    crawl_duration = end - start
    # Convert to hours, minutes, and seconds
    hours = int(crawl_duration // 3600)
    minutes = int((crawl_duration % 3600) // 60)
    seconds = int(crawl_duration % 60)
    milliseconds = int((crawl_duration * 1000) % 1000)
    # Print the duration in a human readable format
    start_string = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(start))
    end_string = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(end))
    logging.info(
        f"Crawl started at {start_string} and ended at {end_string} -> duration: {hours}h {minutes}m {seconds}s {milliseconds}ms"
    )

    filename = f"{ip}_{port}"
    result_dir = os.path.join(sys.argv[2], "results")

    while True:
        try:
            if not os.path.isdir(result_dir):
                os.makedirs(result_dir)

            result_file_path = os.path.join(result_dir, f"{filename}.json")
            with open(result_file_path, "w+") as file:
                json.dump(
                    {
                        "start": start,
                        "start_string": start_string,
                        "end": end,
                        "end_string": end_string,
                        "crawl_duration": crawl_duration,
                        "crawl_duration_string": f"{hours}h {minutes}m {seconds}s {milliseconds}ms",
                        "connection_mode": cm.name,
                        "start_tls": start_tls,
                        "ncs": nc_list,
                        "crawled_ncs": probed_ncs,
                        "alphabet": alphabet,
                        "estimated_size_limit": estimated_size_limit,
                        "last_crawled_cn": last_crawled_cn,
                        "result": results,
                        "completely_crawled": completely_crawled,
                        "search_requests": request_counter,
                        "exceptions_count": ex_counter,
                        "exceptions": ex_list,
                        "uncrawlable_cns": uncrawlable_cns,
                        "not_crawlable_reasons": not_crawlable_reasons,
                    },
                    file,
                    indent=4,
                )

            logging.info(f"Successfully written results to {result_file_path}")
            break
        except OSError:
            logging.exception(
                f"OSERROR occurred while writing results to file. Retrying in {RESULTS_WRITE_RETRY_DELAY} seconds"
            )
            time.sleep(RESULTS_WRITE_RETRY_DELAY)
        except Exception:
            logging.exception(
                f"EXCEPTION occurred while writing results to file. Retrying in {RESULTS_WRITE_RETRY_DELAY} seconds"
            )
            time.sleep(RESULTS_WRITE_RETRY_DELAY)

    return 1


def main():
    """
    Main function. Initiates the crawl setup based on whether a TLS or non-TLS port is provided.
    Ethical consideration: prefers the TLS port if given.
    Falls back to port 389 if a connection to the TLS port cannot be established
    """
    ip_ports = sys.argv[1]
    ip, ports = parse_ip_port(ip_ports)

    if TLS_PORT in ports:
        logging.info("Connecting with impilict TLS")
        r_code = setup_crawl(ip, TLS_PORT)

        if r_code < 0 and NON_TLS_PORT in ports:
            logging.info("TLS failed. Connecting without implicit TLS")
            setup_crawl(ip, NON_TLS_PORT)

    elif NON_TLS_PORT in ports:
        logging.info("Connecting without implicit TLS")
        setup_crawl(ip, NON_TLS_PORT)

    logging.info("Process finished!")
    # Explicitly kill the process because blocking threads from TLS connection attempts are terminated cleanly
    os.kill(os.getpid(), signal.SIGTERM)


def parse_ip_port(ip_ports: str) -> Tuple[str, list[str]]:
    """Parse IP address and ports from the input arguments."""
    ip_ports_splitted = ip_ports.split(",")
    ip = ip_ports_splitted[0]
    ports = [int(p) for p in ip_ports_splitted[1:]]

    return ip, ports


def set_up_logging():
    """Set up logging"""
    ip_ports = sys.argv[1]
    ip, ports = parse_ip_port(ip_ports)
    port = "_".join([str(p) for p in ports])

    logdirbase = os.path.join(sys.argv[2], "crawler_logs")
    logname = f"{ip}_{port}_crawl.log"
    if not os.path.isdir(logdirbase):
        os.makedirs(logdirbase)
    logpath = os.path.join(logdirbase, logname)
    handlers: list[logging.Handler] = [
        logging.FileHandler(filename=logpath, mode="w"),
        logging.StreamHandler(sys.stdout),
    ]
    logging_level = logging.DEBUG

    logging.basicConfig(
        format="%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s",
        datefmt="%Y/%m/%d %H:%M:%S",
        level=logging_level,
        handlers=handlers,
    )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        logging.error(
            f"Usage: {sys.argv[0]} <ip>,<port>[,<port>] <crawling results output directory>"
        )
        exit()
    set_up_logging()
    main()
