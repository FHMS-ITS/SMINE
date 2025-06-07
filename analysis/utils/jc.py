#################################################################################
## Following part: adapted jc-parse functionality that is more relaxed with parsing errors. Function for parsing: jc_parse_relaxed()
import threading
from collections import OrderedDict
from collections.abc import Callable

thread_local = threading.local()

import jc.parsers.asn1crypto.core
from jc.parsers.asn1crypto._errors import unwrap
from jc.parsers.asn1crypto._types import type_name
from jc.parsers.asn1crypto.core import (
    _UNIVERSAL_SPECS,
    CLASS_NUM_TO_NAME_MAP,
    METHOD_NUM_TO_NAME_MAP,
    VOID,
    Any,
    Asn1Value,
    Choice,
    Constructable,
    _tag_type_to_explicit_implicit,
)
from jc.parsers.asn1crypto.parser import _parse


def relaxed_build(
    class_,
    method,
    tag,
    header,
    contents,
    trailer,
    spec=None,
    spec_params=None,
    nested_spec=None,
):
    """
    "Patched" version of the build function that raises fewer exceptions.
    """
    if spec_params is not None:
        _tag_type_to_explicit_implicit(spec_params)

    if header is None:
        return VOID

    header_set = False

    if spec is not None:
        no_explicit = spec_params and "no_explicit" in spec_params
        if not no_explicit and (
            spec.explicit or (spec_params and "explicit" in spec_params)
        ):
            if spec_params:
                value = spec(**spec_params)
            else:
                value = spec()
            original_explicit = value.explicit
            explicit_info = reversed(original_explicit)
            parsed_class = class_
            parsed_method = method
            parsed_tag = tag
            to_parse = contents
            explicit_header = header
            explicit_trailer = trailer or b""
            for expected_class, expected_tag in explicit_info:
                if parsed_class != expected_class:
                    ignore_error(
                        unwrap(
                            """
                        Error parsing %s - explicitly-tagged class should have been
                        %s, but %s was found
                        """,
                            type_name(value),
                            CLASS_NUM_TO_NAME_MAP.get(expected_class),
                            CLASS_NUM_TO_NAME_MAP.get(parsed_class, parsed_class),
                        )
                    )
                if parsed_method != 1:
                    ignore_error(
                        unwrap(
                            """
                        Error parsing %s - explicitly-tagged method should have
                        been %s, but %s was found
                        """,
                            type_name(value),
                            METHOD_NUM_TO_NAME_MAP.get(1),
                            METHOD_NUM_TO_NAME_MAP.get(parsed_method, parsed_method),
                        )
                    )
                if parsed_tag != expected_tag:
                    ignore_error(
                        unwrap(
                            """
                        Error parsing %s - explicitly-tagged tag should have been
                        %s, but %s was found
                        """,
                            type_name(value),
                            expected_tag,
                            parsed_tag,
                        )
                    )
                info, _ = _parse(to_parse, len(to_parse))
                (
                    parsed_class,
                    parsed_method,
                    parsed_tag,
                    parsed_header,
                    to_parse,
                    parsed_trailer,
                ) = info

                if not isinstance(value, Choice):
                    explicit_header += parsed_header
                    explicit_trailer = parsed_trailer + explicit_trailer

            value = relaxed_build(*info, spec=spec, spec_params={"no_explicit": True})
            value._header = explicit_header
            value._trailer = explicit_trailer
            value.explicit = original_explicit
            header_set = True
        else:
            if spec_params:
                value = spec(contents=contents, **spec_params)
            else:
                value = spec(contents=contents)

            if spec is Any:
                pass

            elif isinstance(value, Choice):
                value.validate(class_, tag, contents)
                try:
                    value.contents = header + value.contents
                    header = b""
                    value.parse()
                except (ValueError, TypeError) as e:
                    args = e.args[1:]
                    e.args = (
                        e.args[0] + "\n    while parsing %s" % type_name(value),
                    ) + args
                    raise e

            else:
                if class_ != value.class_:
                    ignore_error(
                        unwrap(
                            """
                        Error parsing %s - class should have been %s, but %s was
                        found
                        """,
                            type_name(value),
                            CLASS_NUM_TO_NAME_MAP.get(value.class_),
                            CLASS_NUM_TO_NAME_MAP.get(class_, class_),
                        )
                    )
                if method != value.method:
                    ber_indef = (
                        method == 1 and value.method == 0 and trailer == b"\x00\x00"
                    )
                    if not ber_indef or not isinstance(value, Constructable):
                        ignore_error(
                            unwrap(
                                """
                            Error parsing %s - method should have been %s, but %s was found
                            """,
                                type_name(value),
                                METHOD_NUM_TO_NAME_MAP.get(value.method),
                                METHOD_NUM_TO_NAME_MAP.get(method, method),
                            )
                        )

                    value.method = method
                    value._indefinite = True
                if tag != value.tag:
                    if isinstance(value._bad_tag, tuple):
                        is_bad_tag = tag in value._bad_tag
                    else:
                        is_bad_tag = tag == value._bad_tag
                    if not is_bad_tag:
                        ignore_error(
                            unwrap(
                                """
                            Error parsing %s - tag should have been %s, but %s was found
                            """,
                                type_name(value),
                                value.tag,
                                tag,
                            )
                        )

    elif spec_params and "explicit" in spec_params:
        original_value = Asn1Value(contents=contents, **spec_params)
        original_explicit = original_value.explicit

        to_parse = contents
        explicit_header = header
        explicit_trailer = trailer or b""
        for expected_class, expected_tag in reversed(original_explicit):
            info, _ = _parse(to_parse, len(to_parse))
            _, _, _, parsed_header, to_parse, parsed_trailer = info
            explicit_header += parsed_header
            explicit_trailer = parsed_trailer + explicit_trailer
        value = relaxed_build(*info, spec=spec, spec_params={"no_explicit": True})
        value._header = header + value._header
        value._trailer += trailer or b""
        value.explicit = original_explicit
        header_set = True

    else:
        if tag not in _UNIVERSAL_SPECS:
            raise ValueError(
                unwrap(
                    """
                Unknown element - %s class, %s method, tag %s
                """,
                    CLASS_NUM_TO_NAME_MAP.get(class_),
                    METHOD_NUM_TO_NAME_MAP.get(method),
                    tag,
                )
            )

        spec = _UNIVERSAL_SPECS[tag]

        value = spec(contents=contents, class_=class_)
        ber_indef = method == 1 and value.method == 0 and trailer == b"\x00\x00"
        if ber_indef and isinstance(value, Constructable):
            value._indefinite = True
        value.method = method

    if not header_set:
        value._header = header
        value._trailer = trailer or b""

    value._native = None

    if nested_spec:
        try:
            value.parse(nested_spec)
        except (ValueError, TypeError) as e:
            args = e.args[1:]
            e.args = (e.args[0] + "\n    while parsing %s" % type_name(value),) + args
            raise e

    return value


jc.parsers.asn1crypto.core._build = relaxed_build


class RelaxedSequence(jc.parsers.asn1crypto.core.Sequence):
    """A patched version of the Sequence class that doesn't raise exceptions if children can't be parsed."""

    @property
    def native(self):
        if self.contents is None:
            return None

        if self._native is None:
            if self.children is None:
                self._parse_children(recurse=True)
            try:
                self._native = OrderedDict()
                for index, child in enumerate(self.children):
                    if child.__class__ == tuple:
                        child = relaxed_build(*child)
                        self.children[index] = child
                    try:
                        name = self._fields[index][0]
                    except IndexError:
                        name = str(index)
                    try:
                        self._native[name] = child.native
                    except Exception as ex:
                        ignore_error(repr(ex))
                        self._native[name] = "__JC_PARSER_ERROR__"
            except (ValueError, TypeError) as e:
                self._native = None
                args = e.args[1:]
                e.args = (
                    e.args[0] + "\n    while parsing %s" % type_name(self),
                ) + args
                raise e
        return self._native


jc.parsers.asn1crypto.core.Sequence = RelaxedSequence  # type: ignore[misc]  # assigning to type

import logging

logger = logging.getLogger(__name__)


def default_error_callback(msg: str) -> None:
    """
    Default error callback function that logs the exception.
    """
    # logger.warning(msg)


thread_local.error_callback = default_error_callback


def ignore_error(msg) -> None:
    """
    Handle non-raised errors that occur during parsing.
    """
    thread_local.error_callback(msg)


def jc_parse_relaxed(
    *args, error_callback_fct: Callable = default_error_callback, **kwargs
):
    """
    Parse function that doesn't raise exceptions if children can't be parsed.
    """
    thread_local.error_callback = error_callback_fct
    try:
        return jc.parse(*args, **kwargs)
    finally:
        thread_local.error_callback = default_error_callback


#################################################################################

# This part: ECC Key analysis
