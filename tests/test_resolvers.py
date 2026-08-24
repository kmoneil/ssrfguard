"""The resolver with a deadline, and the parser that is the price of having one.

Reading DNS off the wire means reading bytes an attacker chose, which is a thing this package
does nowhere else. So the balance of this file is deliberate: the socket tests prove the
deadline, the retry and the fallback, and everything before them is the parser, which is where a
bug would live.

**What a parser bug here cannot do is grant a permit.** `ssrfguard.resolve` validates every
address this returns before anything connects to it, so a mis-parse produces a wrong address that
the policy then refuses or allows on its own merits. What it *can* do is never return, and that
is the failure this file is mostly about: `test_no_message_can_make_name_decoding_hang` is the
one that matters most, because the bug it looks for is the reason `_MAX_JUMPS` exists.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
import threading
import time
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ssrfguard import BlockedAddressError, Policy, resolve
from ssrfguard.resolvers import (
    Record,
    UdpResolver,
    _address_from,
    _decode_name,
    _encode_name,
    _family_of,
    _MalformedError,
    _parse,
    _recv_exactly,
    _ServerFailureError,
    _time_left,
    _WrongQuestionError,
    nameservers_from_resolv_conf,
)

from .scripted_dns import (
    CLASS_IN,
    HEADER,
    RCODE_NXDOMAIN,
    RCODE_SERVFAIL,
    TYPE_A,
    TYPE_AAAA,
    TYPE_CNAME,
    ScriptedDNS,
    answer,
    encode_name,
    question_of,
    raw_reply,
    txid_of,
)

#: The name every test asks about, in a reserved TLD so a leaked query cannot resolve.
NAME = "target.test"

#: The id every hand-built query carries.
TXID = 0x1234


def query_bytes(name: str = NAME, qtype: int = TYPE_A, txid: int = TXID) -> bytes:
    """One query, as `UdpResolver` would send it."""
    return (
        HEADER.pack(txid, 0x0100, 1, 0, 0, 0)
        + encode_name(name)
        + struct.pack("!HH", qtype, CLASS_IN)
    )


# ---------------------------------------------------------------------------
# Encoding a name. A malformed query is a packet that gets an answer nobody can read, so these
# are refused before the socket rather than sent and puzzled over.
# ---------------------------------------------------------------------------


def test_a_name_encodes_as_length_prefixed_labels() -> None:
    assert _encode_name("a.bc") == b"\x01a\x02bc\x00"


def test_only_the_trailing_dot_is_stripped_and_not_the_letters_near_it() -> None:
    """A label may end in any letter, including the ones a careless strip set would take."""
    assert _encode_name("hostX.") == b"\x05hostX\x00"


def test_the_absolute_form_encodes_as_the_same_name() -> None:
    """urllib3 preserves a trailing dot, so a name that arrives with one is not a new name."""
    assert _encode_name("example.test.") == _encode_name("example.test")


@pytest.mark.parametrize(
    ("name", "why"),
    [
        ("", "cannot resolve the root or an empty name"),
        (".", "cannot resolve the root or an empty name"),
        ("a..b", "has an empty label"),
        ("x" * 64 + ".test", "has a label longer than 63 bytes"),
        (".".join(["x" * 63] * 5), "is longer than 255 bytes on the wire"),
        ("café.test", "is not an ASCII name"),
    ],
)
def test_a_name_that_cannot_go_on_the_wire_is_refused(name: str, why: str) -> None:
    with pytest.raises(ValueError, match=why):
        _encode_name(name)


def test_a_name_that_cannot_be_encoded_fails_the_lookup_as_a_resolver_failure() -> None:
    """The caller asked to resolve a name, so the answer is `gaierror`, not `ValueError`."""
    resolver = UdpResolver(nameservers=("127.0.0.1",), timeout=1.0)
    with pytest.raises(socket.gaierror, match="has an empty label"):
        resolver("a..b")


# ---------------------------------------------------------------------------
# Decoding a name. Every one of these is a message a correct server never sends.
# ---------------------------------------------------------------------------


def test_a_name_decodes_and_reports_where_it_ended() -> None:
    message = encode_name("example.test")
    assert _decode_name(message, 0) == ("example.test", len(message))


def test_a_compression_pointer_is_followed_and_the_offset_is_the_pointers_own() -> None:
    """The offset returned is where the name ended *here*, not where the pointer led."""
    message = encode_name("example.test") + b"\xc0\x00"
    name, offset = _decode_name(message, len(message) - 2)
    assert (name, offset) == ("example.test", len(message))


def test_a_pointer_that_points_at_itself_raises_rather_than_looping() -> None:
    """The oldest denial of service in DNS. `_MAX_JUMPS` is what makes this terminate."""
    with pytest.raises(_MalformedError, match="more than 64 compression pointers"):
        _decode_name(b"\xc0\x00", 0)


def test_two_pointers_that_point_at_each_other_raise_rather_than_looping() -> None:
    with pytest.raises(_MalformedError, match="more than 64 compression pointers"):
        _decode_name(b"\xc0\x02\xc0\x00", 0)


def test_a_pointer_cycle_that_consumes_labels_still_terminates() -> None:
    """A cycle that decodes a label per lap defeats a jump counter alone, and is caught by
    the byte ceiling instead. Both bounds are load-bearing; neither is sufficient."""
    message = b"\x01a\xc0\x00"
    with pytest.raises(_MalformedError, match=r"longer than 255 bytes|compression pointers"):
        _decode_name(message, 0)


@pytest.mark.parametrize(
    ("message", "offset", "why"),
    [
        (b"\xc0\xff", 0, "points outside the message"),
        (b"\xc0", 0, "runs past the end of the message"),
        (b"\x40\x00", 0, "reserved label length"),
        (b"\x80\x00", 0, "reserved label length"),
        (b"\x05ab", 0, "a label runs past the end"),
        (b"\x02", 0, "a label runs past the end"),
        (b"\x01a", 0, "a name runs past the end"),
        (b"\x02\xff\xfe\x00", 0, "a label is not ASCII"),
        (b"", 0, "a name runs past the end"),
    ],
)
def test_a_name_that_cannot_be_read_is_malformed(message: bytes, offset: int, why: str) -> None:
    with pytest.raises(_MalformedError, match=why):
        _decode_name(message, offset)


def test_a_name_longer_than_the_wire_allows_is_refused() -> None:
    message = b"".join(bytes([63]) + b"x" * 63 for _ in range(5)) + b"\x00"
    with pytest.raises(_MalformedError, match="longer than 255 bytes"):
        _decode_name(message, 0)


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(message=st.binary(min_size=0, max_size=600), offset=st.integers(min_value=0, max_value=64))
def test_no_message_can_make_name_decoding_hang(message: bytes, offset: int) -> None:
    """**The property this module's safety rests on.**

    Arbitrary bytes either decode or raise, in bounded time. A parser that loops on one input
    would turn the bounded stall this resolver exists to remove into an unbounded one, which
    would make the whole module a net negative.
    """
    try:
        name, end = _decode_name(message, offset)
    except _MalformedError:
        return
    assert isinstance(name, str)
    assert 0 <= end <= len(message)


# ---------------------------------------------------------------------------
# Reading a response. These are the checks that decide whether a reply is ours at all.
# ---------------------------------------------------------------------------


def test_a_well_formed_answer_yields_its_records_with_their_ttls() -> None:
    reply = answer(query_bytes(), addresses=["1.1.1.1"], ttl=42)
    parsed = _parse(reply, txid=TXID, name=NAME, qtype=TYPE_A)
    assert parsed.records == (Record(ip=ipaddress.ip_address("1.1.1.1"), ttl=42),)
    assert parsed.truncated is False


def test_a_reply_carrying_another_transaction_id_is_not_ours() -> None:
    """A forged reply has to guess the id. This is the check that makes guessing necessary."""
    reply = answer(query_bytes(), addresses=["1.1.1.1"], txid=0x9999)
    with pytest.raises(_WrongQuestionError, match="transaction id"):
        _parse(reply, txid=TXID, name=NAME, qtype=TYPE_A)


def test_a_reply_echoing_another_question_type_is_not_ours() -> None:
    """It also has to echo the question, and the type is half of the question."""
    reply = answer(query_bytes(NAME, TYPE_AAAA), addresses=["::1"])
    with pytest.raises(_WrongQuestionError, match="answers type 28"):
        _parse(reply, txid=TXID, name=NAME, qtype=TYPE_A)


def test_a_reply_naming_a_different_question_is_not_ours() -> None:
    reply = answer(query_bytes(name="other.test"), addresses=["1.1.1.1"])
    with pytest.raises(_WrongQuestionError, match=r"answers 'other\.test'"):
        _parse(reply, txid=TXID, name=NAME, qtype=TYPE_A)


def test_a_query_arriving_where_a_response_belongs_is_not_ours() -> None:
    with pytest.raises(_WrongQuestionError, match="a query arrived"):
        _parse(query_bytes(), txid=TXID, name=NAME, qtype=TYPE_A)


def test_a_reply_carrying_no_question_is_not_ours() -> None:
    reply = bytearray(answer(query_bytes(), addresses=["1.1.1.1"]))
    reply[4:6] = struct.pack("!H", 0)
    with pytest.raises(_WrongQuestionError, match="carries 0 questions"):
        _parse(bytes(reply), txid=TXID, name=NAME, qtype=TYPE_A)


def test_a_reply_in_another_class_is_not_ours() -> None:
    query = query_bytes()
    _name, _qtype, past = question_of(query)
    doctored = bytearray(query)
    doctored[past - 2 : past] = struct.pack("!H", 3)  # CHAOS
    reply = HEADER.pack(TXID, 0x8180, 1, 0, 0, 0) + bytes(doctored[HEADER.size : past])
    with pytest.raises(_WrongQuestionError, match="class 3"):
        _parse(reply, txid=TXID, name=NAME, qtype=TYPE_A)


def test_a_message_shorter_than_a_header_is_malformed() -> None:
    with pytest.raises(_MalformedError, match="shorter than a DNS header"):
        _parse(b"\x00" * 11, txid=TXID, name=NAME, qtype=TYPE_A)


def test_a_truncated_question_is_malformed() -> None:
    reply = HEADER.pack(TXID, 0x8180, 1, 0, 0, 0) + encode_name(NAME) + b"\x00"
    with pytest.raises(_MalformedError, match="a question runs past the end"):
        _parse(reply, txid=TXID, name=NAME, qtype=TYPE_A)


def test_a_name_that_does_not_exist_is_an_empty_answer_rather_than_an_error() -> None:
    """NXDOMAIN is the server answering. Retrying it would ask a settled question again."""
    reply = answer(query_bytes(), rcode=RCODE_NXDOMAIN)
    assert _parse(reply, txid=TXID, name=NAME, qtype=TYPE_A).records == ()


def test_a_server_that_could_not_answer_is_a_failure_worth_asking_somebody_else() -> None:
    reply = answer(query_bytes(), rcode=RCODE_SERVFAIL)
    with pytest.raises(_ServerFailureError, match="rcode 2"):
        _parse(reply, txid=TXID, name=NAME, qtype=TYPE_A)


def test_the_truncation_flag_is_read_back() -> None:
    reply = answer(query_bytes(), addresses=["1.1.1.1"], truncated=True)
    assert _parse(reply, txid=TXID, name=NAME, qtype=TYPE_A).truncated is True


# ---------------------------------------------------------------------------
# The answer section. A recursive resolver returns more than what was asked for, and which of
# it is believed is a security decision.
# ---------------------------------------------------------------------------


def test_an_address_owned_by_the_end_of_a_cname_chain_is_accepted() -> None:
    reply = answer(
        query_bytes(),
        addresses=["1.1.1.1"],
        owner="second.test",
        cnames=[(NAME, "first.test"), ("first.test", "second.test")],
    )
    parsed = _parse(reply, txid=TXID, name=NAME, qtype=TYPE_A)
    assert [str(record.ip) for record in parsed.records] == ["1.1.1.1"]


def test_an_address_for_an_owner_nothing_pointed_at_is_dropped() -> None:
    """**The smuggling shape.** An extra record for an unrelated owner, in a reply that is
    otherwise legitimate, is how an answer nobody asked for gets carried in."""
    reply = answer(query_bytes(), addresses=["169.254.169.254"], owner="unrelated.test")
    assert _parse(reply, txid=TXID, name=NAME, qtype=TYPE_A).records == ()


def test_a_cname_for_an_owner_nothing_pointed_at_does_not_extend_the_chain() -> None:
    reply = answer(
        query_bytes(),
        addresses=["169.254.169.254"],
        owner="smuggled.test",
        cnames=[("unrelated.test", "smuggled.test")],
    )
    assert _parse(reply, txid=TXID, name=NAME, qtype=TYPE_A).records == ()


def test_a_record_of_the_wrong_type_for_the_right_owner_is_dropped() -> None:
    reply = answer(query_bytes(), addresses=["1.1.1.1"], qtype=TYPE_CNAME + 100)
    assert _parse(reply, txid=TXID, name=NAME, qtype=TYPE_A).records == ()


def test_an_address_record_of_the_wrong_length_is_malformed() -> None:
    """A four-byte AAAA is not a short address; it is a server lying about its own record."""
    reply = answer(query_bytes(NAME, TYPE_AAAA), addresses=["::1"], rdata=b"\x01\x02\x03\x04")
    with pytest.raises(_MalformedError, match="carries 4 bytes rather than 16"):
        _parse(reply, txid=TXID, name=NAME, qtype=TYPE_AAAA)


@pytest.mark.parametrize("qtype", [TYPE_A, TYPE_AAAA])
def test_an_address_of_the_wrong_length_is_malformed_at_the_leaf(qtype: int) -> None:
    with pytest.raises(_MalformedError, match="bytes rather than"):
        _address_from(b"\x00", qtype)


def test_a_record_header_running_past_the_end_is_malformed() -> None:
    reply = raw_reply(query_bytes(), encode_name(NAME) + b"\x00\x01")
    with pytest.raises(_MalformedError, match="a record header runs past the end"):
        _parse(reply, txid=TXID, name=NAME, qtype=TYPE_A)


def test_record_data_running_past_the_end_is_malformed() -> None:
    payload = encode_name(NAME) + struct.pack("!HHIH", TYPE_A, CLASS_IN, 60, 99) + b"\x01\x02"
    with pytest.raises(_MalformedError, match="a record's data runs past the end"):
        _parse(raw_reply(query_bytes(), payload), txid=TXID, name=NAME, qtype=TYPE_A)


def test_a_header_claiming_more_records_than_it_carries_is_malformed() -> None:
    reply = answer(query_bytes(), addresses=["1.1.1.1"])
    doctored = bytearray(reply)
    doctored[6:8] = struct.pack("!H", 5)
    with pytest.raises(_MalformedError, match="runs past the end"):
        _parse(bytes(doctored), txid=TXID, name=NAME, qtype=TYPE_A)


@settings(max_examples=400, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(message=st.binary(min_size=0, max_size=600))
def test_no_message_can_make_parsing_hang_or_raise_something_unplanned(message: bytes) -> None:
    """Arbitrary bytes produce an answer or one of three named refusals. Nothing else."""
    try:
        parsed = _parse(message, txid=TXID, name=NAME, qtype=TYPE_A)
    except (_MalformedError, _WrongQuestionError, _ServerFailureError):
        return
    assert all(isinstance(record, Record) for record in parsed.records)


# ---------------------------------------------------------------------------
# Against a real socket. The deadline is the reason this module exists, so it is asserted
# against a server that never answers rather than argued from the `settimeout` call.
# ---------------------------------------------------------------------------


def resolver_for(server: ScriptedDNS, **overrides: object) -> UdpResolver:
    """A resolver pointed at a scripted server, tuned short so a test is not a wait."""
    defaults: dict = {
        "nameservers": (server.host,),
        "nameserver_port": server.port,
        "timeout": 2.0,
        "attempt_timeout": 0.4,
        "attempts": 1,
    }
    return UdpResolver(**{**defaults, **overrides})


def addresses_of(rows: list) -> list[str]:
    """The address out of each `getaddrinfo` row."""
    return [row[4][0] for row in rows]


def both_families(query: bytes) -> bytes:
    """Answer A with a v4 address and AAAA with a v6 one."""
    _name, qtype, _past = question_of(query)
    if qtype == TYPE_AAAA:
        return answer(query, addresses=["2606:4700::1111"])
    return answer(query, addresses=["1.1.1.1"])


def test_a_name_resolves_to_every_family_with_ipv6_first() -> None:
    with ScriptedDNS(both_families) as server:
        rows = resolver_for(server)(NAME, 443)
    assert addresses_of(rows) == ["2606:4700::1111", "1.1.1.1"]


def test_the_rows_carry_the_sockaddr_shape_the_socket_layer_expects() -> None:
    """Four elements for IPv6, two for IPv4. `ssrfguard.connect` passes these through intact."""
    with ScriptedDNS(both_families) as server:
        v6, v4 = resolver_for(server)(NAME, 8080)
    assert v6[0] is socket.AF_INET6
    assert v6[4] == ("2606:4700::1111", 8080, 0, 0)
    assert v4[0] is socket.AF_INET
    assert v4[4] == ("1.1.1.1", 8080)


def test_the_socket_type_and_protocol_are_echoed_the_way_getaddrinfo_echoes_them() -> None:
    with ScriptedDNS(both_families) as server:
        rows = resolver_for(server)(NAME, 443, 0, socket.SOCK_STREAM, 0, 0)
    assert {(row[1], row[2]) for row in rows} == {(socket.SOCK_STREAM, socket.IPPROTO_TCP)}


def test_a_server_that_never_answers_fails_inside_the_deadline() -> None:
    """**The claim of the module.** `getaddrinfo` against this server would never return."""
    with ScriptedDNS(lambda _query: None) as server:
        resolver = resolver_for(server, timeout=0.5, attempt_timeout=0.15, attempts=2)
        started = time.monotonic()
        with pytest.raises(socket.gaierror, match="no AAAA answer"):
            resolver(NAME)
        elapsed = time.monotonic() - started
    assert elapsed < 3.0, f"the deadline was not honoured: {elapsed:.2f}s"


def test_the_total_ceiling_binds_even_when_the_attempts_would_run_longer() -> None:
    """`timeout` is the ceiling on the call, not a per-attempt figure multiplied by attempts."""
    with ScriptedDNS(lambda _query: None) as server:
        resolver = resolver_for(server, timeout=0.4, attempt_timeout=5.0, attempts=5)
        started = time.monotonic()
        with pytest.raises(socket.gaierror, match=r"deadline passed|no AAAA answer"):
            resolver(NAME)
        elapsed = time.monotonic() - started
    assert elapsed < 3.0, f"the total ceiling did not bind: {elapsed:.2f}s"


def test_a_second_nameserver_is_asked_when_the_first_does_not_answer() -> None:
    """Nothing is listening on the first entry, so the failover is the only way to an answer."""
    with ScriptedDNS(both_families) as server:
        resolver = UdpResolver(
            nameservers=("127.0.0.2", server.host),
            nameserver_port=server.port,
            timeout=2.0,
            attempt_timeout=0.3,
            attempts=1,
            families=(socket.AF_INET,),
        )
        assert addresses_of(resolver(NAME)) == ["1.1.1.1"]
        assert server.query_count == 1


def test_a_server_that_answers_only_the_second_time_is_asked_twice() -> None:
    seen: list[int] = []

    def flaky(query: bytes) -> bytes | None:
        seen.append(1)
        return None if len(seen) == 1 else answer(query, addresses=["1.1.1.1"])

    with ScriptedDNS(flaky) as server:
        resolver = resolver_for(server, attempts=2, attempt_timeout=0.2, families=(socket.AF_INET,))
        assert addresses_of(resolver(NAME)) == ["1.1.1.1"]
    assert len(seen) == 2


def test_a_forged_reply_arriving_first_does_not_end_the_wait_for_the_real_one() -> None:
    """**The off-path forgery shape.** A guess at the transaction id lands before the real
    answer and must be dropped rather than believed, and dropping it must not abandon the
    query."""

    def forge_then_answer(query: bytes) -> list[bytes]:
        forged = answer(query, addresses=["169.254.169.254"], txid=(txid_of(query) + 1) % 0x10000)
        return [forged, answer(query, addresses=["1.1.1.1"])]

    with ScriptedDNS(forge_then_answer) as server:
        resolver = resolver_for(server, families=(socket.AF_INET,))
        assert addresses_of(resolver(NAME)) == ["1.1.1.1"]


def test_a_forgery_that_is_the_only_reply_times_out_rather_than_being_believed() -> None:
    def only_forgery(query: bytes) -> bytes:
        return answer(query, addresses=["169.254.169.254"], txid=(txid_of(query) + 1) % 0x10000)

    with ScriptedDNS(only_forgery) as server:
        resolver = resolver_for(server, timeout=0.6, attempt_timeout=0.2, attempts=1)
        with pytest.raises(socket.gaierror, match="no AAAA answer"):
            resolver(NAME)


def test_a_truncated_reply_is_asked_again_over_tcp() -> None:
    sent: list[int] = []

    def responder(query: bytes) -> bytes:
        if not sent:
            sent.append(1)
            return answer(query, addresses=["9.9.9.9"], truncated=True)
        return answer(query, addresses=["1.1.1.1"])

    with ScriptedDNS(responder) as server:
        resolver = resolver_for(server, families=(socket.AF_INET,))
        assert addresses_of(resolver(NAME)) == ["1.1.1.1"]
        assert len(server.tcp_queries) == 1, "the fallback did not reach TCP"


def test_a_tcp_reply_that_is_still_truncated_is_refused() -> None:
    """Over TCP there is no size limit to hit, so `TC` is the server saying something untrue."""
    with ScriptedDNS(lambda q: answer(q, addresses=["1.1.1.1"], truncated=True)) as server:
        resolver = resolver_for(server, families=(socket.AF_INET,))
        with pytest.raises(socket.gaierror, match="marked truncated"):
            resolver(NAME)


def test_a_tcp_reply_too_short_to_be_a_message_is_refused() -> None:
    sent: list[int] = []

    def responder(query: bytes) -> bytes:
        if not sent:
            sent.append(1)
            return answer(query, addresses=["9.9.9.9"], truncated=True)
        return b"\x00"

    with ScriptedDNS(responder) as server:
        resolver = resolver_for(server, families=(socket.AF_INET,))
        with pytest.raises(socket.gaierror, match="shorter than a DNS header"):
            resolver(NAME)


# ---------------------------------------------------------------------------
# The fail-closed rule, which is the one decision in this module that trades availability for
# the ability of `on_partial_block` to see what it exists to see.
# ---------------------------------------------------------------------------


def test_a_query_that_does_not_complete_fails_the_call_rather_than_halving_the_answer() -> None:
    """**The security property of this module that is not the deadline.**

    A zone that answers A and stalls AAAA would otherwise decide which half of its own answer
    set the policy is allowed to see, and `on_partial_block='reject'` can only refuse a name
    that resolves both ways if it is shown both ways.
    """

    def answer_a_only(query: bytes) -> bytes | None:
        _name, qtype, _past = question_of(query)
        return None if qtype == TYPE_AAAA else answer(query, addresses=["1.1.1.1"])

    with ScriptedDNS(answer_a_only) as server:
        resolver = resolver_for(server, timeout=0.6, attempt_timeout=0.2, attempts=1)
        with pytest.raises(socket.gaierror, match="no AAAA answer"):
            resolver(NAME)


def test_a_server_failure_on_one_family_fails_the_call_for_the_same_reason() -> None:
    def servfail_aaaa(query: bytes) -> bytes:
        _name, qtype, _past = question_of(query)
        if qtype == TYPE_AAAA:
            return answer(query, rcode=RCODE_SERVFAIL)
        return answer(query, addresses=["1.1.1.1"])

    with ScriptedDNS(servfail_aaaa) as server, pytest.raises(socket.gaierror, match="rcode 2"):
        resolver_for(server, attempts=1)(NAME)


def test_a_definitive_empty_answer_is_complete_information_and_does_not_fail_the_call() -> None:
    """NODATA and NXDOMAIN are the server saying there is nothing, which is not a missing
    answer. Only a query that never completed is."""

    def nodata_aaaa(query: bytes) -> bytes:
        _name, qtype, _past = question_of(query)
        if qtype == TYPE_AAAA:
            return answer(query, rcode=RCODE_NXDOMAIN)
        return answer(query, addresses=["1.1.1.1"])

    with ScriptedDNS(nodata_aaaa) as server:
        assert addresses_of(resolver_for(server)(NAME)) == ["1.1.1.1"]


def test_a_name_with_no_records_at_all_does_not_resolve() -> None:
    with (
        ScriptedDNS(answer) as server,
        pytest.raises(socket.gaierror, match="no address records"),
    ):
        resolver_for(server)(NAME)


# ---------------------------------------------------------------------------
# The TTL, which `getaddrinfo` discards and which has nowhere to live in a `ResolverAnswer`.
# ---------------------------------------------------------------------------


def test_records_keeps_the_lifetimes_the_zone_claimed() -> None:
    with ScriptedDNS(lambda q: answer(q, addresses=["1.1.1.1"], ttl=90)) as server:
        records = resolver_for(server, families=(socket.AF_INET,)).records(NAME)
    assert records == (Record(ip=ipaddress.ip_address("1.1.1.1"), ttl=90),)


def test_narrowing_the_families_sends_one_query_rather_than_two() -> None:
    with ScriptedDNS(both_families) as server:
        rows = resolver_for(server, families=(socket.AF_INET,))(NAME)
        assert addresses_of(rows) == ["1.1.1.1"]
        assert server.query_count == 1


def test_asking_for_one_family_asks_about_only_that_one() -> None:
    with ScriptedDNS(both_families) as server:
        rows = resolver_for(server)(NAME, 443, socket.AF_INET6)
        assert addresses_of(rows) == ["2606:4700::1111"]
        assert server.query_count == 1


# ---------------------------------------------------------------------------
# Reading a framed reply, where the failure is a peer that stops talking.
# ---------------------------------------------------------------------------


def test_a_deadline_that_has_passed_leaves_no_time() -> None:
    """The bound behind every wait in this module, in the one place it is now written."""
    with pytest.raises(TimeoutError, match="the deadline passed while testing"):
        _time_left(time.monotonic() - 1.0, "while testing")


def test_a_deadline_still_ahead_leaves_the_time_that_is_left() -> None:
    assert 0 < _time_left(time.monotonic() + 5.0, "while testing") <= 5.0


def test_a_framed_read_gathers_every_chunk() -> None:
    near, far = socket.socketpair()
    with near, far:
        far.sendall(b"abc")
        assert _recv_exactly(near, 3, time.monotonic() + 2.0) == b"abc"


def test_a_peer_that_closes_mid_reply_is_malformed() -> None:
    near, far = socket.socketpair()
    with near:
        far.sendall(b"ab")
        far.close()
        with pytest.raises(_MalformedError, match="closed the connection mid-reply"):
            _recv_exactly(near, 4, time.monotonic() + 2.0)


def test_a_framed_read_with_no_time_left_is_a_timeout() -> None:
    near, far = socket.socketpair()
    with near, far, pytest.raises(TimeoutError, match="deadline passed mid-reply"):
        _recv_exactly(near, 1, time.monotonic() - 1.0)


# ---------------------------------------------------------------------------
# Literal addresses, which `getaddrinfo` parses rather than looks up, and so does this.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "family", "expected"),
    [
        ("127.0.0.1", socket.AF_INET, "127.0.0.1"),
        ("8.8.8.8", socket.AF_INET, "8.8.8.8"),
        ("::1", socket.AF_INET6, "::1"),
        ("[2001:db8::1]", socket.AF_INET6, "2001:db8::1"),
    ],
)
def test_a_literal_address_is_parsed_and_never_put_on_the_wire(
    host: str, family: int, expected: str
) -> None:
    with ScriptedDNS(both_families) as server:
        rows = resolver_for(server)(host, 443)
        assert server.query_count == 0, "a literal address was looked up"
    assert rows[0][0] is family
    assert rows[0][4][0] == expected


def test_numerichost_refuses_a_name_rather_than_resolving_it() -> None:
    with ScriptedDNS(both_families) as server:
        with pytest.raises(socket.gaierror, match="AI_NUMERICHOST"):
            resolver_for(server)(NAME, 443, 0, 0, 0, socket.AI_NUMERICHOST)
        assert server.query_count == 0


@pytest.mark.parametrize("host", ["0177.0.0.1", "2130706433", "127.1"])
def test_a_legacy_address_form_is_not_decoded_into_an_address(host: str) -> None:
    """**A documented difference from the platform, in the safe direction.**

    glibc reads `0177.0.0.1` as octal and reaches 127.0.0.1. `ipaddress` refuses all three, so
    they are treated as names and looked up, which cannot reach loopback by decoding. The URL
    layer already refuses every one of these before resolution is reached at all.
    """
    with ScriptedDNS(lambda q: answer(q, rcode=RCODE_NXDOMAIN)) as server:
        with pytest.raises(socket.gaierror):
            resolver_for(server, timeout=1.0, attempt_timeout=0.3)(host)
        assert server.query_count >= 1, "the form was decoded rather than looked up"


# ---------------------------------------------------------------------------
# Construction. Every message names the value and the field, the way this package's refusals do.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("kwargs", "why"),
    [
        ({"nameservers": ()}, "nameservers is empty"),
        ({"nameservers": ("dns.example.com",)}, "is not an IP address"),
        ({"timeout": 0}, "timeout=0 must be positive"),
        ({"timeout": -1.0}, "must be positive"),
        ({"attempt_timeout": 0}, "attempt_timeout=0 must be positive"),
        ({"attempts": 0}, "attempts=0 must be at least 1"),
        ({"families": ()}, "families is empty"),
        ({"families": (socket.AF_UNIX,)}, "neither AF_INET nor AF_INET6"),
    ],
)
def test_an_unusable_configuration_is_refused_at_construction(kwargs: dict, why: str) -> None:
    defaults = {"nameservers": ("127.0.0.1",)}
    with pytest.raises(ValueError, match=why):
        UdpResolver(**{**defaults, **kwargs})


def test_a_usable_configuration_is_a_value_that_compares_equal() -> None:
    assert UdpResolver(nameservers=("127.0.0.1",)) == UdpResolver(nameservers=("127.0.0.1",))


# ---------------------------------------------------------------------------
# Where the nameservers come from when nobody says.
# ---------------------------------------------------------------------------


def test_resolv_conf_yields_every_nameserver_in_order(tmp_path: Path) -> None:
    conf = tmp_path / "resolv.conf"
    conf.write_text(
        "# a comment\n"
        "; another comment\n"
        "search example.test\n"
        "nameserver 192.0.2.1\n"
        "nameserver 2001:4860:4860::8888\n"
        "options edns0\n"
    )
    assert nameservers_from_resolv_conf(conf) == ("192.0.2.1", "2001:4860:4860::8888")


def test_a_nameserver_that_is_not_an_address_is_skipped(tmp_path: Path) -> None:
    """A name here could only be resolved by the resolver being built."""
    conf = tmp_path / "resolv.conf"
    conf.write_text("nameserver dns.example.test\nnameserver 192.0.2.1\n")
    assert nameservers_from_resolv_conf(conf) == ("192.0.2.1",)


@pytest.mark.parametrize("body", ["", "search example.test\n", "nameserver\n", "nameserver x\n"])
def test_a_resolv_conf_naming_no_usable_server_says_so(tmp_path: Path, body: str) -> None:
    conf = tmp_path / "resolv.conf"
    conf.write_text(body)
    with pytest.raises(ValueError, match="names no usable nameserver"):
        nameservers_from_resolv_conf(conf)


def test_a_resolv_conf_that_is_not_there_is_not_softened_into_an_empty_list(
    tmp_path: Path,
) -> None:
    """A resolver with no servers fails every lookup; it should say why once, at construction."""
    with pytest.raises(OSError, match="No such file"):
        nameservers_from_resolv_conf(tmp_path / "absent")


# ---------------------------------------------------------------------------
# As a drop-in. The point of the whole module is that nothing else has to change.
# ---------------------------------------------------------------------------


def test_the_policy_validates_what_this_resolver_returns_like_any_other() -> None:
    """Installing a resolver grants nothing: every answer is still checked."""
    with ScriptedDNS(lambda q: answer(q, addresses=["169.254.169.254"])) as server:
        policy = Policy()
        target = policy.check_url(f"http://{NAME}/")
        with pytest.raises(BlockedAddressError, match=r"169\.254\.169\.254"):
            resolve(
                target, policy=policy, resolver=resolver_for(server, families=(socket.AF_INET,))
            )


def test_a_name_answering_both_ways_is_still_refused_whole() -> None:
    """The reason the fail-closed rule above exists, reached through the real resolver."""

    def both_ways(query: bytes) -> bytes:
        _name, qtype, _past = question_of(query)
        if qtype == TYPE_AAAA:
            return answer(query, rcode=RCODE_NXDOMAIN)
        return answer(query, addresses=["1.1.1.1", "169.254.169.254"])

    with ScriptedDNS(both_ways) as server:
        policy = Policy()
        target = policy.check_url(f"http://{NAME}/")
        with pytest.raises(BlockedAddressError, match="resolves to both permitted and denied"):
            resolve(target, policy=policy, resolver=resolver_for(server))


def test_a_literal_target_resolves_without_a_query_through_the_whole_stack() -> None:
    """`resolve` passes `AI_NUMERICHOST` for a literal, and this honours it."""
    with ScriptedDNS(both_families) as server:
        policy = Policy()
        target = policy.check_url("http://8.8.8.8/")
        addresses = resolve(target, policy=policy, resolver=resolver_for(server))
        assert [str(address.ip) for address in addresses] == ["8.8.8.8"]
        assert server.query_count == 0


def test_a_permitted_name_resolves_to_the_addresses_the_policy_allowed() -> None:
    with ScriptedDNS(both_families) as server:
        policy = Policy()
        target = policy.check_url(f"http://{NAME}/")
        addresses = resolve(target, policy=policy, resolver=resolver_for(server))
    assert [str(address.ip) for address in addresses] == ["2606:4700::1111", "1.1.1.1"]
    assert {address.hostname for address in addresses} == {NAME}


# ---------------------------------------------------------------------------
# Boundaries and off-by-ones. Every test below exists because a mutant survived without it:
# the bound was there, and nothing checked which side of it the code was on.
# ---------------------------------------------------------------------------


def name_of_wire_length(total: int) -> bytes:
    """A wire-form name whose decoded length budget is exactly `total` bytes."""
    labels = []
    while total >= 64:
        labels.append(b"\x3f" + b"x" * 63)
        total -= 64
    if total:
        labels.append(bytes([total - 1]) + b"x" * (total - 1))
    return b"".join(labels) + b"\x00"


def test_a_name_of_exactly_the_maximum_length_decodes() -> None:
    assert _decode_name(name_of_wire_length(255), 0)[0].count("x") == 251


def test_a_name_one_byte_over_the_maximum_does_not() -> None:
    with pytest.raises(_MalformedError, match="longer than 255 bytes"):
        _decode_name(name_of_wire_length(256), 0)


def test_a_name_of_exactly_the_maximum_length_encodes() -> None:
    name = ".".join(["x" * 63] * 3 + ["x" * 61])
    assert len(_encode_name(name)) == 255


def test_a_name_one_byte_over_the_maximum_is_refused() -> None:
    name = ".".join(["x" * 63] * 3 + ["x" * 62])
    with pytest.raises(ValueError, match="longer than 255 bytes"):
        _encode_name(name)


def pointer_chain(count: int) -> bytes:
    """A message of `count` pointers, each pointing at the next, ending in a root label."""
    return b"".join(struct.pack("!H", 0xC000 | (2 * (i + 1))) for i in range(count)) + b"\x00"


def test_a_name_may_follow_the_last_pointer_the_budget_allows() -> None:
    assert _decode_name(pointer_chain(64), 0) == ("", 2)


def test_a_name_may_not_follow_one_more_than_that() -> None:
    with pytest.raises(_MalformedError, match="more than 64 compression pointers"):
        _decode_name(pointer_chain(65), 0)


def test_a_pointer_to_the_byte_after_the_message_is_outside_it() -> None:
    """One past the end is outside. The pointer below targets exactly `len(message)`."""
    body = encode_name("example.test")
    message = body + struct.pack("!H", 0xC000 | (len(body) + 2))
    with pytest.raises(_MalformedError, match="points outside the message"):
        _decode_name(message, len(body))


def test_the_end_of_a_name_is_where_its_first_pointer_was() -> None:
    """With two pointers, only the first one's position is the name's end here."""
    message = encode_name("example.test") + struct.pack("!HH", 0xC000, 0xC000 | 12)
    assert _decode_name(message, 14) == ("example.test", 16)


def test_a_message_of_exactly_a_header_is_read_rather_than_called_short() -> None:
    """Twelve bytes is a header. It carries no question, which is a different complaint."""
    with pytest.raises(_WrongQuestionError, match="carries 0 questions"):
        _parse(HEADER.pack(TXID, 0x8180, 0, 0, 0, 0), txid=TXID, name=NAME, qtype=TYPE_A)


def test_a_record_header_ending_exactly_at_the_message_end_is_read() -> None:
    """A record of a type we did not ask for, carrying nothing, ending the message exactly."""
    payload = encode_name(NAME) + struct.pack("!HHIH", 99, CLASS_IN, 60, 0)
    reply = raw_reply(query_bytes(), payload)
    assert _parse(reply, txid=TXID, name=NAME, qtype=TYPE_A).records == ()


# ---------------------------------------------------------------------------
# The absolute form. A name may arrive, be echoed, or be pointed at with a trailing dot, and
# every comparison in this module has to fold it away or it compares two spellings of one name.
# ---------------------------------------------------------------------------


def test_a_name_in_the_absolute_form_is_asked_about_in_the_relative_one() -> None:
    """**The wire has nowhere to put a trailing dot**, so the fold happens once, at encoding.

    `example.test.` and `example.test` are one name. The absolute form is a convention of the
    text form: a message carries length-prefixed labels, and there is no label for the root
    beyond the terminator every name already ends with. So the parser never sees one, and the
    four tests that used to sit here were asserting a fold on messages that could not carry the
    thing being folded. This asks for the absolute form and reads the query off the wire.
    """
    with ScriptedDNS(both_families) as server:
        rows = resolver_for(server, families=(socket.AF_INET,))(NAME + ".", 443)
        asked = [question_of(query)[0] for query in server.queries]
    assert addresses_of(rows) == ["1.1.1.1"]
    assert asked == [NAME], "the absolute form reached the wire"


def test_the_two_forms_of_one_name_encode_identically() -> None:
    assert _encode_name(NAME + ".") == _encode_name(NAME)


def test_a_dropped_record_does_not_end_the_answer_section() -> None:
    """**The record that matters can come after the one that does not.** Stopping at the first
    unwanted record would lose it, and a reply is not obliged to put ours first."""
    query = query_bytes()
    unwanted = encode_name("unrelated.test") + struct.pack("!HHIH", TYPE_A, CLASS_IN, 60, 4)
    unwanted += ipaddress.ip_address("169.254.169.254").packed
    wanted = encode_name(NAME) + struct.pack("!HHIH", TYPE_A, CLASS_IN, 60, 4)
    wanted += ipaddress.ip_address("1.1.1.1").packed
    parsed = _parse(
        raw_reply(query, unwanted + wanted, ancount=2), txid=TXID, name=NAME, qtype=TYPE_A
    )
    assert [str(record.ip) for record in parsed.records] == ["1.1.1.1"]


# ---------------------------------------------------------------------------
# What a refusal carries. `gaierror` has an errno and callers branch on it, so it is asserted
# rather than assumed.
# ---------------------------------------------------------------------------


def test_a_name_that_could_not_be_asked_about_is_a_temporary_failure() -> None:
    """`EAI_AGAIN` rather than `EAI_NONAME`: nobody said this name does not exist."""
    with ScriptedDNS(lambda _query: None) as server:
        resolver = resolver_for(
            server, timeout=0.5, attempt_timeout=0.15, families=(socket.AF_INET,)
        )
        with pytest.raises(socket.gaierror) as caught:
            resolver(NAME)
    assert caught.value.errno == socket.EAI_AGAIN
    assert "no A answer" in str(caught.value)


def test_every_attempt_is_named_in_the_refusal() -> None:
    """A resolver that fails silently in the middle of a guard is one nobody can debug."""
    with ScriptedDNS(lambda _query: None) as server:
        resolver = resolver_for(
            server, timeout=1.0, attempt_timeout=0.15, attempts=2, families=(socket.AF_INET,)
        )
        with pytest.raises(socket.gaierror) as caught:
            resolver(NAME)
    assert str(caught.value).count("; 127.0.0.1:") == 1, "both attempts should be listed"


def test_a_name_given_to_numerichost_is_a_permanent_failure() -> None:
    with ScriptedDNS(both_families) as server, pytest.raises(socket.gaierror) as caught:
        resolver_for(server)(NAME, 443, 0, 0, 0, socket.AI_NUMERICHOST)
    assert caught.value.errno == socket.EAI_NONAME


# ---------------------------------------------------------------------------
# The row shape, in the fields nothing else asserts.
# ---------------------------------------------------------------------------


def test_a_row_defaults_to_a_stream_socket_and_carries_no_canonical_name() -> None:
    """`AI_CANONNAME` is not honoured, so the field is empty rather than guessed at."""
    with ScriptedDNS(both_families) as server:
        rows = resolver_for(server)(NAME, 443)
    assert {(row[1], row[3]) for row in rows} == {(socket.SOCK_STREAM, "")}


def test_a_datagram_request_is_echoed_as_one() -> None:
    with ScriptedDNS(both_families) as server:
        rows = resolver_for(server)(NAME, 443, 0, socket.SOCK_DGRAM)
    assert {(row[1], row[2]) for row in rows} == {(socket.SOCK_DGRAM, socket.IPPROTO_UDP)}


def test_an_ipv6_nameserver_is_talked_to_over_ipv6() -> None:
    """Nothing else in this file uses one, and the family is chosen from the address."""
    assert _family_of("2001:4860:4860::8888") is socket.AF_INET6
    assert _family_of("192.0.2.1") is socket.AF_INET


# ---------------------------------------------------------------------------
# Reading a framed reply, in the two places a partial read decides the answer.
# ---------------------------------------------------------------------------


def send_later(sock: socket.socket, payload: bytes, after: float) -> threading.Thread:
    """Send `payload` once the reader is already waiting, so the read spans two chunks."""

    def deliver() -> None:
        time.sleep(after)
        sock.sendall(payload)

    thread = threading.Thread(target=deliver, daemon=True)
    thread.start()
    return thread


def test_a_framed_read_joins_chunks_without_inventing_bytes_between_them() -> None:
    """**Sending both halves first would not test this.** Four bytes already in the buffer are
    one `recv`, and the loop that gathers them never runs twice."""
    near, far = socket.socketpair()
    with near, far:
        far.sendall(b"ab")
        thread = send_later(far, b"cd", 0.1)
        assert _recv_exactly(near, 4, time.monotonic() + 5.0) == b"abcd"
        thread.join(timeout=2)


def test_a_framed_read_takes_what_it_asked_for_and_leaves_the_rest() -> None:
    """**Over TCP the next message is behind this one.** Reading past the length is how a reply
    and the message after it become one unparseable run of bytes."""
    near, far = socket.socketpair()
    with near, far:
        far.sendall(b"ab")
        thread = send_later(far, b"cdefghij", 0.1)
        assert _recv_exactly(near, 4, time.monotonic() + 5.0) == b"abcd"
        assert _recv_exactly(near, 3, time.monotonic() + 5.0) == b"efg"
        thread.join(timeout=2)


# ---------------------------------------------------------------------------
# resolv.conf, where a comment can carry the word this is looking for.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("comment", ["#", ";"])
def test_a_commented_out_nameserver_is_not_a_nameserver(tmp_path: Path, comment: str) -> None:
    conf = tmp_path / "resolv.conf"
    conf.write_text(f"{comment} nameserver 198.51.100.1\nnameserver 192.0.2.1\n")
    assert nameservers_from_resolv_conf(conf) == ("192.0.2.1",)


def test_a_resolv_conf_that_is_not_valid_utf8_is_read_anyway(tmp_path: Path) -> None:
    """A byte nobody can decode is not a reason to fail every lookup on the host."""
    conf = tmp_path / "resolv.conf"
    conf.write_bytes(b"# \xff\xfe not utf-8\nnameserver 192.0.2.1\n")
    assert nameservers_from_resolv_conf(conf) == ("192.0.2.1",)


def test_asking_for_a_family_this_resolver_does_not_serve_yields_nothing() -> None:
    """`families` narrows what is asked; a request outside it is not a query, so it is empty."""
    with ScriptedDNS(both_families) as server:
        resolver = resolver_for(server, families=(socket.AF_INET,))
        with pytest.raises(socket.gaierror, match="no address records"):
            resolver(NAME, 443, socket.AF_INET6)
        assert server.query_count == 0


def test_a_reply_from_another_source_never_reaches_the_resolver() -> None:
    """**The third anti-forgery check, and the only one the parser cannot make.**

    This forgery is correct in every way the parser could test: the right transaction id, the
    right question, a well-formed answer, and it is sent first. What is wrong with it is where it
    came from. The resolver's datagram socket is connected, so the kernel drops it before any of
    this package runs, and the real answer is the one that lands.
    """
    server: ScriptedDNS

    def forge_from_elsewhere(query: bytes) -> bytes:
        server.spoof(answer(query, addresses=["169.254.169.254"]))
        return answer(query, addresses=["1.1.1.1"])

    with ScriptedDNS(forge_from_elsewhere) as running:
        server = running
        rows = resolver_for(running, families=(socket.AF_INET,))(NAME, 443)
    assert addresses_of(rows) == ["1.1.1.1"], "a datagram from another source was believed"
