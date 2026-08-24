"""Every refusal names the value and the rule that refused it. Here is the gallery.

Run it:

    python examples/02_what_a_refusal_says.py

This example exists because of a claim in `CONTRIBUTING.md` that is easy to make and easy to
let rot: *a refusal a user cannot act on gets configured around, and a control that gets
configured around protects nothing.* So every message below names the offending value **and**
the field or block that rejected it, which is what makes a refusal a bug report rather than a
wall.

Read the output next to the source. The encodings section is the one worth reading twice.
"""

from __future__ import annotations

from _support import heading

from ssrfguard import Policy
from ssrfguard.errors import BlockedAddressError, BlockedURLError, SSRFGuardError

#: Grouped the way a reader meets them, not the way the code checks them.
CASES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "Addresses you did not mean to expose",
        (
            "http://127.0.0.1/admin",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://10.0.0.5/internal",
            "http://[::1]:8080/",
            "http://[fd00::1]/",
            "http://100.64.0.1/",
        ),
    ),
    (
        "The same addresses, written so they do not look like themselves",
        (
            # Every one of these is 127.0.0.1 or the metadata endpoint to some resolver or
            # some parser, and none of them looks like it at a glance. This is why the host
            # is parsed rather than pattern-matched.
            "http://0177.0.0.1/",
            "http://2130706433/",
            "http://127.1/",
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:169.254.169.254]/",
            "http://[64:ff9b::a9fe:a9fe]/",
            "https://①②⑦.0.0.1/",
        ),
    ),
    (
        "Schemes, ports and credentials",
        (
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_SET%20key%20value",
            "http://example.com:22/",
            "http://example.com:6379/",
            "http://trusted.example.com@127.0.0.1/",
        ),
    ),
    (
        "URLs that would parse differently somewhere else",
        (
            # urlsplit strips tab, newline and carriage return from anywhere in a URL, so the
            # string you validated is not the string it parsed. Another component splitting the
            # same bytes may disagree. Refused rather than normalised.
            "https://exa\tmple.com/",
            "https://example.com\n/",
            "http://exa mple.com/",
        ),
    ),
)


def main() -> None:
    """Print every refusal, grouped, with the exact message the caller would see."""
    policy = Policy()

    for title, urls in CASES:
        heading(title)
        for url in urls:
            try:
                target = policy.check_url(url)
            except SSRFGuardError as refused:
                print(f"  {type(refused).__name__}: {refused}")
            else:  # pragma: no cover - none of the cases above is permitted
                print(f"  permitted: {target}")

    heading("A refusal carries structure, not just a sentence")
    # The message is for a human reading a log. The attributes are for the code deciding what to
    # do next, which should not be parsing English. The two refusal types carry different
    # attributes because they answer different questions: one is about a URL as written, the
    # other about an address it turned out to name.
    try:
        policy.check_url("http://169.254.169.254/")
    except BlockedURLError as refused:
        print(f"  BlockedURLError.url    : {refused.url!r}")
        print(f"  BlockedURLError.reason : {refused.reason}")

    try:
        policy.check_address("169.254.169.254")
    except BlockedAddressError as refused:
        print(f"  BlockedAddressError.address: {refused.address}")
        print(f"  BlockedAddressError.reason : {refused.reason}")

    heading("And the check that passes is the one worth understanding")
    # This URL is permitted *by the policy layer*, and it points at the GCP metadata endpoint.
    # Nothing here resolves anything, so nothing here can know that. The address check happens
    # when the name is resolved, which is the next example.
    print(f"  {policy.check_url('http://metadata.google.internal/')}")
    print("  a name is not an address, and this layer never resolves one; see 03_the_pin.py")


if __name__ == "__main__":
    main()
