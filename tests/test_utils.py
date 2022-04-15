import base64
import json
from operator import eq, ne

import pytest

from libtrust.utils import detect_json_indent, jose_base64_url_decode, jose_base64_url_encode, last_index, not_space


@pytest.mark.parametrize(
    "content",
    [
        b"test_jose_base64_url_decode",
        b"base64encoded",
    ],
)
def test_jose_decode(content):
    assert jose_base64_url_decode(base64.urlsafe_b64encode(content)) == content


@pytest.mark.parametrize(
    "content, op",
    [
        # dGVzdF9qb3NlX2Jhc2U2NF91cmxfZGVjb2Rl == dGVzdF9qb3NlX2Jhc2U2NF91cmxfZGVjb2Rl
        (b"test_jose_base64_url_decode", eq),
        # YmFzZTY0ZW5jb2RlZA != YmFzZTY0ZW5jb2RlZA==
        (b"base64encoded", ne),
    ],
)
def test_json_encode(content, op):
    assert op(jose_base64_url_encode(content), base64.urlsafe_b64encode(content).decode())


@pytest.mark.parametrize(
    "content, test, expected",
    [
        (" " * 1000, lambda x: x == " ", 999),
        ("0" * 1000, not_space, 999),
        pytest.param(" " * 1000, not_space, 999, marks=[pytest.mark.xfail]),
    ],
)
def test_last_index(content, test, expected):
    assert last_index(content, test) == expected


@pytest.mark.parametrize(
    "content, expected",
    [
        (json.dumps({}, indent=2), None),
        (json.dumps({"a": "a"}, indent=2), 2),
        (json.dumps({1: 1}, indent=2), 2),
        (json.dumps({1: 1, 2: {3: 3}}, indent=2), 2),
        (json.dumps({1: 1, 2: {3: 3}, 4: 4}, indent=2), 2),
        ("{\n  \n}", 0),
        ('{\n    "\n}', 4),
        ('{\n  "1": 1,\n "1": 1', 2),
    ],
)
def test_detect_json_indent(content, expected):
    assert detect_json_indent(content) == expected
