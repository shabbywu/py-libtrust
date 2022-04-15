import base64
import json
from typing import Any, Callable, Union


def json_dumps(obj, **kwargs):
    indent = kwargs.get("indent")
    if indent is None:
        kwargs["separators"] = (",", ":")
    return json.dumps(obj, **kwargs)


def jose_base64_url_encode(data: Union[str, bytes]) -> str:
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jose_base64_url_decode(data: Union[str, bytes]) -> bytes:
    if isinstance(data, str):
        data = data.encode()
    data = data.replace(b"\n", b"")
    data = data.replace(b" ", b"")
    # illegal when data % 4 == 1
    data += {0: b"", 2: b"==", 3: b"="}[len(data) % 4]
    return base64.urlsafe_b64decode(data)


def detect_json_indent(json_content: str) -> int:
    indent = ""
    if len(json_content) > 2 and json_content[0] == "{" and json_content[1] == "\n":
        quote_index = json_content[1:].find('"')
        if quote_index > 0:
            indent = json_content[2 : quote_index + 1]
        return len(indent)


def not_space(x: str) -> bool:
    return not x.isspace()


def last_index(iterable, test: Callable[[Any], bool]) -> int:
    testd = list(map(test, iterable))
    testd.reverse()
    try:
        reversed_idx = testd.index(True)
    except ValueError as e:
        raise ValueError("Index not found.") from e
    return len(testd) - reversed_idx - 1
