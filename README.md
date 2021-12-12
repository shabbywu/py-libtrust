# py-libtrust - Yet another docker/libtrust implement by python.

Libtrust is library for managing authentication and authorization using public key cryptography.

Works for Python 3.6+.

## Usage

### Install
You can install from PyPi.

```bash
❯ pip install py-libtrust
```

### Example
#### Sign/Verify a jose-json-web-signature
```python
import datetime
from libtrust.keys.ec_key import generate_private_key
from libtrust.jsonsign import JSONSignature

# Generate a EC P256 private key
ec_key = generate_private_key("P-256")

your_content = {
    "author": "shabbywu(shabbywu@qq.com)"
}

# New a JSONSignature
js = JSONSignature.new(your_content)

# signature
js.sign(ec_key, dt=datetime.datetime.utcfromtimestamp(0))

jws = js.to_jws()

loaded_js = JSONSignature.from_jws(jws)

assert js == loaded_js
assert js.verify() == loaded_js.verify()
```

#### Serialize/Deserialize a self-signed JSON signature
```python
import json
import datetime
from libtrust.keys.ec_key import generate_private_key
from libtrust.jsonsign import JSONSignature

# Generate a EC P256 private key
ec_key = generate_private_key("P-256")

your_content = {
    "author": "shabbywu(shabbywu@qq.com)"
}

# New a JSONSignature
js = JSONSignature.new(your_content)

# signature
js.sign(ec_key, dt=datetime.datetime.utcfromtimestamp(0))

pretty_signature = js.to_pretty_signature("signatures")
loaded_js = js.from_pretty_signature(pretty_signature)

assert js.verify() == loaded_js.verify()
assert json.loads(pretty_signature)["author"] == "shabbywu(shabbywu@qq.com)"
```

## Copyright and license

Code and documentation copyright 2021 shabbywu(shabbywu@qq.com).   
Code released under the Apache 2.0 license.

## Reference

- [docker/libtrust](https://github.com/distribution/distribution/tree/main/vendor/github.com/docker/libtrust)
- [realityone/libtrust-py](https://github.com/realityone/libtrust-py)
