import pytest


@pytest.fixture
def django_example_manifest():
    return r"""{
   "schemaVersion": 1,
   "name": "ibmcom/busybox",
   "tag": "1.30.1",
   "architecture": "amd64",
   "fsLayers": [
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:697743189b6d255069caf6c455be10c7f8cae8076c6f94d224ae15cd41420e87"
      }
   ],
   "history": [
      {
         "v1Compatibility": "{\"architecture\":\"amd64\",\"config\":{\"Hostname\":\"\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":false,\"AttachStdout\":false,\"AttachStderr\":false,\"Tty\":false,\"OpenStdin\":false,\"StdinOnce\":false,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"Cmd\":[\"sh\"],\"ArgsEscaped\":true,\"Image\":\"sha256:896f6e65107acffcae30fe593503aebf407fc30ad4566a8db04921dbfb6c0721\",\"Volumes\":null,\"WorkingDir\":\"\",\"Entrypoint\":null,\"OnBuild\":null,\"Labels\":null},\"container\":\"197cb47b0e98a00daefcb62c5fa84634792dd22f11aa29bc95fdd4e10d654d30\",\"container_config\":{\"Hostname\":\"197cb47b0e98\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":false,\"AttachStdout\":false,\"AttachStderr\":false,\"Tty\":false,\"OpenStdin\":false,\"StdinOnce\":false,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"Cmd\":[\"/bin/sh\",\"-c\",\"#(nop) \",\"CMD [\\\"sh\\\"]\"],\"ArgsEscaped\":true,\"Image\":\"sha256:896f6e65107acffcae30fe593503aebf407fc30ad4566a8db04921dbfb6c0721\",\"Volumes\":null,\"WorkingDir\":\"\",\"Entrypoint\":null,\"OnBuild\":null,\"Labels\":{}},\"created\":\"2019-02-15T00:19:37.830935034Z\",\"docker_version\":\"18.06.1-ce\",\"id\":\"2381428bfa58cc3943f86991d9d4cea22161cc460e5b0c7a0ca27e3b19043147\",\"os\":\"linux\",\"parent\":\"4c29dc6d938e0f41ed1f74a644d228b8c2ac120552a81d86ba576e149a645928\",\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"4c29dc6d938e0f41ed1f74a644d228b8c2ac120552a81d86ba576e149a645928\",\"created\":\"2019-02-15T00:19:37.703602988Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) ADD file:9ce77bda0ecf8a7f559c143ea91876057a8684775239a68639198fe64d38ca0c in / \"]}}"
      }
   ],
   "signatures": [
      {
         "header": {
            "jwk": {
               "crv": "P-256",
               "kid": "2OYJ:FCRP:7MGM:ZDBE:25UO:7LO7:TEAK:MGXY:BOHH:N666:2KVT:CEAP",
               "kty": "EC",
               "x": "aKznE1VBHSq3wv0t5RtCsL71i8mqAi1gVD-q5hxBb5g",
               "y": "t-jITjF-vB12f3fplbnBYf6NB9a5FW1hR9UVBqa3-oo"
            },
            "alg": "ES256",
            "chain": []
         },
         "signature": "uf_fQuV6sqUP6ANxjZhOUimbBpU9ixdh_j9H69bMwyw5zG6NQAQ77GYz4HU8EE1iqA0G8rLSqDdzpj45blgPcQ",
         "protected": "eyJmb3JtYXRMZW5ndGgiOjIxMzEsImZvcm1hdFRhaWwiOiJDbjAiLCJ0aW1lIjoiMjAyMS0xMi0wNFQwNzo0NTo0NVoifQ"
      }
   ]
}"""


@pytest.fixture
def django_example_manifest_no_indent():
    return r"""{
   "schemaVersion": 1,
   "name": "ibmcom/busybox",
   "tag": "1.30.1",
   "architecture": "amd64",
   "fsLayers": [
      {
         "blobSum": "sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4"
      },
      {
         "blobSum": "sha256:697743189b6d255069caf6c455be10c7f8cae8076c6f94d224ae15cd41420e87"
      }
   ],
   "history": [
      {
         "v1Compatibility": "{\"architecture\":\"amd64\",\"config\":{\"Hostname\":\"\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":false,\"AttachStdout\":false,\"AttachStderr\":false,\"Tty\":false,\"OpenStdin\":false,\"StdinOnce\":false,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"Cmd\":[\"sh\"],\"ArgsEscaped\":true,\"Image\":\"sha256:896f6e65107acffcae30fe593503aebf407fc30ad4566a8db04921dbfb6c0721\",\"Volumes\":null,\"WorkingDir\":\"\",\"Entrypoint\":null,\"OnBuild\":null,\"Labels\":null},\"container\":\"197cb47b0e98a00daefcb62c5fa84634792dd22f11aa29bc95fdd4e10d654d30\",\"container_config\":{\"Hostname\":\"197cb47b0e98\",\"Domainname\":\"\",\"User\":\"\",\"AttachStdin\":false,\"AttachStdout\":false,\"AttachStderr\":false,\"Tty\":false,\"OpenStdin\":false,\"StdinOnce\":false,\"Env\":[\"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"],\"Cmd\":[\"/bin/sh\",\"-c\",\"#(nop) \",\"CMD [\\\"sh\\\"]\"],\"ArgsEscaped\":true,\"Image\":\"sha256:896f6e65107acffcae30fe593503aebf407fc30ad4566a8db04921dbfb6c0721\",\"Volumes\":null,\"WorkingDir\":\"\",\"Entrypoint\":null,\"OnBuild\":null,\"Labels\":{}},\"created\":\"2019-02-15T00:19:37.830935034Z\",\"docker_version\":\"18.06.1-ce\",\"id\":\"2381428bfa58cc3943f86991d9d4cea22161cc460e5b0c7a0ca27e3b19043147\",\"os\":\"linux\",\"parent\":\"4c29dc6d938e0f41ed1f74a644d228b8c2ac120552a81d86ba576e149a645928\",\"throwaway\":true}"
      },
      {
         "v1Compatibility": "{\"id\":\"4c29dc6d938e0f41ed1f74a644d228b8c2ac120552a81d86ba576e149a645928\",\"created\":\"2019-02-15T00:19:37.703602988Z\",\"container_config\":{\"Cmd\":[\"/bin/sh -c #(nop) ADD file:9ce77bda0ecf8a7f559c143ea91876057a8684775239a68639198fe64d38ca0c in / \"]}}"
      }
   ],"signatures": [{"header":{"jwk":{"crv":"P-256","kid":"2OYJ:FCRP:7MGM:ZDBE:25UO:7LO7:TEAK:MGXY:BOHH:N666:2KVT:CEAP","kty":"EC","x":"aKznE1VBHSq3wv0t5RtCsL71i8mqAi1gVD-q5hxBb5g","y":"t-jITjF-vB12f3fplbnBYf6NB9a5FW1hR9UVBqa3-oo"},"alg":"ES256","chain":[]},"signature":"uf_fQuV6sqUP6ANxjZhOUimbBpU9ixdh_j9H69bMwyw5zG6NQAQ77GYz4HU8EE1iqA0G8rLSqDdzpj45blgPcQ","protected":"eyJmb3JtYXRMZW5ndGgiOjIxMzEsImZvcm1hdFRhaWwiOiJDbjAiLCJ0aW1lIjoiMjAyMS0xMi0wNFQwNzo0NTo0NVoifQ"}]}"""
