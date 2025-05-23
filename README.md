# Simple Validation Authority (simple-va)
THIS PROJECT IS CURRENTLY IN A BETA STATUS.

## Who is this project for ?
This tool is for teams operating in segmented networks who need certificate revocation checks without deploying a full CA solution or exposing your root CA to this network. It provides:

- A lightweight OCSP authority authorized only to sign OCSP responses
- No direct access or exposure of your root CA
- Simple, script-friendly data formats (PEM for certs, JSON for everything else)
- A minimal Go implementation with very few dependencies
- A documented REST API for easy integration and future migration to a more powerful CA system


---

## REST endpoint documention
Visit [swagger document](https://simple-va.de) to take a look at all provided REST API endpoint including expected json formats. 


## Getting Started – Registering an OCSP signer

This mini-guide shows how to register a working **OCSP responder
certificate** in your REST backend 

- Create a local root CA (or use the root CA in your existing PKI)

```bash
# Private key (P-256)
openssl ecparam -name prime256v1 -genkey -noout -out root.key.pem

# Self-signed root certificate, valid for 10 years
openssl req -new -x509 -key root.key.pem -sha256 -days 3650 \
            -subj "/CN=Root CA/O=Example Org" \
            -out root.crt.pem
```

- Create a new CSR 
```bash
curl -sS -X POST http://localhost:8080/createnewcsr \
     -H 'Content-Type: application/json' \
     -d '{"common_name":"deadbeaf.com"}' \
  | jq -r '.csr' > ocsp.csr.pem
```

- Sign the CSR with your root CA
```bash
openssl x509 -req -in ocsp.csr.pem \
  -CA root.crt.pem -CAkey root.key.pem -CAcreateserial \
  -days 365 -sha256 -out ocsp.crt.pem \
  -extfile <(printf "keyUsage=digitalSignature\nextendedKeyUsage=OCSPSigning")
```


- Upload Signed Cert 
```bash
jq -Rs -n \
   --arg sc "$(cat ocsp.crt.pem)" \
   --arg ic "$(cat root.crt.pem)" \
   '{"signed_certificate":$sc,"issuer_certificate":$ic}' \
| curl -sS -X POST http://localhost:8080/uploadsignedcert \
       -H 'Content-Type: application/json' \
       --data @-
# expected result: HTTP 201 Created
```


- Now you are ready to go. Revoke other certs issued by the root ca and check if everything works. 

```
openssl ocsp -issuer issuer.crt -cert server.crt \
             -url http://ocsp.example-ca.com \
             -VAfile issuer.crt \
             -nonce -text -resp_text
```


---
## Protect your private endpoints with api key authentication
- Store your API-keys in a JSON file that maps the SHA-256 hash of each key to a human-readable comment:
```
{
  "HASHED_API_KEY": "COMMENT",
}
```

For example: 
```
{
  "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3": "tim",
  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad": "service 123",
}
```

- Create a strong random key locally, for example:
```
head -c1000000 /dev/urandom | sha256sum
```

- Copy that raw key, then hash it once more to put the hash value (not the raw key) into the JSON file:
```
echo 609c2191eff864c82d3a71cfb29a411dae9febbf1c67ab561fd6970119492525 | sha256sum 
```

- In your configuration file set hashed_api_keys_path to the JSON file’s path.
If you leave the path empty (""), API-key authentication is turned off and every endpoint stays open.


# Installation
## Docker 

Checkout this [docker-compose.yaml](https://github.com/jackenbaer/simple-va/blob/main/build/docker/docker-compose.yaml) to simply getting started with a quick example. 
Remove "volumes" if you just want to get a running container. 