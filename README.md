# Simple Validation Authority (simple-va)


## Who is this project for ?
This tool is for teams operating in segmented networks who need certificate revocation checks without deploying a full CA solution or exposing your root CA to this network. It provides:

- A lightweight OCSP authority authorized only to sign OCSP responses
- No direct access or exposure of your root CA
- Simple, script-friendly data formats (PEM for certs, JSON for everything else)
- A minimal Go implementation with very few dependencies
- A documented REST API for easy integration and future migration to a more powerful CA system


## Getting Started – Registering an OCSP signer

This mini-guide shows how to register a working **OCSP responder
certificate** in your REST backend 

### 1  Create a local root CA (or use the root CA in your existing PKI)

```bash
# Private key (P-256)
openssl ecparam -name prime256v1 -genkey -noout -out root.key.pem

# Self-signed root certificate, valid for 10 years
openssl req -new -x509 -key root.key.pem -sha256 -days 3650 \
            -subj "/CN=Root CA/O=Example Org" \
            -out root.crt.pem
```

### 2 Create a new CSR 
```bash
curl -sS -X POST http://localhost:8080/createnewcsr \
     -H 'Content-Type: application/json' \
     -H 'X-API-Key: 123' \
     -d '{"common_name":"deadbeaf.com"}' \
  | jq -r '.csr' > ocsp.csr.pem
```

### 3 Sign the CSR with your root CA
```bash
openssl x509 -req -in ocsp.csr.pem \
  -CA root.crt.pem -CAkey root.key.pem -CAcreateserial \
  -days 365 -sha256 -out ocsp.crt.pem \
  -extfile <(printf "keyUsage=digitalSignature\nextendedKeyUsage=OCSPSigning")
```


### 4 Upload Signed Cert 
```bash
jq -Rs -n \
   --arg sc "$(cat ocsp.crt.pem)" \
   --arg ic "$(cat root.crt.pem)" \
   '{"signed_certificate":$sc,"issuer_certificate":$ic}' \
| curl -sS -X POST http://localhost:8080/uploadsignedcert \
       -H 'Content-Type: application/json' \
       -H 'X-API-Key: 123' \
       --data @-
# expected result: HTTP 201 Created
```

Now you are ready to go !
---