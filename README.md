# FortiGate automatic certificate push and renewals

Automate certificate issuance and deployment to FortiGate firewalls using [acme.sh](https://github.com/acmesh-official/acme.sh).  These scripts are built to support multiple domains and multiple FortiGate certificate renewals from one linux box.

## Overview

This toolset handles the full certificate lifecycle:

1. **`new-cert-setup.sh`** — One-time setup: creates the directory structure and prints the `acme.sh` command to run for a new domain.
2. **acme.sh** (external) — Issues the certificate via Let's Encrypt. The post-hook concatenates the key and full chain into a single `.pem` file and triggers `certmanager.sh`.
3. **`certmanager.sh`** — Converts the `.pem` to PKCS#12 (`.p12`) format and calls the Python uploader for each configured firewall.
4. **`fortigateuploadcert.py`** — Rotates the certificate on a FortiGate via its REST API: temporarily switches in-use references to a fallback cert, deletes the old cert, uploads the new one, and restores all references.

## Prerequisites

- [acme.sh](https://github.com/acmesh-official/acme.sh) installed and configured for your chosen challenge method (see below)
- `openssl` available on the system
- Python 3 with the `requests` library (`pip install requests`)
- A FortiGate API token with sufficient privileges (see [FortiGate REST API docs](https://docs.fortinet.com/document/fortigate/latest/administration-guide/940602/rest-api))

## acme.sh Challenge Methods

These scripts are not tied to any specific DNS provider or challenge type. acme.sh supports a wide range of options — use whatever fits your environment:

- **DNS-01 challenge** (recommended for wildcard certs): acme.sh has [DNS API plugins](https://github.com/acmesh-official/acme.sh/wiki/dnsapi) for over 150 providers including Azure, Cloudflare, AWS Route 53, GoDaddy, and many others.
- **HTTP-01 challenge**: Works if your server is publicly reachable. Use `--webroot` or the built-in standalone mode.
- **TLS-ALPN-01 challenge**: Useful when port 80 is unavailable.

The example commands in this README use `--dns dns_azure`, but substitute your own DNS plugin or challenge method as needed. See the [acme.sh documentation](https://github.com/acmesh-official/acme.sh/wiki) for the full list of options.

## Setup

### 1. Configure `certmanager.sh`

Edit the `API_KEYS` and `FW_IPS` arrays to match your environment:

```bash
declare -A API_KEYS
API_KEYS[fortigate1]=fortigate1_api_key_here
API_KEYS[fortigate2]=fortigate2_api_key_here

declare -A FW_IPS
FW_IPS[fortigate1]=fortigate1.company.example
FW_IPS[fortigate2]=fortigate2.company.example
```

Also change the `PASS` variable to a strong password — this is the passphrase used to protect the `.p12` file in transit:

```bash
PASS="change_me"
```

### 2. Initialize a new domain

Run `new-cert-setup.sh` with your DNS zone name and a firewall key name:

```bash
bash new-cert-setup.sh example.com fortigate1
```

This creates `/data/ssl/example.com/` and prints the `acme.sh` command to copy and run.

### 3. Run the printed acme.sh command

The printed command will look like:

```bash
acme.sh --issue --dns dns_azure -d example.com -d *.example.com \
  --post-hook "cat /root/.acme.sh/example.com_ecc/example.com.key \
               /root/.acme.sh/example.com_ecc/fullchain.cer \
               > /data/ssl/example.com/example.com.pem; \
               bash /root/lets-encrypt-scripts/certmanager.sh example.com fortigate1"
```

Replace `--dns dns_azure` with your preferred challenge method. On each renewal, acme.sh will automatically re-run the post-hook, converting and uploading the new certificate.

## How `fortigateuploadcert.py` Rotates the Certificate

The Python script performs the following steps against the FortiGate REST API:

1. Checks if the certificate is currently set as the admin HTTPS certificate — if so, temporarily switches to `self-sign`.
2. Finds any firewall VIPs and SSL/SSH inspection profiles using the old certificate and temporarily switches them to `Fortinet_SSL`.
3. Deletes the old certificate.
4. Uploads the new PKCS#12 certificate.
5. Restores the admin certificate (if it was previously using this cert).
6. Restores all VIPs and SSL/SSH profiles to the new certificate.

## File Layout

```
/data/ssl/
└── example.com/
    ├── example.com.pem    # created by acme.sh post-hook (key + fullchain)
    └── example.com.p12    # created by certmanager.sh
```

## Security Notes

- The `.p12` passphrase (`PASS`) is passed as a command-line argument to the Python script. Consider your process visibility on the host.
- The FortiGate API token should be scoped to the minimum required permissions.
- SSL verification is disabled in `fortigateuploadcert.py` (`verify=False`) to allow self-signed certs during the rotation window — use with awareness.
