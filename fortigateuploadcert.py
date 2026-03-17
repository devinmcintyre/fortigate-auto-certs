import requests
import base64
import argparse
import json
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def safe_json(response):
    """
    Parse JSON response or exit on error.
    """
    try:
        return response.json()
    except json.JSONDecodeError:
        print("Error: Expected JSON, got:\n", response.text)
        sys.exit(1)


def api_request(method, args, endpoint, **kwargs):
    """
    Helper to make authenticated requests to FortiGate.
    """
    url = f"https://{args.fortigateIP}{endpoint}"
    headers = {
        "Authorization": f"Bearer {args.apiKey}",
        "Accept": "application/json"
    }
    if 'json' in kwargs:
        headers["Content-Type"] = "application/json"

    resp = requests.request(method, url, headers=headers, verify=False, **kwargs)
    return resp, safe_json(resp)


def get_current_admin(args):
    """
    Return the name of the current admin-server-cert.
    """
    _, global_cfg = api_request("GET", args, "/api/v2/cmdb/system/global")
    return global_cfg.get("results", {}).get("admin-server-cert")


def get_current_sslvpn_cert(args):
    """
    Return the current SSL-VPN servercert name.
    """
    _, sslvpn_cfg = api_request(
        "GET", args,
        "/api/v2/cmdb/vpn.ssl/settings",
        params={"datasource": 1, "vdom": "root"}
    )
    results = sslvpn_cfg.get("results", {})
    servercert = results.get("servercert")
    # servercert can be a dict {"q_origin_key": "..."} or a plain string depending on firmware
    if isinstance(servercert, dict):
        return servercert.get("q_origin_key")
    return servercert


def get_current_user_auth_cert(args):
    """
    Return the current user auth-cert name.
    """
    _, user_cfg = api_request(
        "GET", args,
        "/api/v2/cmdb/user/setting",
        params={"datasource": 1, "with_meta": 1, "vdom": "root"}
    )
    results = user_cfg.get("results", {})
    auth_cert = results.get("auth-cert")
    # auth-cert can be a dict {"q_origin_key": "..."} or a plain string depending on firmware
    if isinstance(auth_cert, dict):
        return auth_cert.get("q_origin_key")
    return auth_cert


def reset_admin_cert(args):
    """
    Temporarily switch admin-server-cert to 'self-sign'.
    """
    api_request(
        "PUT", args,
        "/api/v2/cmdb/system/global",
        json={"admin-server-cert": "self-sign"}
    )
    print("Temporarily switched admin-server-cert to 'self-sign'.")


def reset_sslvpn_cert(args):
    """
    Temporarily switch SSL-VPN servercert to 'Fortinet_Factory'.
    Returns the original cert name so it can be restored later.
    """
    current = get_current_sslvpn_cert(args)
    if current != args.certName:
        print(f"SSL-VPN servercert is '{current}', not '{args.certName}' – skipping reset.")
        return None

    api_request(
        "PUT", args,
        "/api/v2/cmdb/vpn.ssl/settings",
        params={"datasource": 1, "vdom": "root"},
        json={"servercert": {"q_origin_key": "Fortinet_Factory"}}
    )
    print(f"Temporarily switched SSL-VPN servercert to 'Fortinet_Factory'.")
    return current


def reset_general_cert(args):
    """
    Reset VIPs and SSL/SSH profiles using the cert. Detect payload format per device.
    Returns two lists of tuples: (name, is_list_format).
    """
    vip_items = []
    _, vip_data = api_request(
        "GET", args,
        f"/api/v2/cmdb/firewall/vip/?filter=ssl-certificate=={args.certName}"
    )
    for entry in vip_data.get('results', []):
        name = entry.get('name')
        val = entry.get('ssl-certificate')
        use_list = isinstance(val, list)
        vip_items.append((name, use_list))
        payload = {"ssl-certificate": [{"name": "Fortinet_SSL"}]} if use_list else {"ssl-certificate": "Fortinet_SSL"}
        api_request(
            "PUT", args,
            f"/api/v2/cmdb/firewall/vip/{name}",
            json=payload
        )
        print(f"VIP '{name}' switched to 'Fortinet_SSL'.")

    prof_items = []
    _, prof_data = api_request(
        "GET", args,
        f"/api/v2/cmdb/firewall/ssl-ssh-profile/?filter=server-cert=={args.certName}"
    )
    for entry in prof_data.get('results', []):
        name = entry.get('name')
        val = entry.get('server-cert')
        use_list = isinstance(val, list)
        prof_items.append((name, use_list))
        payload = {"server-cert": [{"name": "Fortinet_SSL"}]} if use_list else {"server-cert": "Fortinet_SSL"}
        api_request(
            "PUT", args,
            f"/api/v2/cmdb/firewall/ssl-ssh-profile/{name}",
            json=payload
        )
        print(f"Profile '{name}' switched to 'Fortinet_SSL'.")

    return vip_items, prof_items


def delete_cert(args):
    """
    Delete the certificate if it exists.
    """
    _, cert_info = api_request(
        "GET", args,
        f"/api/v2/cmdb/vpn.certificate/local/{args.certName}"
    )
    if cert_info.get("status") == "success":
        _, del_res = api_request(
            "DELETE", args,
            f"/api/v2/cmdb/vpn.certificate/local/{args.certName}"
        )
        if del_res.get("revision_changed"):
            print(f"Old certificate '{args.certName}' deleted.")
        else:
            print(f"Failed to delete old certificate '{args.certName}'. CLI error: {del_res.get('cli_error')}")


def upload_cert(args):
    """
    Upload a new PKCS#12 certificate.
    """
    b64 = base64.b64encode(open(args.fileName, 'rb').read()).decode()
    form = {
        'type': (None, 'pkcs12'),
        'scope': (None, 'global'),
        'certname': (None, args.certName),
        'file_content': (None, b64),
        'password': (None, args.certPass)
    }
    url_path = "/api/v2/monitor/vpn-certificate/local/import"
    resp = requests.post(
        f"https://{args.fortigateIP}{url_path}",
        headers={
            "Authorization": f"Bearer {args.apiKey}",
            "Accept": "application/json"
        },
        files=form,
        verify=False
    )
    res = safe_json(resp)
    if res.get("status") == "success":
        print(f"New certificate '{args.certName}' uploaded.")
    else:
        print("Upload failed:", res)
        sys.exit(1)


def restore_admin_cert(args):
    """
    Restore admin-server-cert to the renewed certificate.
    """
    api_request(
        "PUT", args,
        "/api/v2/cmdb/system/global",
        json={"admin-server-cert": args.certName}
    )
    print(f"Restored admin-server-cert to '{args.certName}'.")


def restore_sslvpn_cert(args):
    """
    Restore SSL-VPN servercert to the renewed certificate.
    """
    api_request(
        "PUT", args,
        "/api/v2/cmdb/vpn.ssl/settings",
        params={"datasource": 1, "vdom": "root"},
        json={"servercert": {"q_origin_key": args.certName}}
    )
    print(f"Restored SSL-VPN servercert to '{args.certName}'.")


def reset_user_auth_cert(args):
    """
    Temporarily switch user/setting auth-cert to 'Fortinet_Factory'.
    Returns the original cert name so it can be restored later, or None if not in use.
    """
    current = get_current_user_auth_cert(args)
    if current != args.certName:
        print(f"User auth-cert is '{current}', not '{args.certName}' – skipping reset.")
        return None

    api_request(
        "PUT", args,
        "/api/v2/cmdb/user/setting",
        params={"datasource": 1, "with_meta": 1, "vdom": "root"},
        json={"auth-cert": {"q_origin_key": "Fortinet_Factory"}}
    )
    print("Temporarily switched user auth-cert to 'Fortinet_Factory'.")
    return current


def restore_user_auth_cert(args):
    """
    Restore user/setting auth-cert to the renewed certificate.
    """
    api_request(
        "PUT", args,
        "/api/v2/cmdb/user/setting",
        params={"datasource": 1, "with_meta": 1, "vdom": "root"},
        json={"auth-cert": {"q_origin_key": args.certName}}
    )
    print(f"Restored user auth-cert to '{args.certName}'.")


def restore_general_cert(args, vip_items, prof_items):
    """
    Restore VIPs and profiles to use the renewed certificate.
    """
    for name, is_list in vip_items:
        payload = {"ssl-certificate": [{"name": args.certName}]} if is_list else {"ssl-certificate": args.certName}
        api_request(
            "PUT", args,
            f"/api/v2/cmdb/firewall/vip/{name}",
            json=payload
        )
        print(f"VIP '{name}' restored to '{args.certName}'.")
    for name, is_list in prof_items:
        payload = {"server-cert": [{"name": args.certName}]} if is_list else {"server-cert": args.certName}
        api_request(
            "PUT", args,
            f"/api/v2/cmdb/firewall/ssl-ssh-profile/{name}",
            json=payload
        )
        print(f"Profile '{name}' restored to '{args.certName}'.")


def main():
    parser = argparse.ArgumentParser(
        description="Rotate a PKCS#12 cert on FortiGate when renewed"
    )
    parser.add_argument("fortigateIP", help="FortiGate host or IP")
    parser.add_argument("apiKey", help="API token for FortiGate admin user")
    parser.add_argument("certName", help="Certificate name (<=35 chars)")
    parser.add_argument("certPass", help="Password for the PKCS#12 file")
    parser.add_argument("fileName", help="Path to the .p12 file to upload")
    args = parser.parse_args()
    args.certName = args.certName[:35]

    # --- Pre-flight: check what currently uses this cert ---
    current_admin    = get_current_admin(args)
    sslvpn_reset     = reset_sslvpn_cert(args)      # returns cert name if reset was needed, else None
    user_auth_reset  = reset_user_auth_cert(args)   # returns cert name if reset was needed, else None

    if current_admin == args.certName:
        reset_admin_cert(args)

    vip_items, prof_items = reset_general_cert(args)

    # --- Replace the certificate ---
    delete_cert(args)
    upload_cert(args)

    # --- Restore everything ---
    if current_admin == args.certName:
        restore_admin_cert(args)

    if sslvpn_reset is not None:
        restore_sslvpn_cert(args)

    if user_auth_reset is not None:
        restore_user_auth_cert(args)

    restore_general_cert(args, vip_items, prof_items)


if __name__ == "__main__":
    main()