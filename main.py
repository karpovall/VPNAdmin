import requests
import base64
import os
import subprocess
import json
import urllib.parse
import streamlit as st

RED = '\033[0;31m'
ORANGE = '\033[0;33m'
GREEN = '\033[0;32m'
NC = '\033[0m'
params_file = '/etc/wireguard/params'
params = {}
keys_to_ignore = ["SERVER_PRIV_KEY", "SERVER_PUB_KEY"]
PORT = next((line.strip().split("=")[1] for line in open("/etc/cloak/ckport.txt") if line.startswith("PORT=")), None)
with open('/etc/cloak/ckserver.json', 'r') as file:
    data = json.load(file)
admin_uid = data.get('AdminUID')

with open("/opt/outline/access.txt", "r") as file:
    for line in file:
        if "apiUrl" in line:
            api_base = line.split(":", 1)[1].strip()
            break

with open(params_file, 'r') as file:
    for line in file:
        key_value_pair = line.strip().split('=')
        if len(key_value_pair) == 2 and key_value_pair[0] not in keys_to_ignore:
            key, value = key_value_pair
            params[key.strip()] = value.strip()


def outline_list_all_users():
    api_url = f"{api_base}/access-keys/"
    try:
        response = requests.get(api_url, verify=False)
        response.raise_for_status()
        st.write(response.json())
    except requests.RequestException as e:
        st.write("Error:", e)


def outline_add_user():
    api_url = f"{api_base}/access-keys"
    try:
        response = requests.post(api_url, verify=False)
        response.raise_for_status()
        st.write(response.json())
    except requests.RequestException as e:
        st.write("Error:", e)


def outline_delete_user(cloak_id_to_delete_f):
    api_url = f"{api_base}/access-keys/{cloak_id_to_delete_f}"
    response = requests.delete(api_url, verify=False)
    if response.status_code == 204:
        st.write("Done")
    elif response.status_code == 404:
        st.write("Incorrect user ID")
    else:
        st.write("Error")


def wireguard_list_all_users():
    config_file_path = f"/etc/wireguard/{params.get('SERVER_WG_NIC')}.conf"

    with open(config_file_path, 'r') as file:
        lines = file.readlines()
        number_of_clients = sum(1 for line in lines if line.startswith('### Client'))

    if number_of_clients == 0:
        st.write("You have no existing clients!")
        exit(1)

    client_count = 0
    for line in lines:
        if line.startswith('### Client'):
            client_count += 1
            try:
                client_name = line.split(' ')[2].strip()
                st.write(f"{client_count}) {client_name}")
            except ValueError:
                st.write(f"Error processing line: {line.strip()}")
    return number_of_clients


def wireguard_delete_user(client_number_1):# we ask user to input client number in main
    server_wg_nic = params.get('SERVER_WG_NIC', '')
    if server_wg_nic == '':
        st.write("SERVER_WG_NIC parameter is not defined in the params file.")
        return

    number_of_clients = sum(1 for line in open(f"/etc/wireguard/{server_wg_nic}.conf") if line.startswith('### Client'))

    if number_of_clients == 0:
        st.write("\nYou have no existing clients!")
        return

    client_names = [line.split()[2] for line in open(f"/etc/wireguard/{server_wg_nic}.conf") if
                    line.startswith('### Client')]

    while True:
        client_number = int(client_number_1)
        if 1 <= int(client_number) <= number_of_clients:
            break
        else:
            st.write("Invalid input. Please enter a valid client number.")

    client_number -= 1
    client_name = client_names[client_number]

    with open(f"/etc/wireguard/{server_wg_nic}.conf", 'r') as file:
        lines = file.readlines()
    with open(f"/etc/wireguard/{server_wg_nic}.conf", 'w') as file:
        skip_next = False
        for line in lines:
            if skip_next:
                skip_next = False
                continue
            if line.strip() == f"### Client {client_name}":
                skip_next = True
                continue
            file.write(line)

    home_dir = params.get('home_dir', '/home')
    client_conf_path = f"{home_dir}/{server_wg_nic}-client-{client_name}.conf"
    subprocess.run(['rm', '-f', client_conf_path], check=True)
    st.write("Done")


def wireguard_add_user(client_name_1):
    global dot_exists
    server_pub_ip = params.get('SERVER_PUB_IP', '')
    if ":" in server_pub_ip and "[" not in server_pub_ip and "]" not in server_pub_ip:
        server_pub_ip = f"[{server_pub_ip}]"
    endpoint = f"{server_pub_ip}:{params.get('SERVER_PORT', '')}"

    client_name = client_name_1

    for dot_ip in range(2, 255):
        dot_exists = subprocess.getoutput(
            f"grep -c '{params.get('SERVER_WG_IPV4', '')[:-1]}{dot_ip}' '/etc/wireguard/{params.get('SERVER_WG_NIC', '')}.conf'")
        if int(dot_exists) == 0:
            break

    if int(dot_exists) == 1:
        st.write("")
        st.write("The subnet configured supports only 253 clients.")
        exit(1)

    client_priv_key = subprocess.getoutput("wg genkey")
    client_pub_key = subprocess.run(["wg", "pubkey"], input=client_priv_key, capture_output=True,
                                    text=True).stdout.strip()
    client_pre_shared_key = subprocess.getoutput("wg genpsk")

    home_dir = getHomeDirForClient(os.getenv("SUDO_USER"))
    client_conf_path = f"{home_dir}/wg0-client-{client_name}.conf"

    client_conf = f"""[Interface]
PrivateKey = {client_priv_key}
Address = {client_wg_ipv4}/32,{client_wg_ipv6}/128
DNS = 1.1.1.1,1.0.0.1

[Peer]
PublicKey = {client_pub_key}
PresharedKey = {client_pre_shared_key}
Endpoint = {endpoint}
AllowedIPs = 0.0.0.0/0,::/0
PersistentKeepalive = 25
"""

    with open(client_conf_path, "w") as conf_file:
        conf_file.write(client_conf)

    print("")
    print(f"Your client config file is in {client_conf_path}")
    print(f"A QR code is also generated in {client_conf_path}.png")

    with open(f"/etc/wireguard/{params.get('SERVER_WG_NIC', '')}.conf", 'a') as file:
        file.write(f"\n### Client {client_name}\n")
        file.write(f"[Peer]\n")
        file.write(f"PublicKey = {client_pub_key}\n")
        file.write(f"PresharedKey = {client_pre_shared_key}\n")
        file.write(f"AllowedIPs = {client_wg_ipv4}/32,{client_wg_ipv6}/128\n")
        file.write(f"\n")

    try:
        subprocess.run(["qrencode", "-t", "ansiutf8", "-l", "L", f"<{client_conf_path}"], check=True)
        print("")
        print("Here is your client config file as a QR Code:")
        print("")
    except FileNotFoundError:
        pass

    st.write(f"Your client config file is in {client_conf_path}")
    with open(client_conf_path, "r") as f:
        print(f.read())


def getHomeDirForClient(client_name=None):
    if not client_name:
        params_file = '/etc/wireguard/params'
        params = {}
        keys_to_ignore = ["SERVER_PRIV_KEY", "SERVER_PUB_KEY"]

        with open(params_file, 'r') as file:
            for line in file:
                key_value_pair = line.strip().split('=')
                if len(key_value_pair) == 2 and key_value_pair[0] not in keys_to_ignore:
                    key, value = key_value_pair
                    params[key.strip()] = value.strip()

        client_name = params.get('SERVER_PUB_IP', 'default_client')

    if not client_name:
        st.write("Error: getHomeDirForClient() requires a client name as argument")
        exit(1)

    # Home directory of the user, where the client configuration will be written
    if os.path.exists(f"/home/{client_name}"):
        # if client_name is a user name
        home_dir = f"/home/{client_name}"
    elif os.getenv("SUDO_USER"):
        # if not, use SUDO_USER
        if os.getenv("SUDO_USER") == "root":
            # If running sudo as root
            home_dir = "/root"
        else:
            home_dir = f"/home/{client_name}"
    else:
        # if not SUDO_USER, use /root
        home_dir = "/root"

    return home_dir


def cloak_list_all_users():
    with open("/etc/cloak/ckserver.json", "r") as f:
        data = json.load(f)
        uids = data.get("BypassUID", [])

    ckaauid = admin_uid
    uids = [uid for uid in uids if uid != ckaauid]

    st.write("Here are the list of unrestricted users:")
    for uid in uids:
        st.write(uid)
    return len(uids)


def cloak_delete_user(client_number_1):#
    UIDS = json.load(open("/etc/cloak/ckserver.json"))["BypassUID"]
    option = int(client_number_1) - 1
    uid_to_remove = UIDS[option]
    with open("/etc/cloak/ckserver.json", "r+") as f:
        data = json.load(f)
        data["BypassUID"].remove(uid_to_remove)
        f.seek(0)
        json.dump(data, f)
        f.truncate()
    st.write("Done")


def cloak_add_user(option_1, OPTION_1, OPTION_2, ckclient_name_1): #we ask user to input client name and options in input
    ckbuid_process = subprocess.run(["ck-server", "-u"], capture_output=True, text=True)
    ckbuid = ckbuid_process.stdout.strip()

    with open("/etc/cloak/ckserver.json", "r+") as f:
        data = json.load(f)
        data["BypassUID"].append(ckbuid)
        f.seek(0)
        json.dump(data, f, indent=4)
        f.truncate()

    st.write("Ok here is the UID:", ckbuid)

    option = option_1
    if option == "y":
        OPTION = OPTION_1
        ckcrypt = None
        if OPTION == "2":
            ckcrypt = "aes-128-gcm"
        elif OPTION == "3":
            ckcrypt = "aes-256-gcm"
        elif OPTION == "4":
            ckcrypt = "chacha20-poly1305"
        else:
            ckcrypt = "plain"

        with open('/etc/cloak/ckserver.json') as f:
            OPTIONS = json.load(f)['ProxyBook'].keys()

        OPTIONS = [value for value in OPTIONS if value != "LForPanel"]

        if OPTION_2 != None:
            OPTION = int(OPTION_2) - 1

        ckmethod = OPTIONS[OPTION]

        ckclient_name = ckclient_name_1
        ckpub = json.load(open('/etc/cloak/ckadminclient.json'))['PublicKey']
        ckwebaddr = "www.bing.com"

        write_client_file(ckmethod, ckcrypt, ckbuid, ckpub, ckwebaddr, ckclient_name)

        if ckmethod == "shadowsocks":
            st.write("Please wait...")
            PUBLIC_IP = requests.get("https://api.ipify.org").text
            with open('/etc/shadowsocks-rust/config.json') as f:
                config = json.load(f)
            cipher = config['method']
            Password = config['password']
            ckuid = ckbuid
            show_connection_info(PUBLIC_IP, Password, cipher, ckuid, ckpub)

        st.write(f"Sample file saved at /etc/cloak/{ckclient_name}.json")
    else:
        print(f"Ok once more here is your UID:", ckbuid)
        st.write("You can list it again later with running this script again.")

    subprocess.run(["systemctl", "restart", "cloak-server"])
    st.write("Done")


def write_client_file(ckmethod, ckcrypt, ckbuid, ckpub, ckwebaddr, ckclient_name):# for cloak_add
    data = {
        "ProxyMethod": ckmethod,
        "EncryptionMethod": ckcrypt,
        "UID": ckbuid,
        "PublicKey": ckpub,
        "ServerName": ckwebaddr,
        "NumConn": 4,
        "BrowserSig": "chrome",
        "StreamTimeout": 300
    }
    with open(f"/etc/cloak/{ckclient_name}.json", "w") as f:
        json.dump(data, f)


def show_connection_info(PUBLIC_IP, Password, cipher, ckuid, ckpub): # for cloak_add
    print("Your Server IP:", PUBLIC_IP)
    print("Password:      ", Password)
    print("Port:          ", PORT)
    print("Encryption:    ", cipher)
    print("Cloak Proxy Method:   shadowsocks")
    print("Cloak UID:            ", ckuid)
    print("Cloak Public Key:     ", ckpub)
    print("Cloak Encryption:     plain")
    print("Cloak Server Name:    Domain or ip of RedirAddr (Default bing.com)")
    print("Cloak NumConn:        4 or more")
    print("Cloak MaskBrowser:    firefox or chrome")
    print("Cloak StreamTimeout:  300")
    print("Also read more about these arguments at https://github.com/cbeuw/Cloak#client\n")
    print("Download cloak client for android from https://github.com/cbeuw/Cloak-android/releases")
    print("Download cloak client for PC from https://github.com/cbeuw/Cloak/releases\n\n")

    ckpub_encoded = base64.b64encode(ckpub.encode()).decode()
    ckuid_encoded = base64.b64encode(ckuid.encode()).decode()
    SERVER_BASE64 = f"{cipher}:{Password}"
    SERVER_BASE64 = base64.b64encode(SERVER_BASE64.encode()).decode()
    SERVER_CLOAK_ARGS = f"ck-client;UID={ckuid_encoded};PublicKey={ckpub_encoded};ServerName=bing.com;BrowserSig" \
                        f"=chrome;NumConn=4;ProxyMethod=shadowsocks;EncryptionMethod=plain;StreamTimeout=300"
    SERVER_CLOAK_ARGS = urllib.parse.quote(SERVER_CLOAK_ARGS)
    SERVER_BASE64 = f"ss://{SERVER_BASE64}@{PUBLIC_IP}:{PORT}?plugin={SERVER_CLOAK_ARGS}"
    st.write(SERVER_BASE64)


def openvpn_add_user(client_1):
    client = client_1
    if client:
        client_exists = subprocess.getoutput(
            "tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c -E '/CN={}$'".format(client))
        if client_exists == '1':
            st.write("The specified client CN was already found in easy-rsa, please choose another name.")
            return
        else:
            os.chdir("/etc/openvpn/easy-rsa/")
            subprocess.run(["./easyrsa", "build-client-full", client, "nopass"], input="yes", text=True, check=True)# cloak add run the subrocess to confirm your configurations, I add input = "yes" to skip it
            st.write("Client {} added.".format(client))

        if os.path.exists("/home/{}".format(client)):
            home_dir = "/home/{}".format(client)
        elif os.getenv("SUDO_USER"):
            if os.getenv("SUDO_USER") == "root":
                home_dir = "/root"
            else:
                home_dir = "/home/{}".format(os.getenv("SUDO_USER"))
        else:
            home_dir = "/root"

        tls_sig = None
        if "tls-crypt" in open("/etc/openvpn/server.conf").read():
            tls_sig = 1
        elif "tls-auth" in open("/etc/openvpn/server.conf").read():
            tls_sig = 2

        with open(home_dir + "/{}.ovpn".format(client), "w") as file:
            file.write("<ca>\n")
            file.write(open("/etc/openvpn/easy-rsa/pki/ca.crt").read())
            file.write("</ca>\n")

            file.write("<cert>\n")
            file.write(open("/etc/openvpn/easy-rsa/pki/issued/{}.crt".format(client)).read())
            file.write("</cert>\n")

            file.write("<key>\n")
            file.write(open("/etc/openvpn/easy-rsa/pki/private/{}.key".format(client)).read())
            file.write("</key>\n")

            if tls_sig == 1:
                file.write("<tls-crypt>\n")
                file.write(open("/etc/openvpn/tls-crypt.key").read())
                file.write("</tls-crypt>\n")
            elif tls_sig == 2:
                file.write("key-direction 1\n")
                file.write("<tls-auth>\n")
                file.write(open("/etc/openvpn/tls-auth.key").read())
                file.write("</tls-auth>\n")

        print("The configuration file has been written to {}/{}.ovpn.".format(home_dir, client))
        print("Download the .ovpn file and import it in your OpenVPN client.")


def openvpn_delete_user(client_number_1):
    number_of_clients = subprocess.getoutput("tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c '^V'")
    if number_of_clients == '0':
        st.write("")
        st.write("You have no existing clients!")
        return

    client_number = client_number_1
    while not client_number.isdigit() or int(client_number) < 1 or int(client_number) > int(number_of_clients):
        if client_number == '1':
            client_number = input("Select one client [1]: ")
        else:
            client_number = input("Select one client [1-{}]: ".format(number_of_clients))

    client = subprocess.getoutput(
        "tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep '^V' | cut -d '=' -f 2 | sed -n '{}'p".format(
            client_number))
    os.chdir("/etc/openvpn/easy-rsa/")
    subprocess.run(["./easyrsa", "--batch", "revoke", client])
    subprocess.run(["./easyrsa", "gen-crl"])
    subprocess.run(["rm", "-f", "/etc/openvpn/crl.pem"])
    subprocess.run(["cp", "/etc/openvpn/easy-rsa/pki/crl.pem", "/etc/openvpn/crl.pem"])
    subprocess.run(["chmod", "644", "/etc/openvpn/crl.pem"])
    subprocess.run(["find", "/home/", "-maxdepth", "2", "-name", "{}.ovpn".format(client), "-delete"])
    subprocess.run(["rm", "-f", "/root/{}.ovpn".format(client)])
    subprocess.run(["sed", "-i", "/^{},.*/d".format(client), "/etc/openvpn/ipp.txt"])
    subprocess.run(["cp", "/etc/openvpn/e-rsa/pki/index.txt{,.bk}"])

    st.write("")
    st.write("Certificate for client {} revoked.".format(client))
    return


def openvpn_list_all_users():
    index_file_path = "/etc/openvpn/easy-rsa/pki/index.txt"
    if not os.path.exists(index_file_path):
        st.write("Index file not found. Make sure the path is correct.")
        return

    with open(index_file_path, "r") as index_file:
        clients = []
        for line in index_file.readlines()[1:]:
            if line.startswith("V"):
                client_info = line.split("=")[1].strip()
                clients.append(client_info)
    if len(clients) == 0:
        st.write("You have no existing clients!")
        exit(1)
    for i, client in enumerate(clients, start=1):
        st.write(f"{i}) {client}")
    return len(clients)


name = st.selectbox(
    "Choose VPN",
    ("...", "OpenVPN", "Cloak", "Wireguard", "Outline")
)

if name == 'OpenVPN':
    com = st.selectbox(
        "Choose VPN",
        ("Add", "Delete", "List")
    )
    if com == "Add":
        client_1 = st.text_input("Client name:")
        if st.button("OpenVPN: Add"):
            openvpn_add_user(client_1)
    elif com == "Delete":
        number = openvpn_list_all_users()
        client_number_1 = st.text_input(f"Select one client [1-{number}]: ")
        if st.button(f"OpenVPN: Delete {client_number_1}"):
            openvpn_delete_user(client_number_1)
    elif com == "List":
        if st.button("OpenVPN: List"):
            openvpn_list_all_users()

elif name == 'Cloak':
    com = st.selectbox(
        "Choose VPN",
        ("Add", "Delete", "List")
    )
    if com == "Add":
        option_1 = st.text_input('Do you want me to generate a config file for it? (y/n)', '').lower()
        OPTION_1 = None
        OPTION_2 = None
        ckclient_name_1 = None
        if option_1 == 'y':
            st.write("1) plain")
            st.write("2) aes-128-gcm")
            st.write("3) aes-256-gcm")
            st.write("4) chacha20-poly1305")
            OPTION_1 = st.text_input("Which encryption method you want to use?[1-4]: ")
            with open('/etc/cloak/ckserver.json') as f:
                OPTIONS_1 = json.load(f)['ProxyBook'].keys()

            OPTIONS_1 = [value for value in OPTIONS_1 if value != "LForPanel"]

            for i, option_2 in enumerate(OPTIONS_1, 1):
                st.write(f"{i}) {option_2}")
            OPTION_2 = st.text_input(
                "Choose one of the forward rules to create the client file based on it. You can of course change "
                "ProxyMethod for your client by just changing it in client config file. Choose one by number:", '')
            ckclient_name_1 = st.text_input("Choose a file name for the client file: ")
        if st.button("Cloak: Add"):
            cloak_add_user(option_1, OPTION_1, OPTION_2, ckclient_name_1)
    elif com == "Delete":
        number = cloak_list_all_users()
        client_number_1 = st.text_input(f"Select one client [1-{number}]: ")
        if st.button(f"Cloak:  Delete {client_number_1}"):
            cloak_delete_user(client_number_1)
    elif com == "List":
        if st.button("Cloak: List"):
            cloak_list_all_users()


elif name == 'Wireguard':
    com = st.selectbox(
        "Wireguard: Choose operation",
        ("Add", "Delete", "List")
    )
    if com == "Add":
        while True:
            client_name_1 = st.text_input("Client name: ", '')
            client_exists = subprocess.getoutput(
                f"grep -c -E '^### Client {client_name_1}$' '/etc/wireguard/{params.get('SERVER_WG_NIC', '')}.conf'")
            if int(client_exists) != 0:
                st.write("")
                st.write(
                    f"{ORANGE}A client with the specified name was already created, please choose another name.{NC}")
                st.write("")
            else:
                break
        base_ip = '.'.join(params.get('SERVER_WG_IPV4', '').split('.')[:3])
        while True:
            dot_ip_1 = st.text_input(f"Client WireGuard IPv4: {base_ip}.", '')
            client_wg_ipv4 = f"{base_ip}.{dot_ip_1}"
            ipv4_exists = subprocess.getoutput(
                f"grep -c '{client_wg_ipv4}/32' '/etc/wireguard/{params.get('SERVER_WG_NIC', '')}.conf'")
            if int(ipv4_exists) != 0:
                st.write("")
                st.write(
                    f"{ORANGE}A client with the specified IPv4 was already created, please choose another IPv4.{NC}")
                st.write("")
            else:
                break

        base_ip = params.get('SERVER_WG_IPV6', '').split('::')[0]
        while True:
            dot_ip_2 = st.text_input(f"Client WireGuard IPv6: {base_ip}::", '')
            client_wg_ipv6 = f"{base_ip}::{dot_ip_2}"
            ipv6_exists = subprocess.getoutput(
                f"grep -c '{client_wg_ipv6}/128' '/etc/wireguard/{params.get('SERVER_WG_NIC', '')}.conf'")
            if int(ipv6_exists) != 0:
                st.write("")
                st.write(
                    f"{ORANGE}A client with the specified IPv6 was already created, please choose another IPv6.{NC}")
                st.write("")
            else:
                break

        if st.button("Wireguard: Add"):
            wireguard_add_user(client_name_1)
    elif com == "Delete":
        number = wireguard_list_all_users()
        client_number_1 = st.text_input(f"Select one client [1-{number}]: ")
        if st.button(f"Wireguard: Delete {client_number_1}"):
            wireguard_delete_user(client_number_1)

    elif com == "List":
        if st.button("Wireguard: List"):
            wireguard_list_all_users()


elif name == 'Outline':
    com = st.selectbox(
        "Outline: Choose operation",
        ("Add", "Delete", "List")
    )
    if com == "Add":
        if st.button("Outline: Add"):
            outline_add_user()
    elif com == "Delete":
        cloak_id_to_delete = st.text_input('Outline: Type user ID', '')
        if st.button(f"Outline: Delete {cloak_id_to_delete}"):
            outline_delete_user(cloak_id_to_delete)
    elif com == "List":
        if st.button("Outline: List"):
            outline_list_all_users()
