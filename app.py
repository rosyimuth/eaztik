import streamlit as st
import paramiko
from streamlit_option_menu import option_menu
import socket 
import ipaddress

# Konfigurasi halaman
st.set_page_config(page_title="EazT!k", layout="centered", page_icon="favicon.svg")

# Inisialisasi session state jika belum ada
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'IP' not in st.session_state:
    st.session_state.IP = ""
if 'user' not in st.session_state:
    st.session_state.user = "admin"
if 'passwd' not in st.session_state:
    st.session_state.passwd = ""
if 'port' not in st.session_state:
    st.session_state.port = 22

# Cek apakah pengguna sudah login berdasarkan query params
if st.query_params.get("logged_in") == "true":
    st.session_state.logged_in = True

# ================== HALAMAN CONNECT ==================
def login_page():
    st.markdown("<h1 style='text-align: center;'>🔗 Connect EazT!k</h1>", unsafe_allow_html=True)

    IP = st.text_input("Masukkan IP Address Mikrotik", 
                       value=st.session_state.IP, 
                       placeholder="Masukkan IP Address")
    
    user = st.text_input("Masukkan Username", 
                         value=st.session_state.user, 
                         placeholder="Masukkan username (default: admin)")
    
    passwd = st.text_input("Masukkan Password", 
                           type="password", 
                           placeholder="Masukkan password")

    port = st.number_input("Masukkan Port", 
                           min_value=1, 
                           max_value=65535, 
                           value=st.session_state.port, 
                           placeholder="Default: 22")

    if st.button("Connect"):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(IP, username=user, password=passwd, port=int(port))
            st.success(f'✅ SSH Berhasil Terkoneksi ke {IP}')

            # Simpan informasi login di session state
            st.session_state.logged_in = True
            st.session_state.IP = IP
            st.session_state.user = user
            st.session_state.passwd = passwd  # Simpan password agar bisa digunakan kembali
            st.session_state.port = int(port)
            st.query_params["logged_in"] = "true"  # Menyimpan status login di query params

            st.rerun()
        except paramiko.AuthenticationException:
            st.error('❌ Gagal! Username atau password salah.', icon="🚨")
        except paramiko.SSHException as e:
            st.error(f'⚠️ Kesalahan SSH: {str(e)}', icon="⚠️")
        except paramiko.ssh_exception.NoValidConnectionsError:
            st.error(f'❌ Tidak dapat terhubung ke {IP}. Periksa IP dan port.', icon="⚠️")
        except Exception as e:
            st.error(f'❌ Gagal terkoneksi! {str(e)}', icon="⚠️")
            st.session_state.logged_in = False

# Jika belum login, tampilkan halaman login
if not st.session_state.get("logged_in", False):
    login_page()
    st.stop()

# Sidebar dan menu
st.sidebar.image("EazT!k.svg", use_container_width=True)

with st.sidebar:
    selected = option_menu('',
                           ['Dashboard', 'IP Address', 'Routes', 'Wireless', 
                            'DHCP Server', 'DNS', 'Firewall'],
                           icons=["house-door", "plug", "router", "wifi", "hdd", "cloud", "lock"],
                           default_index=0)

if st.sidebar.button("Disconnect"):
    st.session_state.logged_in = False
    st.session_state.IP = ""
    st.session_state.user = "admin"
    st.session_state.passwd = ""  # Hapus password dari session
    st.session_state.port = 22
    del st.query_params["logged_in"]  # Hapus status login dari query params
    st.rerun()

# ================== HALAMAN DASHBOARD ==================
if selected == 'Dashboard':
    st.title(f"Selamat Datang {st.session_state.get('IP', 'User')}")
    
    # Menambahkan subjudul untuk status
    st.subheader("Status Perangkat")
    # Menampilkan ringkasan status perangkat
    col1, col2 = st.columns(2)
    col1.metric("📡 IP Address", st.session_state.get('IP', 'Tidak tersedia'))
    col2.metric("🌐 Status Koneksi", "Terhubung" if st.session_state.get('Connected', True) else "Terputus", delta="🟢" if st.session_state.get('Connected', True) else "🔴")

    # Hanya satu kolom untuk tombol
    col1 = st.columns(1)[0]  # Ambil elemen pertama dari list kolom
    if col1.button("🔍 Cek Status Router"):
        st.success("Status router: Aktif ✅")

# ================== HALAMAN KONFIGURASI IP ADDRESS ==================
if selected == 'IP Address':
    st.title('Konfigurasi IP Address')

    # Input untuk IP Address
    ip_address = st.text_input("Masukkan IP Address", placeholder="192.168.88.1/24", help="Masukkan alamat IP dengan subnet mask yang sesuai untuk perangkat ini")

    # Pilihan untuk memilih interface
    interface = st.selectbox("Pilih Interface", ["ether1", "ether2", "ether3", "ether4", "ether5", "wlan1"], help="Pilih interface jaringan yang akan digunakan")

    connect = st.button("Proses")

    if connect:
        # Mengecek apakah IP Address mengandung CIDR
        if '/' not in ip_address:
            # Jika tidak ada CIDR, tambahkan default /24
            ip_address = ip_address + "/24"
            st.warning("⚠️ CIDR tidak ditemukan. Menambahkan default /24 pada IP Address.")

        try:
            # Memeriksa apakah format IP Address valid (termasuk subnet mask dalam format CIDR)
            ip_obj = ipaddress.ip_interface(ip_address)  # Memastikan format CIDR yang benar

            # Inisialisasi SSH client
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(st.session_state.IP, username=st.session_state.user, 
                           password=st.session_state.passwd, port=st.session_state.port)

            # Tambahkan IP Address ke interface yang dipilih
            client.exec_command(f"/ip address add address={ip_address} interface={interface}")
            
            st.success(f"✅ IP {ip_address} berhasil dikonfigurasi di interface {interface}.")
        except ValueError:
            # Jika format IP Address tidak valid
            st.error("⚠️ Format IP Address salah. Pastikan formatnya benar dengan CIDR (contoh: 192.168.1.1/24).")
        except Exception as e:
            st.error(f"⚠️ Gagal konfigurasi IP Address: {str(e)}")

# ================== HALAMAN KONFIGURASI ROUTES ==================
if selected == 'Routes':
    st.title('Konfigurasi Routes')

    # Input untuk Destination Address dan Gateway
    dst_address = st.text_input("Masukkan Destination Address", placeholder="0.0.0.0/0", help="Masukkan alamat tujuan untuk rute ini")
    gateway = st.text_input("Masukkan Gateway", placeholder="192.168.88.254", help="Masukkan alamat IP gateway yang digunakan untuk keluar dari jaringan lokal Anda")

    connect = st.button("Proses")

    if connect and dst_address and gateway:
        try:
            # Inisialisasi SSH client
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(st.session_state.IP, username=st.session_state.user, 
                           password=st.session_state.passwd, port=st.session_state.port)

            # Menambahkan default route dengan destination address dan gateway yang dimasukkan
            client.exec_command(f"/ip route add dst-address={dst_address} gateway={gateway}")
            
            st.success(f"✅ Route dengan Destination Address {dst_address} dan Gateway {gateway} berhasil dikonfigurasi.")
        except Exception as e:
            st.error(f"⚠️ Gagal konfigurasi Route: {str(e)}")

# ================== HALAMAN KONFIGURASI WIRELESS ==================
if selected == 'Wireless':
    st.title('Konfigurasi Wireless')
    ssid = st.text_input("Masukkan SSID Wireless Baru", placeholder="Masukkan SSID Wireless", help="Masukkan nama jaringan Wi-Fi Anda.")
    auth = st.text_input("Masukkan Password Wireless Baru", type="password", placeholder="Masukkan Password Wireless", help="Masukkan kata sandi untuk jaringan Wi-Fi Anda")
    interface = st.selectbox("Pilih Interface Wireless", ["wlan1", "wlan2"], help="Pilih interface yang terhubung ke jaringan Wi-Fi")  # Pilih interface wireless
    connect = st.button("Proses")

    if connect:
        try:
            # Membuat SSH client dan menghubungkan ke perangkat MikroTik
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(st.session_state.IP, username=st.session_state.user, 
                           password=st.session_state.passwd, port=st.session_state.port)

            # Menampilkan daftar interface wireless yang ada untuk memverifikasi koneksi
            stdin, stdout, stderr = client.exec_command("/interface wireless print")
            interfaces = stdout.read().decode()

            # Memeriksa apakah interface yang dipilih ada dalam daftar
            if interface in interfaces:
                # Mengonfirmasi apakah security profile sudah ada
                stdin, stdout, stderr = client.exec_command("/interface wireless security-profiles print")
                existing_profiles = stdout.read().decode()

                # Membuat nama security profile baru jika sudah ada yang sama
                new_profile_name = f"passwd_wifi_{len(existing_profiles.splitlines()) + 1}"
                
                # Menambahkan security profile dengan WPA dan WPA2 PSK
                stdin, stdout, stderr = client.exec_command(f'/interface wireless security-profiles add name={new_profile_name} '
                                                            f'authentication-types=wpa2-psk,wpa-psk '
                                                            f'wpa2-pre-shared-key={auth} wpa-pre-shared-key={auth}')
                # Membaca output dari perintah untuk debugging
                st.write(stdout.read().decode())  # Untuk melihat hasil output
                st.write(stderr.read().decode())  # Untuk melihat error jika ada

                # Mengonfigurasi SSID, mode wireless, dan security profile pada interface yang dipilih
                stdin, stdout, stderr = client.exec_command(f'/interface wireless set {interface} ssid={ssid} '
                                                            f'mode=ap-bridge security-profile={new_profile_name}')
                # Membaca output dari perintah untuk debugging
                st.write(stdout.read().decode())  # Untuk melihat hasil output
                st.write(stderr.read().decode())  # Untuk melihat error jika ada

                st.success(f"✅ Wireless {ssid} pada interface {interface} berhasil dikonfigurasi dengan profile {new_profile_name}.")
            else:
                # Menambahkan interface wireless baru jika tidak ada
                st.write(f"⚠️ Interface {interface} tidak ditemukan. Menambahkan interface baru...")

                # Menambahkan interface wireless baru
                stdin, stdout, stderr = client.exec_command(f"/interface wireless add name={interface} disabled=no")
                st.write(stdout.read().decode())  # Untuk melihat hasil output
                st.write(stderr.read().decode())  # Untuk melihat error jika ada

                # Mengonfirmasi apakah security profile sudah ada
                stdin, stdout, stderr = client.exec_command("/interface wireless security-profiles print")
                existing_profiles = stdout.read().decode()

                # Membuat nama security profile baru jika sudah ada yang sama
                new_profile_name = f"passwd_wifi_{len(existing_profiles.splitlines()) + 1}"

                # Menambahkan security profile dengan WPA dan WPA2 PSK
                stdin, stdout, stderr = client.exec_command(f'/interface wireless security-profiles add name={new_profile_name} '
                                                            f'authentication-types=wpa2-psk,wpa-psk '
                                                            f'wpa2-pre-shared-key={auth} wpa-pre-shared-key={auth}')
                st.write(stdout.read().decode())  # Untuk melihat hasil output
                st.write(stderr.read().decode())  # Untuk melihat error jika ada

                # Mengonfigurasi SSID, mode wireless, dan security profile pada interface yang dipilih
                stdin, stdout, stderr = client.exec_command(f'/interface wireless set {interface} ssid={ssid} '
                                                            f'mode=ap-bridge security-profile={new_profile_name}')
                st.write(stdout.read().decode())  # Untuk melihat hasil output
                st.write(stderr.read().decode())  # Untuk melihat error jika ada

                st.success(f"✅ Wireless {ssid} pada interface {interface} berhasil dikonfigurasi dengan profile {new_profile_name}.")
                
        except Exception as e:
            st.error(f"⚠️ Gagal konfigurasi Wireless: {str(e)}")

# ================== HALAMAN KONFIGURASI DHCP SERVER ==================
if selected == "DHCP Server":
    st.title("Konfigurasi DHCP Server")

    # Pilih Interface untuk DHCP
    interface = st.selectbox("Pilih Interface untuk DHCP", ["ether1", "ether2", "ether3", "ether4", "ether5", "wlan1"], help="Pilih interface jaringan tempat DHCP akan diaktifkan")

    # Masukkan DHCP Address Space secara manual
    dhcp_space = st.text_input("Masukkan DHCP Address Space", placeholder="192.168.88.0/24", help="Masukkan rentang alamat IP yang akan digunakan oleh DHCP")

    # Masukkan Lease Time
    lease_time = st.text_input("Masukkan Lease Time", placeholder="1h", 
    help="Waktu sewa IP oleh perangkat. Format: s (detik), m (menit), h (jam), d (hari)")

    connect = st.button("Proses")

    if connect:
        try:
            # Mengonversi DHCP Address Space ke objek network
            network = ipaddress.IPv4Network(dhcp_space, strict=False)
            
            # Menghitung rentang IP untuk DHCP
            dhcp_start = str(network.network_address + 2)  # IP pertama yang bisa digunakan
            dhcp_end = str(network.network_address + network.num_addresses - 3)  # IP terakhir yang bisa digunakan
            
            # DNS yang digunakan
            dns = "8.8.8.8"
            
            # Gateway, alamat terakhir dalam subnet (/24) biasanya .254
            gateway = str(network.network_address + network.num_addresses - 2)

            # SSH client untuk koneksi MikroTik
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(st.session_state.IP, username=st.session_state.user, password=st.session_state.passwd, port=st.session_state.port)

            # Periksa apakah address pool sudah ada atau buat baru
            pool_check_command = f"/ip pool print where name=dhcp_pool"
            stdin, stdout, stderr = client.exec_command(pool_check_command)
            output = stdout.read().decode('utf-8')

            if "dhcp_pool" not in output:
                # Konfigurasi address pool jika belum ada
                pool_command = f"/ip pool add name=dhcp_pool ranges={dhcp_start}-{dhcp_end}"
                client.exec_command(pool_command)

            # Konfigurasi DHCP Server
            dhcp_command = f"/ip dhcp-server add address-pool=dhcp_pool interface={interface} lease-time={lease_time}"
            client.exec_command(dhcp_command)

            # Set DNS dan Gateway untuk DHCP
            dns_command = f"/ip dhcp-server network add address={network.network_address} gateway={gateway} dns-server={dns}"
            client.exec_command(dns_command)

            st.success(f"✅ DHCP Server berhasil dikonfigurasi di interface {interface} dengan IP Range {dhcp_start}-{dhcp_end}. DNS: {dns}, Gateway: {gateway}.")
        except Exception as e:
            st.error(f"⚠️ Gagal konfigurasi DHCP Server: {str(e)}")


# ================== HALAMAN KONFIGURASI DNS ==================
if selected == 'DNS':
    st.title('Konfigurasi DNS')
    
    # Pilihan mode konfigurasi DNS
    dns_mode = st.radio("Pilih Mode DNS:", ("Otomatis", "Manual"), help="Pilih apakah ingin menggunakan DNS otomatis atau mengatur secara manual")
    
    # Default DNS Google jika mode otomatis dipilih
    if dns_mode == "Otomatis":
        dns_server = "8.8.8.8,8.8.4.4"
        st.info("Menggunakan DNS Google: 8.8.8.8 dan 8.8.4.4")
    else:
        dns_server = st.text_input("Masukkan DNS Server", placeholder="1.1.1.1", help="Masukkan alamat DNS yang ingin digunakan")
    
    connect = st.button("Proses")
    
    if connect:
        try:
            # Koneksi SSH ke router
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(st.session_state.IP, username=st.session_state.user, 
                           password=st.session_state.passwd, port=st.session_state.port)
            
            # Menambahkan DNS Server
            command = f'/ip dns set servers={dns_server}'
            client.exec_command(command)
            
            st.success(f"✅ DNS Server {dns_server} berhasil ditambahkan.")
        except Exception as e:
            st.error(f"⚠️ Gagal menambahkan DNS Server: {str(e)}")

# ================== HALAMAN KONFIGURASI FIREWALL ==================
if selected == 'Firewall':
    st.title('Konfigurasi Firewall')
    
    # Input URL dengan tooltip
    url = st.text_input("Masukkan URL untuk diblokir atau diizinkan", placeholder="Masukkan URL", help="Masukkan URL yang ingin dikonfigurasi dalam firewall")
    
    # Pilih Aksi dengan tooltip
    action = st.selectbox("Pilih Aksi", ["Accept", "Drop", "Reject"], help="Pilih tindakan yang akan diterapkan pada URL yang dimasukkan")
    
    # Keterangan tentang aksi
    if action == "Accept":
        st.info("✅ Accept: Mengizinkan URL tersebut untuk diakses.")
    elif action == "Drop":
        st.info("⚠️ Drop: Memblokir URL tersebut tanpa memberi pemberitahuan.")
    elif action == "Reject":
        st.info("❌ Reject: Memblokir URL tersebut dan memberi pemberitahuan bahwa akses ditolak.")
    
    # Tombol Proses
    connect = st.button("Proses")

    if connect and url:
        try:
            # Pastikan URL tidak berisi 'https://' atau 'http://'
            url_clean = url.replace("https://", "").replace("http://", "").split('/')[0]

            # Konversi URL ke daftar IP Address
            try:
                ip_addresses = list(set(
                    info[4][0] for info in socket.getaddrinfo(url_clean, None)
                ))
            except socket.gaierror:
                st.error(f"⚠️ Tidak dapat mengonversi {url} ke alamat IP.")
                ip_addresses = []

            if ip_addresses:
                # Koneksi SSH ke MikroTik
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(st.session_state.IP, username=st.session_state.user, 
                            password=st.session_state.passwd, port=st.session_state.port)

                # Loop melalui setiap IP dan tambahkan aturan firewall
                for ip_address in ip_addresses:
                    command = f"/ip firewall filter add chain=forward dst-address={ip_address} action={action.lower()}"
                    stdin, stdout, stderr = client.exec_command(command)

                    # Cek Error Output
                    error_output = stderr.read().decode()
                    if error_output:
                        st.error(f"⚠️ Gagal konfigurasi Firewall untuk {ip_address}: {error_output}")
                    else:
                        st.success(f"✅ URL {url} ({ip_address}) berhasil dikonfigurasi dengan aksi {action}.")
                
                client.close()
        except Exception as e:
            st.error(f"⚠️ Gagal konfigurasi Firewall: {str(e)}")
