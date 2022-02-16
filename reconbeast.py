import argparse
import logging
import sqlite3
import subprocess
import os
import re
import requests

from bs4 import BeautifulSoup
from dataclasses import field, dataclass
from dataclasses_json import config, dataclass_json, Undefined
from typing import Optional, List
from rich.console import Console

CONSOLE = Console()

# subdomain_tools = ['findomain','subfinder','assetfinder','amass','chaos_client','rapiddns']
subdomain_tools = ['findomain','rapiddns']
output_to_terminal = ['assetfinder', 'gauplus']
temp_path = os.path.join(os.path.dirname(__file__), "temp")
os.makedirs(f"{temp_path}",exist_ok=True)
subdomains_list = []

def print_banner():
    print("""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██████╗ ███████╗ █████╗ ███████╗████████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔══██╗██╔════╝██╔══██╗██╔════╝╚══██╔══╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██████╔╝█████╗  ███████║███████╗   ██║   
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██╔══██╗██╔══╝  ██╔══██║╚════██║   ██║   
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██████╔╝███████╗██║  ██║███████║   ██║   
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   
    """)
    # print("\033[1mDeveloped by ValluvarSploit\033[0m\n")

def get_arguments():
    parser = argparse.ArgumentParser()
    # parser.add_argument('-d', '--domain', default="example.com", help='Domain name')
    parser.add_argument('-d', '--domain', help='Domain name')
    parser.add_argument('-df', '--domain_file', help='Multiple domain names')
    # parser.add_argument('-df', '--domain_file', default='domain.txt', help='Multiple domain names')
    parser.add_argument('-ck', '--chaos_key', help='Chaos project discovery API key')
    parser.add_argument('-db', '--database', default="reconbeast.db", help="Output database filename")
    args = parser.parse_args()
    if not (args.domain or args.domain_file):
        print_banner()
        parser.print_help()
        exit(1)
    return args

ARGS = get_arguments()
database = ARGS.database

def get_logger():
    log_formatter = logging.Formatter("%(asctime)-15s [%(levelname)8s] [%(threadName)s] [%(name)-12s] - %(message)s")
    log = logging.getLogger()
    log.setLevel(logging.DEBUG)
    file_handler = logging.FileHandler(os.path.join(os.path.dirname(__file__), "reconbeast.log"))
    file_handler.setFormatter(log_formatter)
    log.addHandler(file_handler)
    return log

LOG = get_logger()

def setup_database():
    if not os.path.exists(database): 
        LOG.info("Database setup has started")
        print("\033[33m[*] Setting Up Database...\033[0m")
        conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), database))
        conn.execute("CREATE TABLE IF NOT EXISTS domains (domain text unique)")
        conn.execute("CREATE TABLE IF NOT EXISTS rawsubdomains (subdomain text unique)")
        conn.execute(
            """CREATE TABLE IF NOT EXISTS results (
            protocol text,
            domain text,
            port int,
            statuscodechain text,
            statuscode text,
            title text,
            redirectURL text,
            unique(domain,port)
        )""")
        conn.commit()
        LOG.info(f"Database setup has completed {database}") 
        print("\033[33m[*] Setup Completed!\033[0m")
    else:
        conn = sqlite3.connect(os.path.join(os.path.dirname(__file__), database))
        LOG.info(f"Database connection successful {database}")
        print("\033[33m[*] Database Connected!\033[0m")

    return conn

def process_input(conn):
    if ARGS.domain:
        domains = [ARGS.domain]
    elif ARGS.domain_file:
        with open(ARGS.domain_file, 'r') as handle:
            domains = handle.readlines()
        domains = list(map(lambda d: d.strip(), domains))
    
    domain_list = list(map(lambda d: (d,), domains))
    conn.executemany("INSERT OR IGNORE INTO domains VALUES (?)", domain_list)
    conn.commit()
    LOG.info(f"No of domains inserted is {len(domain_list)}")

def get_data_from_db(conn, requested):
    if requested == 'domain':
        data = conn.execute("SELECT * FROM domains")
    elif requested == 'subdomain':
        data = conn.execute("SELECT * FROM rawsubdomains")
    
    return list(map(lambda d: d[0], data))

def process_import_temp_files(conn, tool, target):
    try:
        with open(f"{temp_path}/{target}_{tool}.txt") as output_file:
            result = output_file.readlines()
        LOG.info(f"Read result of {tool} with {len(result)} lines")
    except FileNotFoundError:
        LOG.warning(f"Reading {temp_path}/{target}_{tool}.txt is failed")
        return

    [ print(r.strip()) for r in result ]
    result = list(map(lambda r: (r.strip(),), result))

    conn.executemany("INSERT OR IGNORE INTO rawsubdomains VALUES (?)", result)
    conn.commit()
    LOG.info(f"Added results of {tool} to database") 

def do_subdomain_scan(conn, tool, target):
    if tool == 'findomain':
        cmd = f"findomain -t {target} -u {temp_path}/{target}_{tool}.txt"
    elif tool == 'subfinder':
        cmd = f"subfinder -d {target} -all -o {temp_path}/{target}_{tool}.txt"
    elif tool == "assetfinder":
        cmd = f"assetfinder --subs-only {target}"
    elif tool == "amass":
        cmd = f"amass enum -passive -d {target} -o {temp_path}/{target}_{tool}.txt"
    elif tool == "chaos_client":
        if ARGS.chaos_key:
            chaos_key = ARGS.chaos_key
            cmd = f"chaos -d {target} -key {chaos_key} -o {temp_path}/{target}_{tool}.txt"
        else:
            LOG.warning("No Chaos API key found, skipping Chaos scan")
            CONSOLE.print("[orange][*] No Chaos API key found, skipping Chaos scan...")

    LOG.info(f"{tool} scan has started")
    CONSOLE.print(f"[yellow][*] {tool} scan")
    
    if tool in output_to_terminal:
        proc = subprocess.check_output(cmd, shell=True, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tool_output = proc.decode().strip()
        with open(f'{temp_path}/{target}_{tool}.txt', 'w') as handle:
            handle.write(tool_output)
    else:
        proc = subprocess.run(cmd, shell=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
         
    LOG.info(f"{tool} scan has completed: {proc}")
    process_import_temp_files(conn, tool, target)

def scrape_rapiddns(target):
    response = requests.get("https://rapiddns.io/subdomain/"+target+"?full=1#result")
    soup = BeautifulSoup(response.content, "html.parser")
    table = soup.find('table')
    table_body = table.find('tbody')
    rows = table_body.find_all('tr')

    for row in rows:
        cols = [td.text.strip() for td in row.find_all('td')]
        subdomains_list.append(cols[0])
    
    with open(f"{temp_path}/{target}_rapiddns.txt", 'w') as handle:
        for subdomain in subdomains_list:
            handle.write(f"{subdomain}\n")
            print(subdomain)

def start_subdomain_scan(conn, domains):
    for domain in domains:
        # if not os.path.isdir(f"{temp_path}/{domain}"):
        #     os.makedirs(f"{temp_path}/{domain}",exist_ok=True)
        do_subdomain_scan(conn, "findomain", domain)
        do_subdomain_scan(conn, "subfinder", domain)
        do_subdomain_scan(conn, "assetfinder", domain)
        do_subdomain_scan(conn, "amass", domain)
        if ARGS.chaos_key:
            do_subdomain_scan(conn, "chaos_client", domain)
        
        scrape_rapiddns(domain)
        process_import_temp_files(conn, 'rapiddns', domain)

# def start_subdomain_probe(conn, raw_subdomains, target, domains):
#     for domains in domains:
#         do_subdomain_probe(conn, raw_subdomains, target)

def do_subdomain_probe(conn, raw_subdomains):
    with open(f'{temp_path}/raw_subdomains.txt', 'w') as sf:
        sf.write('\n'.join(raw_subdomains))

    LOG.info("httpx has started")
    httpx_cmd = f"httpx -l {temp_path}/raw_subdomains.txt -silent -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; " \
                "rv:55.0) Gecko/20100101 Firefox/55.0' -ports 80,8080,8081,8443,443,7001,3000 -status-code " \
                f"-no-color -follow-redirects -title -websocket -json -o {temp_path}/httpx_subs.txt"
    proc = subprocess.run(httpx_cmd, shell=True, stdout=subprocess.DEVNULL)
    LOG.info(f"Httpx Process Completed! {proc}")

    @dataclass_json(undefined=Undefined.EXCLUDE)
    @dataclass
    class HttpxOutput:
        scheme: Optional[str] = None
        port: Optional[int] = None
        url: Optional[str] = None
        title: Optional[str] = None
        statuscode: Optional[int] = field(metadata=config(field_name="status-code"), default=None)
        final_dest: Optional[str] = field(metadata=config(field_name="final-url"), default=None)
        statuscodes: Optional[List[int]] = field(metadata=config(field_name="chain-status-codes"), default=None)

        def get_db_tuple(self):
            domain = re.match(r"https?://([^:]*)(:\d*)?", self.url).groups()[0]
            return (
                self.scheme,
                domain,
                self.port,
                str(self.statuscodes),
                self.statuscode,
                self.title,
                self.final_dest
            )

    with open(f"{temp_path}/httpx_subs.txt") as handle:
        to_insert = [HttpxOutput.schema().loads(line).get_db_tuple() for line in handle.readlines()]
    LOG.info(f"Number of results from httpx is {len(to_insert)}")

    conn.executemany("INSERT OR IGNORE INTO results VALUES (?, ?, ?, ?, ?, ?, ?)", to_insert)
    conn.commit()
    LOG.info("Inserted httpx results to the database")

def main():
    print_banner()
    with CONSOLE.status("") as status:
        # CONSOLE.print("[yellow][*] Setup database")
        CONN = setup_database()
        # CONSOLE.print("[yellow][*] Setup Completed!")
        process_input(CONN)
        # insert_domains(requested_domains)
        domains_to_scan = get_data_from_db(CONN, 'domain')
        status.update("[bold yellow]Scanning for Subdomains...")
        start_subdomain_scan(CONN, domains_to_scan)
        CONSOLE.print("[yellow][*] Scanning Completed!")
        status.update("[bold yellow]Probing Subdomains...")
        subdomains_to_probe = get_data_from_db(CONN, 'subdomain')
        do_subdomain_probe(CONN, subdomains_to_probe)
        # do_subdomain_probe(subdomains_to_probe)
        CONSOLE.print("[yellow][*] Probing Completed!")
        # # connection.close()

if __name__ == "__main__":
    main()


