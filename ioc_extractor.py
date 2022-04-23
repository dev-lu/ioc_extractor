#==============================================
# Extracts IPs, domains, URLs and hashes from .csv & .txt files
# IoCs will be added to sorted lists
# IoCs will be printed on console
# Author: https://github.com/dev-lu
#==============================================
import re
from collections import OrderedDict


# Read user input
f = input("Pleaser enter path to input file: \n").encode('unicode-escape').decode()

ips = []
md5_hashes = []
sha1_hashes = []
sha256_hashes = []
domains = []
urls = []


def extract_ips_from_file(file):
    with open(file) as f:
        fstring = f.readlines()
    for line in fstring:
        ip = re.findall( r'[0-9]+(?:\.[0-9]+){3}', line )
        if ip:
            for i in ip:
                ips.append(i)
    ips_unique = list(OrderedDict.fromkeys(ips))
    print("\n ==== IP addresses ====\n")
    for i in ips_unique:
        print(i)


def extract_md5_from_file(file):
    with open(file) as f:
        fstring = f.readlines()
    for line in fstring:
        md5 = re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{32}(?![a-z0-9])', line)
        if md5:
            for i in md5:
                md5_hashes.append(i)
    md5_unique = list(OrderedDict.fromkeys(md5_hashes))
    print("\n ==== MD5 hashes ====\n")
    for i in md5_unique:
        print(i)


def extract_sha1_from_file(file):
    with open(file) as f:
        fstring = f.readlines()
    for line in fstring:
        sha1 = re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{40}(?![a-z0-9])', line)
        if sha1:
            for i in sha1:
                sha1_hashes.append(i)
    sha1_unique = list(OrderedDict.fromkeys(sha1_hashes))
    print("\n ==== SHA1 hashes ====\n")
    for i in sha1_unique:
        print(i)


def extract_sha256_from_file(file):
    with open(file) as f:
        fstring = f.readlines()

    for line in fstring:
        sha256 = re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{64}(?![a-z0-9])', line)
        if sha256:
            for i in sha256:
                sha256_hashes.append(i)
    sha256_unique = list(OrderedDict.fromkeys(sha256_hashes))
    print("\n ==== SHA256 hashes ====\n")
    for i in sha256_unique:
        print(i)


def extract_domains_from_file(file):
    with open(file) as f:
        fstring = f.readlines()
    for line in fstring:
        domain = re.findall(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', line)
        if domain:
            for i in domain:
                domains.append(i)
    domains_unique = list(OrderedDict.fromkeys(domains))
    r = re.compile(r'[0-9]+(?:\.[0-9]+){3}')  # Regex for IPs
    domains_filtered = [i for i in domains_unique if not r.match(i)]  # New list without IPs
    print("\n ==== Domains ====\n")
    for i in domains_filtered:
        print(i)


def extract_urls_from_file(file):
    with open(file) as f:
        fstring = f.readlines()
    for line in fstring:
        url = re.findall(r'https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()!@:%_\+.~#?&\/\/=]*)', line)
        if url:
            for i in url:
                urls.append(i)
    urls_unique = list(OrderedDict.fromkeys(urls))
    print("\n ==== URLs ====\n")
    if not urls_unique:
        print("None")
    for i in urls_unique:
        print(i)


if __name__ == "__main__":
    extract_ips_from_file(f)
    extract_md5_from_file(f)
    extract_sha1_from_file(f)
    extract_sha256_from_file(f)
    extract_domains_from_file(f)
    extract_urls_from_file(f)
