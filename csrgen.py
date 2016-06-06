#!/usr/bin/env python
#
# Generate a key, self-signed certificate, and certificate request.
# Usage: csrgen <fqdn>
#
# When more than one hostname is provided, a SAN (Subject Alternate Name)
# certificate and request are generated.  This can be acheived by adding -s.
# Usage: csrgen <hostname> -s <san0> <san1>
#
# Author: Courtney Cotton <cotton@cottoncourtney.com> 06-25-2014

# Libraries/Modules

import argparse
from OpenSSL import crypto


# Generate Certificate Signing Request (CSR)
def generateCSR(nodename, sans = []):

  while True:
    C  = raw_input("Enter your Country Name (2 letter code) [US]: ")
    if len(C) != 2:
      print "You must enter two letters. You entered %r" % (C)
      continue
    ST = raw_input("Enter your State or Province <full name> []:California: ")
    if len(ST) == 0:
      print "Please enter your State or Province."
      continue
    L  = raw_input("Enter your (Locality Name (eg, city) []:San Francisco: ")
    if len(L) == 0:
      print "Please enter your City."
      continue
    O  = raw_input("Enter your Organization Name (eg, company) []:FTW Enterprise: ")
    if len(L) == 0:
       print "Please enter your Organization Name."
       continue
    OU = raw_input("Enter your Organizational Unit (eg, section) []:IT: ")
    if len(OU) == 0:
      print "Please enter your OU."
      continue

    # Allows you to permanently set values required for CSR
    # To use, comment raw_input and uncomment this section.
    # C  = 'US'
    # ST = 'New York'
    # L  = 'Location'
    # O  = 'Organization'
    # OU = 'Organizational Unit'

    csrfile = 'host.csr'
    keyfile = 'host.key'
    TYPE_RSA = crypto.TYPE_RSA
    # Appends SAN to have 'DNS:'
    ss = []
    for i in sans:
        ss.append("DNS: %s" % i)
    ss = ", ".join(ss)

    req = crypto.X509Req()
    req.get_subject().CN = nodename
    req.get_subject().countryName = C
    req.get_subject().stateOrProvinceName = ST
    req.get_subject().localityName = L
    req.get_subject().organizationName = O
    req.get_subject().organizationalUnitName = OU
    # Add in extensions
    base_constraints = ([
        crypto.X509Extension("keyUsage", False, "Digital Signature, Non Repudiation, Key Encipherment"),
        crypto.X509Extension("basicConstraints", False, "CA:FALSE"),
    ])
    x509_extensions = base_constraints
    # If there are SAN entries, append the base_constraints to include them.
    if ss:
        san_constraint = crypto.X509Extension("subjectAltName", False, ss)
        x509_extensions.append(san_constraint)
    req.add_extensions(x509_extensions)
    # Utilizes generateKey function to kick off key generation.
    key = generateKey(TYPE_RSA, 2048)
    req.set_pubkey(key)

    #update sha?
    #req.sign(key, "sha1")
    req.sign(key, "sha256")

    generateFiles(csrfile, req)
    generateFiles(keyfile, key)

    return req

# Generate Private Key
def generateKey(type, bits):

    key = crypto.PKey()
    key.generate_key(type, bits)
    return key

# Generate .csr/key files.
def generateFiles(mkFile, request):

    if mkFile == 'host.csr':
        f = open(mkFile, "w")
        f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, request))
        f.close()
        print crypto.dump_certificate_request(crypto.FILETYPE_PEM, request)
    elif mkFile == 'host.key':
        f = open(mkFile, "w")
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, request))
        f.close()
    else:
        print "Failed."
        exit()


# Run Portion
parser = argparse.ArgumentParser()
parser.add_argument("name", help="Provide the FQDN", action="store")
parser.add_argument("-s", "--san", help="SANS", action="store", nargs='*', default="")
args = parser.parse_args()

hostname = args.name
sans = args.san

generateCSR(hostname, sans)
