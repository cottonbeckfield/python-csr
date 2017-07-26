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
from OpenSSL.crypto import FILETYPE_PEM


# Generate Certificate Signing Request (CSR)
def generateCSR(nodename, unattended, sans = []):

  default_C =  "ES"
  default_ST = "State"
  default_L =  "Locality"
  default_O =  "ORG"
  default_OU = "ORG_Unit"
  default_EM = "account@example.com"

  #interactive mode
  loop = True
  while loop == True and unattended == False:
    C  = raw_input("Enter your Country Name (2 letter code) [" + default_C + "]: ")
    if len(C) == 0:
      C = default_C
    elif len(C) != 2:
      print "You must enter two letters. You entered %r" % (C)
      continue
    ST = raw_input("Enter your State or Province <full name> [" + default_ST + "]: ")
    if len(ST) == 0:
      ST = default_ST
    L  = raw_input("Enter your (Locality Name (eg, city) [" + default_L + "]: ")
    if len(L) == 0:
      L = default_L
    O  = raw_input("Enter your Organization Name (eg, company) [" + default_O + "]: ")
    if len(O) == 0:
       O = default_O
    OU = raw_input("Enter your Organizational Unit (eg, section) [" + default_OU + "]: ")
    if len(OU) == 0:
      OU = default_OU
    EM = raw_input("Enter your e-mail  [" + default_EM + "]: ")
    if len(EM) == 0:
      EM = default_EM
    loop = False

  #unatended mode
  if unattended == True:
    C  = default_C
    ST = default_ST
    L  = default_L
    O  = default_O
    OU = default_OU
    EM = default_EM

  csrfile = nodename + '.csr'
  keyfile = nodename + '.key'
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
  req.get_subject().emailAddress = EM
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

    if mkFile.endswith('.csr'):
        f = open(mkFile, "w")
        f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, request))
        f.close()
    elif mkFile.endswith('.key'):
        f = open(mkFile, "w")
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, request))
        f.close()
    else:
        print "Failed."
        exit()

# Check the CRS generated and display the information in there
def checkCSR(nodename):

    try:
      f = open(nodename, "r")
      csr = f.read()
      f.close()
    except Exception as e:
      print str(e)
      return

    req = crypto.load_certificate_request(FILETYPE_PEM, csr)
    subject = req.get_subject()
    print
    print "Information for certificate: " + nodename
    print "-"*len("Information for certificate: " + nodename)
    cadena = "{0:<16}{1}{2}"
    for component in subject.get_components():
      print cadena.format(component[0], ": ", component[1])

    for i in req.get_extensions():
      if str(i).startswith('DNS:'):
        i = str(i).replace('DNS:','').split(',')
        for san in i:
          print cadena.format("SAN:", ": ", san.strip())
    print


# Main program
if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Generate the certificate signed by the CA")

    #defined the commands available for the script
    subparsers = parser.add_subparsers(title='commands') #,  help='commands availables')
    parser_create = subparsers.add_parser('create', help='create the certificates requested')
    parser_create.set_defaults(which='create')
    parser_create.add_argument("-s", "--san", required=False, help="SANS", action="store", nargs='*', default="")
    parser_create.add_argument("-u", "--unattended", required=False, help="Create the certificate unattended, with the options by default", action="store_true")
    parser_check = subparsers.add_parser('check', help='check the certificate passed')
    parser_check.set_defaults(which='check')

    #main argument is always required
    parser.add_argument("name", help="Provide the FQDN", action="store")

    args = vars(parser.parse_args())
    hostname = args['name']


    #execute the apropiate function depending of the command chosen.
    if args['which'] == 'create':
      sans = args['san']
      unattended = args['unattended']
      generateCSR(hostname, unattended, sans)
    elif  args['which'] == 'check':
      checkCSR(hostname)

