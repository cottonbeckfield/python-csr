#!/usr/bin/env python
#
# Generate a key, self-signed certificate, and certificate request.
# Usage: csrgen -n <fqdn>
#
# When more than one hostname is provided, a SAN (Subject Alternate Name)
# certificate and request are generated.  This can be acheived by adding -s.
# Usage: csrgen -n <hostname> -s <san0> <san1>
#
# If you want to generate multiple CSRs, you can use the -f command to
# feed in a .yaml file via the CLI. See the example sample.yaml in this
# repository for examples.
#
# If you want to predefine some of your CSR attributes, you can use the -u command
# to feed in a .yaml file via the CLI. See the example csr.yaml in this repository
# for examples.
#
# Author: Courtney Cotton <cotton@cottoncourtney.com> 06-25-2014, Updated 8-9-2017
# Author: Ben Mz <bmz@prohacktive.io> Updated 06-15-2018

# Libraries/Modules
import sys, platform, yaml
import argparse, logging, logging.handlers
from OpenSSL import crypto, SSL

__version__ = '1.0.1'

class Certificate:
    def __init__(self, logger, opts={}):
        self._logger = logger
        self.allowed = ["Digital Signature", "Non Repudiation", "Key Encipherment"]
        
        # Set default usage
        self._level = logging.WARNING
        self._key_size = 2048
        self._ca = False
        self._verbose = True
        self.usage = ','.join(self.allowed)

        try:
            self._verbose = opts['verbose']
            del opts['verbose']
        except KeyError:
            pass

        self._header()

        # Set default log level
        try:
            self._level = opts['level']
            del opts['level']
        except KeyError:
            pass

        # Set key size
        try:
            if int(opts['size']) in [1024,2048,4096]:
                self._key_size = int(opts['size'])
            del opts['size']
        except KeyError:
            pass
        except ValueError:
            pass

        try:
            for usage in opts['usage']:
                if usage not in self.allowed:
                    raise Exception('Invalid key usage: {u}'.format(u=usage))
                self.usage = opts['usage'] 
            del opts['usage']   
        except KeyError:
            # Keep server default if no usage is set
            pass

        self.opts = opts
        self.output('[*] We have already set options:',level=logging.DEBUG)
        self.output('{o}'.format(o=self.opts),level=logging.DEBUG)
    
    def _header(self):
        self.output('\t\t..:: Certificate Signing Request (CSR) Generator ::..\n')

    def _isCA(self):
        return "TRUE" if self._ca else "FALSE"

    def _ask(self, msg, country=False, default=None):
        while True:
            rep = raw_input(msg)
            if country and (len(rep)) and (len(rep) != 2):
                self.output('[!] Sorry this value is invalid (should be two letters only).')
                continue
            if len(rep) is 0:
                if default is None:
                    self.output('[!] Sorry this value is mandatory.')
                    continue
                rep = default
            break

        return rep

    # Generate Certificate Signing Request (CSR)
    def generateCSR(self):
        try:
            nodename = self.opts['hostname']
        except KeyError:
            raise Exception('Could not generate certificate with empty hostname')

        # These variables will be used to create the host.csr and host.key files.
        csrfile = nodename + '.csr'
        keyfile = nodename + '.key'
        # OpenSSL Key Type Variable, passed in later.
        TYPE_RSA = crypto.TYPE_RSA

        # Appends SAN to have 'DNS:'
        ss = []
        try:
            for entry in self.opts['sans']:
                ss.append("DNS: {e}".format(e=entry))
        except KeyError:
            pass
        ss = ", ".join(ss)

        req = crypto.X509Req()
        req.get_subject().CN = nodename
        try:
            req.get_subject().countryName = self.opts['C']
            req.get_subject().stateOrProvinceName = self.opts['ST']
            req.get_subject().localityName = self.opts['L']
            req.get_subject().organizationName = self.opts['O']
            req.get_subject().organizationalUnitName = self.opts['OU']
        except KeyError:
            raise Exception('Missing mandatory certificate value!')

        # Email Address is not mandatory
        try:
            req.get_subject().emailAddress = self.opts['emailAddress']
        except KeyError:
            pass

        # Add in extensions
        base_constraints = ([
            crypto.X509Extension("keyUsage", False, self.usage),
            crypto.X509Extension("basicConstraints", False, "CA:{c}".format(c=self._isCA())),
            ])
        x509_extensions = base_constraints
        
        # If there are SAN entries, append the base_constraints to include them.
        if len(ss):
            san_constraint = crypto.X509Extension("subjectAltName", False, ss)
            x509_extensions.append(san_constraint)
        
        req.add_extensions(x509_extensions)
        
        # Utilizes generateKey function to kick off key generation.
        key = self.generateKey(TYPE_RSA, self._key_size)
        req.set_pubkey(key)
        req.sign(key, "sha256")

        self.output('[+] Generate CSR file: {f}'.format(f=csrfile))
        self.generateFiles(csrfile, req)
        self.output('[+] Generate Key file: {f}'.format(f=keyfile))
        self.generateFiles(keyfile, key)

        self.output("\n[+] Your CSR and certificate ({s} bits) are now generated with:".format(s=self._key_size))
        for k,v in self.opts.items():
            if k is 'hostname':
                self.output("\t[{k}]\t-> {v}".format(k=k,v=v))
            else:    
                self.output("\t[{k}]\t\t-> {v}".format(k=k,v=v))

        return req

    def getCSRSubjects(self):
        fields = ['C','ST','L','O','OU','hostname']

        for field in fields:
            try:
                # Check if field is already setup
                if self.opts[field]:
                    self.output('[*] Field {n} is set'.format(n=field), level=logging.DEBUG)
                    continue
            except KeyError:
                self.output('[*] Field {n} is NOT set'.format(n=field), level=logging.DEBUG)
                pass

            if field is 'C':
                self.opts['C'] = self._ask("Enter your Country Name (2 letter code) [US]: ", default='US', country=True)
            elif field is 'ST':
                self.opts['ST'] = self._ask("Enter your State or Province <full name> [California]: ", default='California')
            elif field is 'L':
                self.opts['L'] = self._ask("Enter your (Locality Name (eg, city) [San Francisco]: ", default='San Francisco')
            elif field is 'O':
                self.opts['O'] = self._ask("Enter your Organization Name (eg, company) [FTW Enterprise]: ", default='FTW Enterprise')
            elif field is 'OU':
                self.opts['OU'] = self._ask("Enter your Organizational Unit (eg, section) [IT]: ", default='IT')
            elif field is 'hostname':
                self.opts['hostname'] = self._ask("Enter your Common Name (eg, DNS name) [{n}]:".format(n=platform.node()), default=platform.node())

        # Allows you to permanently set values required for CSR
        # To use, comment raw_input and uncomment this section.
        # C  = 'US'
        # ST = 'New York'
        # L  = 'Location'
        # O  = 'Organization'
        # OU = 'Organizational Unit'

    # Parse the contents of the YAML file and then
    # auto setup values.
    def loadDefaults(self, csr_file):
        try:
            self.output("[+] Reading default values file: {f}".format(f=csr_file), level=logging.DEBUG)
            cfg = self._parseYAML(csr_file)
        except Exception as err:
            raise Exception(err)

        for k,v in cfg.items():
            if (k is 'C') and len(v) != 2:
                continue
            if len(v) is 0:
                continue
            
            try:
                self.opts[k] = str(v)
            except Exception:
                pass

    # Parse the contents of the YAML file and then
    # generate a CSR for each of them.
    def loadNodes(self, nodes_file):
        try:
            self.output("[+] Reading nodes file: {f}".format(f=nodes_file), level=logging.DEBUG)
            cfg = self._parseYAML(nodes_file)
        except Exception as err:
            raise Exception(err)

        self.output('[+] Generate certificates for:')
        for k,v in cfg.items():
            self.opts['hostname'] = cfg[k]['hostname']
            if cfg[k]['sans']:
                self.opts['sans'] = cfg[k]['sans']
            else:
                self.opts['sans'] = ''
            self.output("[+] host: {h}, alternate names: {s}".format(h=self.opts['hostname'], s=self.opts['sans']))
            self.generateCSR()

    def _parseYAML(self, yaml_file):
        """Parse YAML file and return object generated
        """
        with open(yaml_file, 'r') as stream:
            cfg = yaml.load(stream)
        return cfg

    def generateKey(self, type, bits):
        """Generate Private Key
        """
        self.output('[+] Generate certificate seed Key...')
        
        key = crypto.PKey()
        key.generate_key(type, bits)
        
        return key

    def generateFiles(self, mkFile, request):
        """Generate .csr/key files.
        """
        with open(mkFile, "w") as f:
            if ".csr" in mkFile:
                f.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, request))
            elif ".key" in mkFile:
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, request))
            else:
                self.output("[!] Failed to create CSR/Key files", level=logging.ERROR)
        
    def output(self, msg, level=logging.WARNING):
        """Generate output to CLI and log file
        """

        # Output to log
        if level == logging.DEBUG:
            self._logger.debug(msg)
        elif level == logging.INFO:
            self._logger.info(msg)
        elif level == logging.WARNING:
            self._logger.warning(msg)
        elif level == logging.ERROR:
            self._logger.error(msg)
        elif level == logging.CRITICAL:
            self._logger.critical(msg)
        # Misconfigured level are high notifications
        else:
            self._logger.error("[!] Invalid level for message: {m}".format(m=msg))

        # Output to CLI if needed
        if self._verbose and (level >= self._level):
            sys.stdout.write("{m}\n".format(m=msg))

class Authority(Certificate):
    def __init__(self,logger, opts):
        # Init certificate
        try:
            super(Authority, self).__init__(logger,opts)
        except Exception as err:
            raise Exception("Error at {n} initialization: {e}".format(n=self._name, e=err))
        self._ca = True
    
    def initialize(self):
        self.generateCSR()


def main(argv):
    # Define default values
    VERBOSE = False
    LOG_FILE = "/var/log/certGen.log"
    LOG_LEVEL = logging.WARNING
    opts = {}

    # Run Portion
    # This section will parse the flags available via command line.
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="Output more infos", action="store_true")
    parser.add_argument("-d", "--debug", help="Enable debug mode", action="store_true")
    parser.add_argument("-l", "--log", help="Define log file (default: {f}".format(f=LOG_FILE))
    parser.add_argument("-n", "--name", help="Provide the FQDN", action="store", default="")
    parser.add_argument("-s", "--san", help="SANS, define alternative names", action="store", nargs='*', default="")
    parser.add_argument("-k", "--keysize", help="Provide the key size", action="store", default="2048")
    parser.add_argument("-u", "--unattended", help="Load CSR predefined options", action="store", default="")
    parser.add_argument("-f", "--file", help="Load hosts file (CN and optional Alternate Names) list", action="store", default="")
    parser.add_argument("-a", "--authority", help="Generate Authority certificate (Default is server)", action="store_true")
    parser.add_argument("-c", "--client", help="Generate client certificate (Default is server)", action="store_true")
    
    args = parser.parse_args()

    # Run the primary function.
    # Checks to see if the -f was given. If it wasn't, skip directly
    # to the generateCSR, otherwise it'll need to parse the YAML file
    # first via the functio parseYAML called via generateFromFile.
    if args.log:
        LOG_FILE = args.log

    if args.verbose:
        VERBOSE = True
    
    opts['verbose'] = VERBOSE

    if args.debug:
        opts['level'] = logging.DEBUG

    # Define logger
    try:
        logger = logging.getLogger('certgen')
        hdlr = logging.handlers.TimedRotatingFileHandler(LOG_FILE, when="midnight", backupCount=3)
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
        hdlr.setFormatter(formatter)
        logger.addHandler(hdlr)
        logger.setLevel(LOG_LEVEL)
    except AttributeError as err:
        sys.stdout.write("[!] Unable to open log file {f}: {e}\n".format(f=LOG_FILE, e=err))
        sys.exit(1)
    except IOError as err:
        sys.stdout.write("[!] Unable to open log file {f}: {e}\n".format(f=LOG_FILE, e=err))
        sys.exit(1)

    if args.keysize:
        opts['size'] = args.keysize

    if args.authority:
        if args.client:
            sys.stdout.write('[!] You can generate multiple certificate type at one time.')
            sys.exit(2)
        if args.san:
            sys.stdout.write('[!] You can not specify alternative names with authority certificates')
            sys.exit(1)
        opts['usage'] = ['Certificate signing','CRL signing']

    if args.client:
        if args.san:
            sys.stdout.write('[!] You can not specify alternative names with client certificates')
            sys.exit(1)
        opts['usage'] = ["digitalSignature"]
    
    # Store infos if set
    if args.name:
        opts['hostname'] = args.name
    if args.san:
        opts['sans'] = args.san

    try:
        # Initialize certificate object
        cert = Certificate(logger, opts)

        if args.unattended:
            cert.loadDefaults(args.unattended)

        # Run interactively if needed for C, ST, L, O, OU values
        cert.getCSRSubjects()
        
        if args.file:
            cert.generateFromFile(args.file)
        else:
            cert.generateCSR()
    except KeyboardInterrupt:
        sys.stdout.write('\n[!] Exit requested.')
    except SystemExit:
        sys.stdout.write('\n[!] Software aborted.')

    sys.stdout.write('\nBye! ;)\n')

if __name__ == '__main__':
    main(sys.argv)