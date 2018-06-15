# python-csr
## Purpose
Generate a key, self-signed certificate, and certificate request.

## Information
You'll notice there is only one version of python scripts. This can be used with both python(2.7) and python(3.5).

## Installation / Dependencies
The following modules are required:
- OpenSSL (pyopenssl)
- Argparse (argparse)
- YAML (pyyaml)

I've included a setup.py that will install these dependencies if you run:
```bash
python setup.py install
```

## Usage

```bash
./csrgen -n [fqdn]
```

Note: you could always use '-h' in order to get some informations ;)

```bash
user@host> ./csrgen.py -h
usage: csrgen.py [-h] [-v] [-d] [-l LOG] [-n NAME] [-s [SAN [SAN ...]]]
                 [-k KEYSIZE] [-u UNATTENDED] [-f FILE] [-a] [-c]

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Output more infos
  -d, --debug           Enable debug mode
  -l LOG, --log LOG     Define log file (default: /var/log/certGen.log)
  -n NAME, --name NAME  Provide the FQDN
  -s [SAN [SAN ...]], --san [SAN [SAN ...]]
                        SANS, define alternative names
  -k KEYSIZE, --keysize KEYSIZE
                        Provide the key size
  -u UNATTENDED, --unattended UNATTENDED
                        Load CSR predefined options
  -f FILE, --file FILE  Load hosts file (CN and optional Alternate Names) list
  -a, --authority       Generate Authority certificate (Default is server)
  -c, --client          Generate client certificate (Default is server)
```

Basic usage would be
```bash
./csrgen -n test.test.com
```

When more than one hostname is provided, a SAN (Subject Alternate Name)
certificate and request are generated.  This can be acheived by adding a -s.

csrgen <hostname> -s <san0> <san1>

```bash
./csrgen -n test.test.com -s mushu.test.com pushu.test.com
```

You can pass a yaml file as arguments to pre-fill your CSR values (C, ST, L, O, OU). Basically any attribute defined in the YAML file will be set in the certificate. On exception: if you force the hostname with -n parameter, it will override the 'Hostname' set in YAML file.

```bash
./csrgen -f sample.yaml -u csr.yaml
```

## Debug options
A debug option (-d) and a verbose flag (-v) are available. If in any case you want to check the content of generated files, here is a quick cheat-sheet...

### To read a CSR
```bash
openssl req -in test.test.com.csr -noout -text
```

### To read a Certificate (CER)
```bash
openssl x509 -in test.test.com.cer -noout -text
```

### To read a Certificate (PEM)
```bash
openssl x509 -inform pem -in test.test.com.cer -noout -text
```

# TODO
- Implement Unit Tests
