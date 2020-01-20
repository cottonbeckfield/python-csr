import pytest
import csrgen
import logging

def import_logging():
    logger = logging.getLogger('certgen')
    hdlr = logging.handlers.TimedRotatingFileHandler("csrgen_test.log", when="midnight", backupCount=3)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel("WARN")

    return logger

# Test that if a file is supplied (../samples/sample-file.yaml) the code does #
#   exit with an error.

def test_load_nodes():
    logger = import_logging()
    cert = csrgen.Certificate(logger, {'verbose': False, 'size': '2048', 'C': 'Te', 'ST': 'PACA', 'L': 'Gap', 'O': 'ProHacktive SAS', 'OU': 'prohacktive.io'})
    result = cert.loadNodes("samples/sample-file.yaml")

def test_load_defaults():
    logger = import_logging()
    cert = csrgen.Certificate(logger, {'verbose': False, 'size': '2048'})
    result = cert.loadDefaults("samples/csr-sample-unattended.yaml")

def test_generate_csr():
    logger = import_logging()
    cert = csrgen.Certificate(logger, {'verbose': False, 'size': '2048', 'hostname': 'test-csr.edu', 'sans': 'test-csr-sans.edu',
    'C': 'Te', 'ST': 'PACA', 'L': 'Gap', 'O': 'ProHacktive SAS', 'OU': 'prohacktive.io'})
    result = cert.generateCSR()

# Test that if a file is supplied and a ../samples/csr-sample-unattended.yaml is supplied
#   that the code does not exit.

# Test that if someone supplies -n the code does not exit.

# Test that if someone supplies a -n and a -s that the code does not exit.
