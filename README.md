# python-csr
# Generate a key, self-signed certificate, and certificate request.
# Usage: csrgen <fqdn>
# 
# When more than one hostname is provided, a SAN (Subject Alternate Name)
# certificate and request are generated.  This can be acheived by adding -s.
# Usage: csrgen <hostname> -s <san0> <san1>
