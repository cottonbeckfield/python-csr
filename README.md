# python-csr
Generate a key, self-signed certificate, and certificate request.

Usage: csrgen [fqdn]

```
python csrgen test.test.com
```
When more than one hostname is provided, a SAN (Subject Alternate Name)
certificate and request are generated.  This can be acheived by adding -s.

Usage: csrgen <hostname> -s <san0> <san1>

```
python csrgen test.test.com -s mushu.test.com pushu.test.com
```
When you do not want to be prompted for locality, you can use a config file.
This can be acheived by adding -c. (SAN request still work)

Usage: csrgen <hostnaem> -c your_config -s <san0> <san1>

```
python csrgen test.test.com -c csrgen.conf -s mushu.test.com pushu.test.com
```
