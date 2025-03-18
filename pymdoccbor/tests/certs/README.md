### Procedure to create fake certificate fake-cert.pem
```
openssl ecparam -name prime256v1 -genkey -noout -out fake-private-key.pem   
openssl x509 -req -in fake-request.csr -out leaf-asl.pem -days 3650 -sha256
openssl x509 -req -in fake-request.csr -key fake-private-key.pem -out fake-cert.pem -days 3650 -sha256
```