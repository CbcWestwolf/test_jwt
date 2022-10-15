# Generate private key

```shell
openssl genrsa -out ssl_key/rsa_private_key.pem 2048
```

# Generate public key

```shell
openssl rsa -in ssl_key/rsa_private_key.pem -pubout -out ssl_key/rsa_public_key.pem
```
