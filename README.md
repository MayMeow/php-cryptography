# MayMeow/Cryptography

[![PHP Composer](https://github.com/MayMeow/php-cryptography/actions/workflows/php.yml/badge.svg)](https://github.com/MayMeow/php-cryptography/actions/workflows/php.yml)

# Requirements

* PHP 7.4.*

## What it is contained

* [x] AES Crypto service provider (encrypt, decrypt strings)
* [ ] RSA Crypto service provider
* [x] Key derivation
* [ ] Certificate signing

## Development

This project contains dev container. To start development build container

```bash
docker-compose -f docker-compose.dev.yml build
```

This container running as user `vscode` with uid `1000`. Start container

```bash
docker-compose -f docker-compose.dev.yml run --rm dev-container sh
```

## Usage

### Cryptographic key derivation

```php
$p = new Maymeow\Cryptography\CryptoKey();

$p->getCryptograhicKey($password, $salt);
```
