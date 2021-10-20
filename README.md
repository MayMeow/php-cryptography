# MayMeow/Cryptography

Cryptographic library for encrypting and decrypting data the symetrical and asymetrical way.

This package replaces https://github.com/MayMeow/php-encrypt

[![PHP Composer](https://github.com/MayMeow/php-cryptography/actions/workflows/php.yml/badge.svg)](https://github.com/MayMeow/php-cryptography/actions/workflows/php.yml)

# Requirements

- PHP 8.*
- openssl extension

## What it is contained

* [x] AES Crypto service provider (encrypt, decrypt strings)
* [x] RSA Crypto service provider
* [x] Key derivation

## Development

This project contains dev container. To start development build container

```bash
docker-compose -f docker-compose.dev.yml build
```

This container running as user `vscode` with uid `1000`. Start container

```bash
docker-compose -f docker-compose.dev.yml run --rm dev-container sh
```

or it can be used as configuration for remote PHP processor in PHPStorm.

## Usage

### Cryptographic key derivation

```php
$p = new Maymeow\Cryptography\CryptoKey();

$p->getCryptograhicKey($password, $salt);
```

## Contribute

Feel free to contribute to this project. All contributions must have:

- Created Issue - describe what you want to add or change
- pull requests has to be linked to this issue, Describe there what you chaning / adding
- Do not make big changes in one pull request. Keep it simple and clean and rather make another pull request for more changes.
- Pull requests must pass all checks.

License MIT
