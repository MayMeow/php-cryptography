#!/bin/bash

docker run -it --rm -v "$(pwd)":/usr/local/src/your-app githubchangeloggenerator/github-changelog-generator -u maymeow -p php-cryptography
