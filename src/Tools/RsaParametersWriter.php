<?php

namespace MayMeow\Cryptography\Tools;

use MayMeow\Cryptography\RSAParameters;

class RsaParametersWriter
{

    public function write(RSAParameters $RSAParameters): void
    {
        $privKey = KEYSTORE . DIRECTORY_SEPARATOR . 'key.pem';
        $pubKey = KEYSTORE . DIRECTORY_SEPARATOR . 'pubkey.pem';
        $passPhrase = KEYSTORE . DIRECTORY_SEPARATOR . 'pass.txt';

        file_put_contents($pubKey, $RSAParameters->getPublicKey());
        file_put_contents($passPhrase, $RSAParameters->getPassphrase());

        openssl_pkey_export_to_file(
            $RSAParameters->getPrivateKey(),
            $privKey,
            $RSAParameters->getPassphrase()
        );
    }
}
