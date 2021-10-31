<?php

namespace MayMeow\Cryptography\Tools;

use MayMeow\Cryptography\RSAParameters;

interface RsaParametersWriterInterface
{
    /**
     * Write parameters to given location
     */
    public function write(RSAParameters $RSAParameters): void;
}
