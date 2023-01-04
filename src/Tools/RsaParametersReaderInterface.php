<?php

namespace MayMeow\Cryptography\Tools;

use MayMeow\Cryptography\Exceptions\FileReadException;
use MayMeow\Cryptography\RSAParameters;

interface RsaParametersReaderInterface
{
    /**
     * @return RSAParameters
     * @throws FileReadException
     */
    public function read(): RSAParameters;
}
