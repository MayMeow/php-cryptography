<?php

namespace MayMeow\Cryptography\Exceptions;

use Throwable;

class DecryptPrivateKeyException extends \Exception
{
    public function __construct(
        string $message = "Cannot decrypt private key with given password",
        int $code = 0,
        Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
    }
}
