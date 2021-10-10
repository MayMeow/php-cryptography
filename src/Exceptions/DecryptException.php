<?php

namespace MayMeow\Cryptography\Exceptions;

use Throwable;

class DecryptException extends \Exception
{
    public function __construct(string $message = "Cannot decrypt text", int $code = 0, Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}