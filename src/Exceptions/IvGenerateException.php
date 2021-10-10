<?php

namespace MayMeow\Cryptography\Exceptions;

use Throwable;

class IvGenerateException extends \Exception
{
    public function __construct(string $message = "Cannot generate IV", int $code = 0, Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}