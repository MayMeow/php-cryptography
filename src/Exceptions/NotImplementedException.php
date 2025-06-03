<?php

namespace MayMeow\Cryptography\Exceptions;

use Throwable;

class NotImplementedException extends \Exception
{
    public function __construct(string $message = "Not Implemented yet!", int $code = 0, ?Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}
