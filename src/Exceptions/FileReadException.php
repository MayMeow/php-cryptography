<?php

namespace MayMeow\Cryptography\Exceptions;

use Throwable;

class FileReadException extends \Exception
{
    /**
     * @param string $message
     * @param int $code
     * @param Throwable|null $previous
     */
    public function __construct(string $message = "Cannot read file", int $code = 10, Throwable $previous = null)
    {
        parent::__construct($message, $code, $previous);
    }
}