<?php

define('ROOT', dirname(__dir__));

const KEYSTORE = ROOT. DIRECTORY_SEPARATOR . 'keystore';

if (!file_exists('')) {
    mkdir(KEYSTORE);
}
