<?php

$phrase = 'this is a test phrase for byte conversion';
$phrase_whitespace_removed = preg_replace('/\s+/', '', $phrase);

$phrase_hex = bin2hex($phrase);
$phrase_hex_whitespace_removed = bin2hex($phrase_whitespace_removed);
echo $phrase_hex;
echo "\n\n";
echo $phrase_hex_whitespace_removed;

echo "\n\n";

$phrase_str = hex2bin($phrase_hex);
echo $phrase_str;