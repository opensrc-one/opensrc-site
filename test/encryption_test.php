<?php

require_once (realpath(dirname(__FILE__) . '/../src/backend/utils/Cryptography.php'));

use backend\utils\Cryptography;

$crypto = new Cryptography();

$plain_text = 'test message to be encrypted';
$key = 'TestKey123@';
$salt = md5('salt-seed-305jio3hu45i6h');

$encrypted_text = $crypto->encrypt_string($plain_text, $key);
echo $encrypted_text;

echo "\n\n";

$decrypted_text = $crypto->decrypt_string($encrypted_text, $key);
echo $decrypted_text;

echo "\n\n";

$hashed_key = $crypto->hash_password($key, $salt);
echo $hashed_key;

echo "\n\n";

$password_verified = $crypto->verify_password_hash($key, $hashed_key, $salt);
var_dump($password_verified);

echo "\n\n";

$mnemonic = $crypto->generate_mnemonic();
var_dump($mnemonic);

echo "\n\n";

$pbkdf2_key = $crypto->pbkdf2_hash($plain_text, $salt);
echo $pbkdf2_key;

echo "\n\n";

$registration_key = 'opensrc-' . $crypto->create_secure_random_string(32);
$registration_key_hash = hash('sha512', $registration_key);
echo $registration_key;
echo "\n";
echo $registration_key_hash;
