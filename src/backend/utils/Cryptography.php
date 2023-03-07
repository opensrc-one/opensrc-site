<?php
namespace backend\utils;

require_once (realpath(dirname(__FILE__) . '/../../../vendor/autoload.php'));

use Exception;
use FurqanSiddiqui\BIP39\BIP39;
use FurqanSiddiqui\BIP39\Exception\MnemonicException;
use FurqanSiddiqui\BIP39\Exception\WordListException;

class Cryptography {
    private const ARGON_CONFIG = array (
        'memory_cost' => 100000,
        'time_cost'   => 6,
        'threads'     => 3
    );
    private const PBKDF2_CONFIG = array (
        'length' => 128,
        'iterations' => 1000
    );

    // Create secure random string using random_int()
    public function create_secure_random_string (int $length = 128, bool $symbols = false): string|null {
        // If length is above 1024 or below 1, correct it to the closest valid length
        if ($length < 1)    $length = 1;
        if ($length > 1024) $length = 1024;

        $unique_id = hash('sha512', uniqid() . openssl_random_pseudo_bytes(128) . time());
        $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';

        // if ($symbols) $keyspace .= "~!@#$%^&*()_+{}[]:;<,>.?/|";
        if ($symbols) $keyspace .= str_repeat("()_{}[]:;<,>./|@$", 2);

        $keyspace = str_shuffle($keyspace . $unique_id);

        $pieces = [];
        $max = mb_strlen($keyspace, '8bit') - 1;

        // Gets a char from the keyspace using random_int as index value
        for ($i = 0; $i < $length; ++$i) {
            try {
                $pieces[] = $keyspace[random_int(0, $max)];
            } catch (Exception $e) {
                echo 'Error encountered: ' . $e;
                return null;
            }
        }
        // Returns array as string
        return implode('', $pieces);
    }

    // Create random string using openssl
    public function create_random_string (int $length = 128): string {
        if ($length > 128) $length = 128;
        return substr(hash('sha512', openssl_random_pseudo_bytes(128)), 0, $length);
    }

    // Encrypt string using openssl
    public function encrypt_string (string $plain_text, string $key, string $crypt_cipher = 'AES-256-CBC'): string {
        $iv_length = openssl_cipher_iv_length($crypt_cipher);
        $iv = openssl_random_pseudo_bytes($iv_length);
        $cipher_text_raw = openssl_encrypt($plain_text, $crypt_cipher, $key, OPENSSL_RAW_DATA, $iv);
        $hmac = hash_hmac('sha512', $cipher_text_raw, $key, true);
        return base64_encode($iv . $hmac . $cipher_text_raw);
    }

    // Decrypt string using openssl
    public function decrypt_string (string $cipher_text, string $key, string $crypt_cipher = 'AES-256-CBC'): bool|string {
        $cipher_text_joined = base64_decode($cipher_text);
        $iv_length = openssl_cipher_iv_length($crypt_cipher);
        $iv = substr($cipher_text_joined, 0, $iv_length);
        $hmac = substr($cipher_text_joined, $iv_length, $sha512_length = 64);

        $cipher_text_raw = substr($cipher_text_joined, $iv_length + $sha512_length);
        $plain_text = openssl_decrypt($cipher_text_raw, $crypt_cipher, $key, OPENSSL_RAW_DATA, $iv);
        $calculate_hmac = hash_hmac('sha512', $cipher_text_raw, $key, true);

        if (!hash_equals($hmac, $calculate_hmac))
            return false;
        return $plain_text;
    }

    // Create argon2id hash
    public function argon2id_hash (
        string $plain_text,
        string $salt = '',
        $memory_cost = self::ARGON_CONFIG['memory_cost'],
        $time_cost = self::ARGON_CONFIG['time_cost'],
        $threads = self::ARGON_CONFIG['threads']
    ): string {
        return password_hash($plain_text . $salt, PASSWORD_ARGON2ID, [
            'memory_cost' => $memory_cost,
            'time_cost'   => $time_cost,
            'threads'     => $threads
        ]);
    }

    // Create salted pbkdf2 hash
    public function pbkdf2_hash (
        string $plain_text, string $salt,
        $length = self::PBKDF2_CONFIG['length'], $iterations = self::PBKDF2_CONFIG['iterations']
    ): string { return hash_pbkdf2('sha512', $plain_text, $salt, $iterations, $length); }

    // Create salted password hash using argon2id
    public function hash_password (string $password, string $salt): string {
        $salted_password_hash = hash('sha512', $password . $salt) . $salt;
        return $this->argon2id_hash($salted_password_hash);
    }

    // Verify salted password hash using argon2id
    public function verify_password_hash (string $password, string $password_hash, string $salt): bool {
        $salted_password_hash = hash('sha512', $password . $salt) . $salt;
        return password_verify($salted_password_hash, $password_hash);
    }

    // Creates mnemonic of specific length
    public function generate_mnemonic (int $length = 24): array {
        $mnemonic = null;

        try {
            $mnemonic = BIP39::Generate($length);
        } catch (MnemonicException | WordListException $e) {
            echo "Error occurred: " . $e;
        }

        $split_mnemonic = $mnemonic->words;

        $mnemonic = implode(' ', $split_mnemonic);
        $mnemonic_no_whitespace = preg_replace('/\s*/', '', $mnemonic);
        $mnemonic_hex = bin2hex($mnemonic_no_whitespace);
        $mnemonic_salt = $this->create_secure_random_string(32);
        $mnemonic_hash = $this->argon2id_hash($mnemonic_no_whitespace, $mnemonic_salt);

        return array (
            'mnemonic' => $mnemonic,
            'hex'      => $mnemonic_hex,
            'salt'     => $mnemonic_salt,
            'hash'     => $mnemonic_hash
        );
    }
}
