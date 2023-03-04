<?php
namespace backend\utils;

require_once('Cryptography.php');
require_once('EnvironmentVariable.php');

session_start();
session_regenerate_id();

class Sessions {
    private Cryptography $crypto;
    private EnvironmentVariable $env;

    public function __construct () {
        $this->crypto = new Cryptography();
        $this->env    = new EnvironmentVariable();
    }

    public function set (string $name, $value, bool $encrypt = false): void {
        $value = strval($value);
        if ($encrypt) {
            $value = $this->crypto->encrypt_string($value, $this->env->get_variable('SESSION_ENC_KEY'));
        }
        $_SESSION[$name] = $value;
    }

    public function get (string $name, bool $decrypt = false): string|null {
        if (!isset($_SESSION[$name])) return null;

        $value = $_SESSION[$name];
        if ($decrypt) {
            $value = $this->crypto->decrypt_string($value, $this->env->get_variable('SESSION_ENC_KEY'));
        }
        return $value;
    }

    public function unset (string $name): void {
        unset($_SESSION[$name]);
    }

    private function destroy_session (): void {
        session_unset();
        session_destroy();
    }
}