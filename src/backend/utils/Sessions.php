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

    public function validate_all (): void {
        $this->validate_user_agent();
        $this->validate_remote_address();
        $this->validate_access_time();
    }

    public function set_security_sessions (): void {
        $_SESSION['user_agent']  = $_SERVER['HTTP_USER_AGENT'];
        $_SESSION['ip_address']  = $_SERVER['REMOTE_ADDR'];
        $_SESSION['last_access'] = time();
    }

    public function set (string $name, $value, bool $set_last_access = true, bool $encrypt = false): void {
        if ($set_last_access) {
            $_SESSION['last_access'] = time();
        }

        $value = strval($value);
        if ($encrypt) {
            $value = $this->crypto->encrypt_string($value, $this->env->get_variable('SESSION_ENC_KEY'));
        }
        $_SESSION[$name] = $value;
    }

    public function get (string $name, bool $set_last_access = true, bool $decrypt = false): string|null {
        if (!isset($_SESSION[$name])) return null;
        if ($set_last_access) $_SESSION['last_access'] = time();

        $value = $_SESSION[$name];
        if ($decrypt) {
            $value = $this->crypto->decrypt_string($value, $this->env->get_variable('SESSION_ENC_KEY'));
        }
        return $value;
    }

    public function unset (string $name): void {
        unset($_SESSION[$name]);
    }

    public function validate_user_agent (): void {
        if (isset($_SESSION['user_agent']) && $_SERVER['HTTP_USER_AGENT'] != $_SESSION['user_agent']) {
            $this->destroy_session();
        }
    }

    public function validate_remote_address (): void {
        if (isset($_SESSION['ip_address']) && $_SERVER['REMOTE_ADDR'] != $_SESSION['ip_address']) {
            $this->destroy_session();
        }
    }

    public function validate_access_time (): void {
        if (isset($_SESSION['last_access']) && time() > $_SESSION['last_access'] + (6 * 3600)) {
            $this->destroy_session();
        }
    }

    private function destroy_session (): void {
        session_unset();
        session_destroy();
    }
}