<?php
namespace src\backend;

require_once('utils/Database.php');
require_once('utils/Sessions.php');
require_once('utils/Cookies.php');
require_once('utils/Cryptography.php');
require_once('utils/TOTP.php');
require_once('utils/StringTools.php');

use backend\utils\Database;
use backend\utils\Sessions;
use backend\utils\Cookies;
use backend\utils\Cryptography;
use backend\utils\TOTP;
use backend\utils\StringTools;
use PDO;

class AccountAuth {
    private Database $database;
    private Sessions $sessions;
    private Cookies $cookies;
    private Cryptography $crypto;
    private TOTP $totp;
    private StringTools $string_tools;
    private ?PDO $conn;

    public function __construct () {
        $this->database     = new Database();
        $this->sessions     = new Sessions();
        $this->cookies      = new Cookies();
        $this->crypto       = new Cryptography();
        $this->totp         = new TOTP();
        $this->string_tools = new StringTools();
        $this->conn         = $this->database->connect();
    }

    public function create_account ($username, $password, $confirm_password, $registration_key = false): bool {
        $username = $this->string_tools->sanitize_string($username);
        $username_lower = strtolower($username);

        // Check if password and confirm password are the same
        if ($password !== $confirm_password) {
            $this->cookies->set('res-err', 'password_mismatch');
            return false;
        }

        // Check if password contains a number and special character
        $has_special_char = $this->string_tools->has_special($password);
        $has_number_char = $this->string_tools->has_number($password);
        if (strlen($password) < 6 || !$has_number_char || !$has_special_char) {
            $this->cookies->set('res-err', 'invalid_password');
            return false;
        }

        // Check if username has at more than 3 characters
        if (strlen($username) < 3) {
            $this->cookies->set('res-err', 'invalid_username');
            return false;
        }

        // Check whether username is already assigned to an account
        $query = "SELECT username FROM `opensrc_users` WHERE LOWER(username) = :username";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':username', $username_lower);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            $this->cookies->set('res-err', 'username_taken');
            return false;
        }

        if ($registration_key) {
            $registration_key_hash = hash('sha512', $registration_key);

            $query = "SELECT id, `key`, status FROM `opensrc_registration_keys` WHERE `key` = :key";
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':key', $registration_key_hash);
            $stmt->execute();

            $registration_key_data = $stmt->fetch();

            if ($stmt->rowCount() < 1 || !$registration_key_data['status']) {
                $this->cookies->set('res-err', 'invalid_registration_key');
                return false;
            }

            $status = 0;
            $query = "UPDATE `opensrc_registration_keys` SET status = :status WHERE id = :id";
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':status', $status);
            $stmt->bindParam(':id', $registration_key_data['id']);
            $stmt->execute();
        }

        $mnemonic = $this->crypto->generate_mnemonic();
        $mnemonic_phrase = $mnemonic['mnemonic'];
        $mnemonic_hex = $mnemonic['hex'];
        $mnemonic_salt = $mnemonic['salt'];
        $mnemonic_hash = $mnemonic['hash'];
        $mnemonic_json = json_encode(array('mnemonic_hash' => $mnemonic_hash, 'salt' => $mnemonic_salt));

        $data_key = $this->crypto->pbkdf2_hash($mnemonic_hex, $mnemonic_salt, 256);
        $data_key_salt = $this->crypto->create_secure_random_string(32);
        $data_key_encryption_key = $this->crypto->pbkdf2_hash($password, $data_key_salt, 256);
        $data_key_encrypted = $this->crypto->encrypt_string($data_key, $data_key_encryption_key);
        $data_key_json = json_encode(array('key' => $data_key_encrypted, 'salt' => $data_key_salt));

        // Generate salt and create password hash
        $password_salt = $this->crypto->create_secure_random_string(32);
        $password_hash = $this->crypto->hash_password($password, $password_salt);
        $password_json = json_encode(array('password_hash' => $password_hash, 'salt' => $password_salt));

        // Insert new user into database
        $query = "INSERT INTO `opensrc_users` (username, password, mnemonic, data_key) VALUES (?, ? ,?, ?)";
        $stmt = $this->conn->prepare($query);
        $stmt->execute([$username, $password_json, $mnemonic_json, $data_key_json]);

        $this->sessions->set('res-data', $mnemonic_phrase, true);
        $this->cookies->set('res-err', 'register_valid');
        return true;
    }

    // Verify user login using username, password, and/or TOTP
    public function login_account ($username, $password, $totp_code = null): bool {
        if ($this->sessions->get('user-data') !== null) { return true; }

        $username_lower = strtolower($username);

        $query = "SELECT uid, username, password, user_groups, totp FROM `opensrc_users` WHERE LOWER(username) = :username";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':username', $username_lower);
        $stmt->execute();
        $db_data = $stmt->fetch();

        $db_password_json = json_decode($db_data['password'], true);
        $db_password_hash = $db_password_json['password_hash'];
        $db_salt = $db_password_json['salt'];

        if ($stmt->rowCount() < 1 || !$this->crypto->verify_password_hash($password, $db_password_hash, $db_salt)) {
            $this->cookies->set('res-err', 'invalid_login');
            return false;
        }

        $db_data_key_json = json_decode($db_data['data_key'], true);
        $data_key_encryption_key = $this->crypto->pbkdf2_hash($password, $db_data_key_json['salt'], 256);
        $db_data_key_decrypted = $this->crypto->decrypt_string($db_data_key_json['key'], $data_key_encryption_key);

        if (!is_null($db_data['totp'])) {
            $totp_json = json_decode($db_data['totp'], true);
            $secret = $this->crypto->decrypt_string($totp_json['secret'], $db_data_key_decrypted);
            if (
                $totp_code == null
                || !$this->totp->verify_secret($secret, $totp_code, $totp_json['discrepancy'],
                                               $totp_json['time'], $totp_json['time_slice'])
            ) {
                $this->cookies->set('res-err', 'invalid_totp');
                return false;
            }
        }

        $login_key = $this->crypto->create_secure_random_string(64);
        $login_key_hash = hash('sha256', $login_key);

        $query = "UPDATE `opensrc_users` SET login_key = :login_key WHERE uid = :uid";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':login_key', $login_key_hash);
        $stmt->bindParam(':uid', $db_data['uid']);
        $stmt->execute();

        $session_data_json = json_encode(array (
            'status'        => true,
            'uid'           => $db_data['uid'],
            'username'      => $db_data['username'],
            'user_groups'   => $db_data['user_groups'],
            'data_key'      => $db_data_key_decrypted,
            'login_key'     => $login_key
        ));

        $this->sessions->set('user-data', $session_data_json, true);
        $this->cookies->set('res-msg', 'login_valid');
        return true;
    }

    public function set_password ($uid, $new_password, $current_password = false, $mnemonic = false): bool {
        $query = "SELECT uid, password, mnemonic, data_key FROM `opensrc_users` WHERE uid = :uid";
        $stmt = $this->conn->prepare($query);
        $stmt->bindParam(':uid', $uid);
        $stmt->execute();

        $db_data = $stmt->fetch();

        $password_hash_array = json_decode($db_data['password'], true);
        $password_hash = $password_hash_array['password_hash'];
        $password_salt = $password_hash_array['salt'];

        $data_key_array = json_decode($db_data['data_key'], true);
        $data_key = $data_key_array['key'];
        $data_key_salt = $data_key_array['salt'];

        // $this->crypto->pbkdf2_hash($password, $data_key_salt, 256);

        if ($this->crypto->verify_password_hash($current_password, $password_hash, $password_salt)) {
            $data_key_encryption_key = $this->crypto->pbkdf2_hash($current_password, $data_key_salt, 256);
            $decrypted_data_key = $this->crypto->decrypt_string($data_key, $data_key_encryption_key);

            $new_data_key_salt = $this->crypto->create_secure_random_string(32);
            $new_data_key_encryption_key = $this->crypto->pbkdf2_hash($new_password, $new_data_key_salt, 256);
            $new_encrypted_data_key = $this->crypto->encrypt_string($decrypted_data_key, $new_data_key_encryption_key);
            $new_data_key_json = json_encode(array('key' => $new_encrypted_data_key, 'salt' => $new_data_key_salt));

            // Generate salt and create password hash
            $new_password_salt = $this->crypto->create_secure_random_string(32);
            $new_password_hash = $this->crypto->hash_password($new_password, $new_password_salt);
            $new_password_json = json_encode(array('password_hash' => $new_password_hash, 'salt' => $new_password_salt));

            $query = "UPDATE `opensrc_users` SET password = :password, data_key = :data_key WHERE uid = :uid";
            $stmt = $this->conn->prepare($query);
            $stmt->bindParam(':password', $new_password_json);
            $stmt->bindParam(':data_key', $new_data_key_json);
            $stmt->bindParam(':uid', $uid);
            $stmt->execute();
        }
    }
}