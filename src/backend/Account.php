<?php
namespace src\backend;

require_once('utils/Database.php');
require_once('utils/Sessions.php');
require_once('utils/Cryptography.php');
require_once('utils/TOTP.php');

use backend\utils\Database;
use backend\utils\Sessions;
use backend\utils\Cryptography;
use backend\utils\TOTP;
use Exception;
use PDO;
use RobThree\Auth\TwoFactorAuthException;

class Account {
    private Database $database;
    private Sessions $sessions;
    private Cryptography $crypto;
    private TOTP $totp;
    private ?PDO $conn;

    private int $uid;
    private string $username, $user_groups, $login_key, $data_key;

    public function __construct ($uid = null) {
        $this->database     = new Database();
        $this->sessions     = new Sessions();
        $this->crypto       = new Cryptography();
        $this->totp         = new TOTP();
        $this->conn         = $this->database->connect();

        if ($uid != null) {
            $query = "SELECT uid, username, user_groups, data_key FROM `opensrc_users` WHERE uid = :uid";
            $stmt = $this->conn->prepare($query);

            $stmt->bindParam(':uid', $uid);
            $stmt->execute();
            $db_data = $stmt->fetch();

            $this->uid         = intval($db_data['uid']);
            $this->username    = strval($db_data['username']);
            $this->user_groups = strval($db_data['user_groups']);
            $this->data_key    = strval($db_data['data_key']);
            $this->login_key   = null;
        } else {
            $session_user_data_json = $this->sessions->get('user-data', true);
            $session_user_data      = json_decode($session_user_data_json, true);

            $this->uid         = intval($session_user_data['uid']);
            $this->username    = strval($session_user_data['username']);
            $this->user_groups = strval($session_user_data['user_groups']);
            $this->data_key    = strval($session_user_data['data_key']);
            $this->login_key   = strval($session_user_data['login_key']);
        }
    }

    public function get_uid (): int {
        return $this->uid;
    }

    public function get_username (): string {
        return $this->username;
    }

    public function get_user_groups (): array {
        return json_decode($this->user_groups, true);
    }

    public function get_data_key (): string {
        return $this->data_key;
    }

    public function set_username (string $new_username): bool {
        if (strlen($new_username) < 3) {
            $this->sessions->set('res-err', 'invalid_username');
            return false;
        }

        $query = "SELECT username FROM `opensrc_users` WHERE LOWER(username) = :new_username";
        $stmt = $this->conn->prepare($query);

        $stmt->bindParam(':new_username', $new_username);
        $stmt->execute();

        if ($stmt->rowCount() > 0) {
            $this->sessions->set('res-err', 'username_taken');
            return false;
        }

        $query = "UPDATE `opensrc_users` SET username = :new_username WHERE uid = :uid";
        $stmt = $this->conn->prepare($query);

        $stmt->bindParam(':new_username', $new_username);
        $stmt->bindParam(':uid', $this->uid);
        $stmt->execute();

        $this->username = $new_username;
        $this->update_user_data_session();

        $this->sessions->set('res-err', 'username_change_valid');
        return true;
    }

    public function set_user_groups (array $new_user_groups): bool {
        $new_user_groups_json = json_encode($new_user_groups);

        $query = "UPDATE `opensrc_users` SET user_groups = :user_groups WHERE uid = :uid";
        $stmt = $this->conn->prepare($query);

        $stmt->bindParam(':user_groups', $new_user_groups_json);
        $stmt->bindParam(':uid', $this->uid);
        $stmt->execute();

        $this->user_groups = $new_user_groups_json;
        $this->update_user_data_session();

        $this->sessions->set('res-err', 'user_group_change_valid');
        return true;
    }

    /**
     * @throws TwoFactorAuthException
     */
    public function set_totp (bool $disable = false): bool {
        if ($disable) {
            $query = "UPDATE `opensrc_users` SET totp = NULL WHERE uid = :uid";
            $stmt = $this->conn->prepare($query);

            $stmt->bindParam(':uid', $this->uid);
            $stmt->execute();

            $this->sessions->set('res-err', 'totp_disabled');
            return true;
        }

        $totp_data = $this->totp->generate_secret();
        $totp_data['secret'] = $this->crypto->encrypt_string($totp_data['secret'], $this->data_key);
        $totp_data_json = json_encode($totp_data);

        $query = "UPDATE `opensrc_users` SET totp = :totp WHERE uid = :uid";
        $stmt = $this->conn->prepare($query);

        $stmt->bindParam(':totp', $totp_data_json);
        $stmt->bindParam(':uid', $this->uid);
        $stmt->execute();

        $this->sessions->set('res-err', 'totp_enabled');
        return true;
    }

    // TODO: Re-crypt data stored using mnemonic encryption key
    /**
     * @throws Exception
     */
    public function regenerate_mnemonic ($password): bool {
        $new_mnemonic      = $this->crypto->generate_mnemonic();
        $new_mnemonic_hex  = $new_mnemonic['hex'];
        $new_mnemonic_salt = $new_mnemonic['salt'];
        $new_mnemonic_hash = $new_mnemonic['hash'];
        $new_mnemonic_json = json_encode(array('mnemonic_hash' => $new_mnemonic_hash, 'salt' => $new_mnemonic_salt));

        $new_data_key = $this->crypto->pbkdf2_hash($new_mnemonic_hex, $new_mnemonic_salt, 256);
        $new_data_key_salt = $this->crypto->create_secure_random_string(32);
        $new_data_key_encryption_key = $this->crypto->pbkdf2_hash($password, $new_data_key_salt, 256);
        $new_data_key_encrypted = $this->crypto->encrypt_string($new_data_key, $new_data_key_encryption_key);
        $new_data_key_json = json_encode(array('key' => $new_data_key_encrypted, 'salt' => $new_data_key_salt));

        $query = "UPDATE `opensrc_users` SET mnemonic = :new_mnemonic, data_key = :new_data_key WHERE uid = :uid";
        $stmt = $this->conn->prepare($query);

        $stmt->bindParam(':new_mnemonic', $new_mnemonic_json);
        $stmt->bindParam(':new_data_key', $new_data_key_json);
        $stmt->bindParam(':uid', $this->uid);
        $stmt->execute();

        $this->data_key = $new_data_key;
        $this->update_user_data_session();

        $this->sessions->set('res-err', 'mnemonic_regenerated');
        return true;
    }

    public function validate_user_session (): bool {
        if ($this->sessions->get('user-data') == null) {
            return false;
        }

        $query = "SELECT uid, login_key FROM `opensrc_users` WHERE uid = :uid";
        $stmt = $this->conn->prepare($query);

        $stmt->bindParam(':uid', $this->uid);
        $stmt->execute();

        $db_data = $stmt->fetch();
        $login_key_hash = hash('sha512', $this->login_key);

        if (is_null($db_data['login_key']) || $login_key_hash !== $db_data['login_key']) {
            return false;
        }
        return true;
    }

    private function update_user_data_session (): void {
        $new_session_data_json = json_encode(array (
            'status'        => true,
            'uid'           => $this->uid,
            'username'      => $this->username,
            'user_groups'   => $this->user_groups,
            'data_key'      => $this->data_key
        ));
        $this->sessions->set('user-data', $new_session_data_json, true);
    }
}