<?php
namespace backend\utils;

require_once "EnvironmentVariable.php";

use PDO;
use PDOException;

class Database {
    private mixed $host, $db_name, $username, $password, $charset;

    public function __construct() {
        $env = new EnvironmentVariable();

        $this->host     = $env->get_variable('DB_HOST');
        $this->db_name  = $env->get_variable('DB_NAME');
        $this->username = $env->get_variable('DB_USER');
        $this->password = $env->get_variable('DB_PASS');
        $this->charset  = 'utf8mb4';
    }

    public function connect(): ?PDO {
        try {
            $dsn = 'mysql:host=' . $this->host . ';dbname=' . $this->db_name . ';charset=' . $this->charset;
            $pdo = new PDO($dsn, $this->username, $this->password);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            // echo "Database connection failed: " . $e->getMessage() . "\n";
            return null;
        }

        // echo "Database connection successful. \n";
        return $pdo;
    }
}