<?php
namespace backend\utils;

require_once (realpath(dirname(__FILE__) . '/../../vendor/autoload.php'));

use Dotenv\Dotenv;

class EnvironmentVariable {

    public function get_variable (string $name) {
        $dotenv = Dotenv::createImmutable(realpath(dirname(__FILE__) . '/../'));
        $dotenv->load();

        return $_ENV[$name];
    }
}