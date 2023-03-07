<?php
namespace src\frontend;

ini_set('display_errors', '1');
ini_set('display_startup_errors', '1');
error_reporting(E_ALL);

require_once('../../backend/AccountAuth.php');

use src\backend\AccountAuth;

$account_auth = new AccountAuth();

$post_check_array = array('request-register', 'username', 'password', 'confirm-password', 'registration-key');
if (array_diff($post_check_array, array_keys($_POST))) {
    header('Location: ../');
    exit;
}

$username         = $_POST['username'];
$password         = $_POST['password'];
$confirm_password = $_POST['confirm-password'];
$registration_key = $_POST['registration-key'];

if (!$account_auth->create_account($username, $password, $confirm_password, $registration_key)) {
    header('Location: ../');
    exit;
}