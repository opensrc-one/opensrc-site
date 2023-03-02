<?php

require_once('../src/backend/utils/TOTP.php');
require_once ('../src/backend/utils/Cryptography.php');

use backend\utils\TOTP;

$totp = new TOTP();

$secret = "";
echo $totp->verify_secret($secret, '');

// $secret = $totp->generate_secret();
// echo $secret;

