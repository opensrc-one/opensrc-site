<?php

require_once ('../src/backend/utils/TwoFactor.php');
require_once ('../src/backend/utils/Cryptography.php');

use backend\utils\TwoFactor;

$totp = new TwoFactor();

$secret = "";
echo $totp->verify_secret($secret, '');

// $secret = $totp->generate_secret();
// echo $secret;

