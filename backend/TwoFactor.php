<?php

use RobThree\Auth\TwoFactorAuth;
class TwoFactor {
    private $ifa;
    public function __construct() {
        $this->ifa = new TwoFactorAuth();
    }

    public function generateSecret(): string {
        return $this->ifa->createSecret();
    }

    public function verifySecret($secret, $code): bool {
        $discrepancy = 1;
        $time = null;
        $timeslice = null;
        return $this->ifa->verifyCode($secret, $code);
    }
}