<?php
namespace backend\utils;

require_once (realpath(dirname(__FILE__) . '/../../../vendor/autoload.php'));

use RobThree\Auth\Algorithm;
use RobThree\Auth\TwoFactorAuth;
use RobThree\Auth\TwoFactorAuthException;

class TOTP {
    private TwoFactorAuth $totp;
    private const VERIFY_CONFIG = array (
        'discrepancy' => 1,
        'time'        => null,
        'time_slice'  => null
    );
    private const CONSTRUCT_CONFIG = array (
        'issuer'           => 'opensrc.one',
        'digits'           => 6,
        'period'           => 30,
        'algorithm'        => Algorithm::Sha1,
        'qr_code_provider' => null,
        'rng_provider'     => null,
        'time_provider'    => null
    );
    private const GENERATE_CONFIG = array('bits' => 80);

    /**
     * @throws TwoFactorAuthException
     */
    public function __construct (
        $issuer           = self::CONSTRUCT_CONFIG['issuer'],
        $digits           = self::CONSTRUCT_CONFIG['digits'],
        $period           = self::CONSTRUCT_CONFIG['period'],
        $algorithm        = self::CONSTRUCT_CONFIG['algorithm'],
        $qr_code_provider = self::CONSTRUCT_CONFIG['qr_code_provider'],
        $rng_provider     = self::CONSTRUCT_CONFIG['rng_provider'],
        $time_provider    = self::CONSTRUCT_CONFIG['time_provider']
    ) {
        $this->totp = new TwoFactorAuth(
            $issuer, $digits, $period, $algorithm, $qr_code_provider, $rng_provider, $time_provider
        );
    }

    /**
     * @throws TwoFactorAuthException
     */
    public function generate_secret (int $bits = self::GENERATE_CONFIG['bits']): array {
        return array (
            'secret'      => $this->totp->createSecret($bits),
            'discrepancy' => self::GENERATE_CONFIG['discrepancy'],
            'time'        => self::GENERATE_CONFIG['time'],
            'time_slice'  => self::GENERATE_CONFIG['time_slice']
        );
    }

    public function verify_secret (
        string $secret,
        string $code,
        int $discrepancy = self::VERIFY_CONFIG['discrepancy'],
        $time            = self::VERIFY_CONFIG['time'],
        $time_slice      = self::VERIFY_CONFIG['time_slice']
    ): bool { return $this->totp->verifyCode($secret, $code, $discrepancy, $time, $time_slice); }
}