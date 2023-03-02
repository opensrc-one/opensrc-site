<?php
namespace backend\utils;

class StringTools {
    public function sanitize_string (string $str): string {
        return str_replace("\n", '', htmlspecialchars($str, ENT_QUOTES));
    }

    public function has_number (string $str): bool {
        return preg_match('~[0-9]+~', $str);
    }

    public function has_special (string $str): bool {
        return preg_match('/[^a-z0-9 ]+/i', $str);
    }
}