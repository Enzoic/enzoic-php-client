<?php

namespace Enzoic;

class Hashing
{
    public static function md5($toHash)
    {
        return md5($toHash);
    }

    public static function md5Binary($toHash)
    {
        return md5($toHash, TRUE);
    }

    public static function sha1($toHash)
    {
        return sha1($toHash);
    }

    public static function sha1Binary($toHash)
    {
        return sha1($toHash, TRUE);
    }

    public static function sha256($toHash)
    {
        return hash('sha256', $toHash);
    }

    public static function sha512($toHash)
    {
        return hash('sha512', $toHash);
    }

    public static function sha512Binary($toHash)
    {
        return hash('sha512', $toHash, true);
    }

    public static function whirlpool($toHash)
    {
        return hash('whirlpool', $toHash);
    }

    public static function whirlpoolBinary($toHash)
    {
        return hash('whirlpool', $toHash, true);
    }

    public static function myBB($toHash, $salt)
    {
        return self::md5(self::md5($salt) . self::md5($toHash));
    }

    public static function vBulletin($toHash, $salt)
    {
        return self::md5(self::md5($toHash) . $salt);
    }

    public static function phpbb3($toHash, $hashSalt)
    {
        $itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

        $output = '';

        // Check for correct hash
        if (substr($hashSalt, 0, 3) != '$H$')
        {
            return $output;
        }

        $count_log2 = strpos($itoa64, $hashSalt[3]);

        if ($count_log2 < 7 || $count_log2 > 30)
        {
            return $output;
        }

        $count = 1 << $count_log2;
        $salt = substr($hashSalt, 4, 8);

        if (strlen($salt) != 8)
        {
            return $output;
        }

        /**
         * We're kind of forced to use MD5 here since it's the only
         * cryptographic primitive available in all versions of PHP
         * currently in use.  To implement our own low-level crypto
         * in PHP would result in much worse performance and
         * consequently in lower iteration counts and hashes that are
         * quicker to crack (by non-PHP code).
         */
        if (PHP_VERSION >= 5)
        {
            $hash = md5($salt . $toHash, true);
            do
            {
                $hash = md5($hash . $toHash, true);
            }
            while (--$count);
        }
        else
        {
            $hash = pack('H*', md5($salt . $toHash));
            do
            {
                $hash = pack('H*', md5($hash . $toHash));
            }
            while (--$count);
        }

        $output = substr($hashSalt, 0, 12);
        $output .= self::_hash_encode64($hash, 16, $itoa64);

        return $output;
    }

    /**
     * Encode hash
     */
    private static function _hash_encode64($input, $count, &$itoa64)
    {
        $output = '';
        $i = 0;

        do
        {
            $value = ord($input[$i++]);
            $output .= $itoa64[$value & 0x3f];

            if ($i < $count)
            {
                $value |= ord($input[$i]) << 8;
            }

            $output .= $itoa64[($value >> 6) & 0x3f];

            if ($i++ >= $count)
            {
                break;
            }

            if ($i < $count)
            {
                $value |= ord($input[$i]) << 16;
            }

            $output .= $itoa64[($value >> 12) & 0x3f];

            if ($i++ >= $count)
            {
                break;
            }

            $output .= $itoa64[($value >> 18) & 0x3f];
        }
        while ($i < $count);

        return $output;
    }

    public static function bCrypt($toHash, $salt)
    {
        return crypt($toHash, $salt);
    }

    public static function customAlgorithm1($toHash, $salt)
    {
        return self::xor(self::sha512Binary($toHash . $salt), self::whirlpoolBinary($salt . $toHash));
    }

    public static function customAlgorithm2($toHash, $salt)
    {
        return self::md5($toHash . $salt);
    }

    public static function customAlgorithm3($toHash)
    {
        return self::md5("kikugalanet".$toHash);
    }

    public static function customAlgorithm4($toHash, $salt)
    {
        return crypt(self::md5($toHash), $salt);
    }

    public static function customAlgorithm5($toHash, $salt)
    {
        return self::sha256(self::md5($toHash . $salt));
    }

    public static function customAlgorithm6($toHash, $salt)
    {
        return self::sha1($toHash . $salt);
    }

    public static function customAlgorithm7($toHash, $salt)
    {
        $secret = 'd2e1a4c569e7018cc142e9cce755a964bd9b193d2d31f02d80bb589c959afd7e';
        $derivedSalt = self::sha1($salt);
        return hash_hmac('sha256', $derivedSalt.$toHash, $secret);
    }

    public static function customAlgorithm9($toHash, $salt)
    {
        $result = self::sha512($toHash.$salt);
        for ($i = 0; $i < 11; $i++) {
            $result = self::sha512($result);
        }
        return $result;
    }

    public static function customAlgorithm10($toHash, $salt)
    {
        return self::sha512($toHash.":".$salt);
    }

    public static function authMeSHA256($toHash, $salt)
    {
        return '$SHA$'.$salt."$".self::sha256(self::sha256($toHash).$salt);
    }

    public static function crc32($toHash)
    {
        return hash('crc32b', $toHash);
    }

    public static function md5Crypt($toHash, $salt)
    {
        return crypt($toHash, $salt);
    }

    public static function sha256Crypt($toHash, $salt)
    {
        return crypt($toHash, $salt);
    }

    public static function sha512Crypt($toHash, $salt)
    {
        return crypt($toHash, $salt);
    }

    public static function osCommerce_AEF($toHash, $salt)
    {
        return self::md5($salt . $toHash);
    }

    public static function desCrypt($toHash, $salt)
    {
        return crypt($toHash, $salt);
    }

    public static function mySqlPre4_1($toHash)
    {
        $nr = 1345345333;
        $add = 7;
        $nr2 = 0x12345671;

        for ($i = 0; $i < strlen($toHash); $i++) {
            $c = substr($toHash, $i, 1);

            if ($c == ' ' || $c == '\t')
                continue;

            $tmp = ord($c);
            $nr ^= ((($nr & 63) + $add) * $tmp) + ($nr << 8);
            $nr2 += ($nr2 << 8) ^ $nr;
            $add += $tmp;
        }

        $result1 = $nr & ((1 << 31) - 1);
        $result2 = $nr2 & ((1 << 31) - 1);

        return sprintf('%x', $result1) . sprintf('%x', $result2);
    }

    public static function mySqlPost4_1($toHash)
    {
        return '*' . self::sha1(self::sha1Binary($toHash));
    }

    public static function peopleSoft($toHash)
    {
        return base64_encode(self::sha1Binary(mb_convert_encoding($toHash, 'UTF-16LE')));
    }

    public static function punBB($toHash, $salt)
    {
        return self::sha1($salt . self::sha1($toHash));
    }

    public static function ave_DataLife_Diferior($toHash)
    {
        return self::md5(self::md5($toHash));
    }

    public static function djangoMD5($toHash, $salt)
    {
        return "md5$" . $salt . "$" . self::md5($salt . $toHash);
    }

    public static function djangoSHA1($toHash, $salt)
    {
        return "sha1$" . $salt . "$" . self::sha1($salt . $toHash);
    }

    public static function pliggCMS($toHash, $salt)
    {
        return $salt . self::sha1($salt . $toHash);
    }

    public static function runCMS_SMF1_1($toHash, $salt)
    {
        return self::sha1($salt . $toHash);
    }

    public static function ntlm($toHash)
    {
        // Convert the password from UTF8 to UTF16 (little endian)
        $preHash = iconv('UTF-8', 'UTF-16LE', $toHash);
        $hash = hash("md4", $preHash);
        return $hash;
    }

    public static function sha1Dash($toHash, $salt)
    {
        return self::sha1('--' . $salt . '--' . $toHash . '--');
    }

    public static function sha384($toHash)
    {
        return hash('sha384', $toHash);
    }

    public static function xor($value1, $value2)
    {
        // Our output text
        $outText = '';

        // Iterate through each character
        for ($i = 0; $i < strlen($value1); $i++) {
            $outText .= bin2hex($value1[$i] ^ $value2[$i]);
        }
        return $outText;
    }

    public static function argon2($toHash, $salt)
    {
        // defaults
        $iterations = 3;
        $memoryCost = 1024;
        $parallelism = 2;
        $hashLength = 20;
        $justSalt = $salt;
        $argonTypeArg = '-d';

        // check if salt has settings encoded in it
        if (substr($salt, 0, 7) === '$argon2') {

            // apparently has settings encoded in it - use these
            if (substr($salt, 0, 8) === ('$argon2i')) {
                $argonTypeArg = '-i';
            }

            $saltParts = preg_split('/\$/', $salt);

            if (count($saltParts) === 5) {
                $justSalt = base64_decode($saltParts[4]);
                $saltParams = preg_split('/,/', $saltParts[3]);

                for ($i = 0; $i < count($saltParams); $i++) {
                    $currentParam = $saltParams[$i];
                    $currentParamValues = preg_split('/=/', $currentParam);

                    switch ($currentParamValues[0]) {
                        case 't':
                            $iterations = is_numeric($currentParamValues[1]) ? $currentParamValues[1] : $iterations;
                            break;
                        case 'm':
                            $memoryCost = is_numeric($currentParamValues[1]) ? $currentParamValues[1] : $memoryCost;
                            break;
                        case 'p':
                            $parallelism = is_numeric($currentParamValues[1]) ? $currentParamValues[1] : $parallelism;
                            break;
                        case 'l':
                            $hashLength = is_numeric($currentParamValues[1]) ? $currentParamValues[1] : $hashLength;
                            break;
                    }
                }
            }
        }

        // replace invalid chars in justSalt
        $justSalt = str_replace('\'', '\'\\\'\'', $justSalt);

        $cmd = 'argon2 \'' . $justSalt . '\' ' . $argonTypeArg . ' -t ' . $iterations .
            ' -k ' . $memoryCost . ' -p ' . $parallelism . ' -l ' . $hashLength . ' -e';

        $descriptorspec = array(
            0 => array("pipe", "r"),
            1 => array("pipe", "w")
        );

        $process = proc_open($cmd, $descriptorspec, $pipes);

        if (is_resource($process)) {
            fwrite($pipes[0], $toHash);
            fclose($pipes[0]);

            $response = stream_get_contents($pipes[1]);
            fclose($pipes[1]);
            $return_value = proc_close($process);

            // strip trailing \n from response
            $response = substr($response, 0, strlen($response) - 1);
            return $response;
        }
    }

    public static function lastIndexOf($haystack, $needle)
    {
        $size = strlen($haystack);
        $pos = strpos(strrev($haystack), $needle);

        if ($pos === false)
            return false;

        return $size - $pos;
    }
}
