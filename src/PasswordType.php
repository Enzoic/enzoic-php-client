<?php

namespace Enzoic;

abstract class PasswordType
{
    const Plaintext = 0;
    const MD5 = 1;
    const SHA1 = 2;
    const SHA256 = 3;
    const TripleDES = 4;
    const IPBoard_MyBB = 5;
    const vBulletinPre3_8_5 = 6;
    const vBulletinPost3_8_5 = 7;
    const BCrypt = 8;
    const CRC32 = 9;
    const PHPBB3 = 10;
    const CustomAlgorithm1 = 11;
    const SCrypt = 12;
    const CustomAlgorithm2 = 13;
    const SHA512 = 14;
    const CustomAlgorithm3 = 15; // gpotato.com
    const MD5Crypt = 16;
    const CustomAlgorithm4 = 17; // edmodo.com
    const CustomAlgorithm5 = 18; // wrestletalk.tv; wrestlepod.com
    const osCommerce_AEF = 19; // citrus.ua; md5(salt.password)
    const DESCrypt = 20;
    const MySQLPre4_1 = 21;
    const MySQLPost4_1 = 22;
    const PeopleSoft = 23;       // Base64(SHA1_binary(UTF16_LE(password)))
    const PunBB = 24;
    const CustomAlgorithm6 = 25; // sha1(password.salt) - newrune.net
    const PartialMD5_20 = 26;
    const AVE_DataLife_Diferior = 27;
    const DjangoMD5 = 28;
    const DjangoSHA1 = 29;
    const PartialMD5_29 = 30;
    const PliggCMS = 31;
    const RunCMS_SMF1_1 = 32;  // sha1(username.salt) - set salt to username column
    const NTLM = 33;
    const SHA1Dash = 34; // sha1(--salt--password--)
    const SHA384 = 35;
    const CustomAlgorithm7 = 36; // sha256hmac(sha1(id).pass.salt) (Wattpad)
    const CustomAlgorithm8 = 37;
    const CustomAlgorithm9 = 38;
    const SHA512Crypt = 39;
    const CustomAlgorithm10 = 40;
    const HMACSHA1_SaltAsKey = 41;
    const AuthMeSHA256 = 42;
    const SHA256Crypt = 43;

    const Unknown = 97;
    const UnusablePassword = 98;
    const None = 99;
}