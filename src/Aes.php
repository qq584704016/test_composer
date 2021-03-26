<?php
/**
 * author       :   zhenyang
 * createTime   :   2021/3/26 9:54 下午
 */

class Aes
{
    /**
     * AES加密
     * @param string $decrypted_data
     * @param string $secret_key
     * @param string $iv
     * @return string|null
     */
    public  static function encrypt($decrypted_data, $secret_key, $iv)
    {
        if (empty($secret_key) || strlen($iv) < 16)
        {
            return null;
        }
        $blocksize      = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
        $padded_data    = Aes::pkcs5_pad($decrypted_data, $blocksize);
        $encrypted      = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $secret_key, $padded_data, MCRYPT_MODE_CBC, $iv);
        $encrypted_data = self::urlsafe_b64encode($encrypted);
        return $encrypted_data;
    }
    /**
     * AES解密
     * @param string $encrypted_data
     * @param string $secret_key
     * @param string $iv
     * @return string|null
     */
    public static function decrypt($encrypted_data, $secret_key, $iv)
    {
        if (empty($secret_key) || strlen($iv) < 16)
        {
            return null;
        }
        $encrypted_data = self::urlsafe_b64decode($encrypted_data);
        $decrypted      = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $secret_key, $encrypted_data, MCRYPT_MODE_CBC, $iv);
        $decrypted_data = Aes::pkcs5_unpad($decrypted, "\0");
        return $decrypted_data;
    }
    /**
     * 采用pkcs5pad方式填充数据
     * @param type $text
     * @param type $blocksize
     * @return type
     */
    public static function pkcs5_pad($text, $blocksize)
    {
        $pad = $blocksize - (strlen($text) % $blocksize);
        return $text . str_repeat(chr($pad), $pad);
    }
    /**
     * 删除多余的填充数据
     * @param type $text
     * @return boolean
     */
    public static function pkcs5_unpad($text)
    {
        $pad = ord($text{strlen($text) - 1});
        if ($pad > strlen($text))
        {
            return false;
        }
        if (strspn($text, chr($pad), strlen($text) - $pad) != $pad)
        {
            return false;
        }
        return substr($text, 0, -1 * $pad);
    }

    public static function urlsafe_b64encode($string) {
        $data = base64_encode($string);
        $data = str_replace(array('+','/','='),array('-','_',''),$data);
        return $data;
    }

    public static function urlsafe_b64decode($string) {
        $data = str_replace(array('-','_'),array('+','/'),$string);
        $mod4 = strlen($data) % 4;
        if ($mod4) {
            $data .= substr('====', $mod4);
        }
        return base64_decode($data);
    }
}