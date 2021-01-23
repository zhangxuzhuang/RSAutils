package com.zhang;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import javax.crypto.Cipher;
import java.security.Key;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSAUtils {
    public static final String KEY_ALGORITHM = "RSA";
    /**
     * 公钥
     */
    public static final String PUBLICKEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCQHQQYVVDPmEBI2NRlA1xqCZMMjbE/vvOSzuV+FEXaxK8orfcpyzoCJhQ0dm9Y5wdycrnQPxDVeSVHIuHdECaW2K6+IQjZKpbvyaOLkOYCnr95OPCg/emIqgXAE/s2GjkJ1pOBjZWmHRX+wKa42C7UsuSNB7rrLUuOfgaY6Nks8QIDAQAB";
    /**
     * 私钥
     */
    public static final String PRIVATEKEY = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJAdBBhVUM+YQEjY1GUDXGoJkwyNsT++85LO5X4URdrEryit9ynLOgImFDR2b1jnB3JyudA/ENV5JUci4d0QJpbYrr4hCNkqlu/Jo4uQ5gKev3k48KD96YiqBcAT+zYaOQnWk4GNlaYdFf7AprjYLtSy5I0HuustS45+Bpjo2SzxAgMBAAECgYAOA5RTXXCHT3Ho45T74bDJ6vZuwRScc1AyVYZBlW0ZkgjKduhTGx0f+l36oA3B4m159qgVFRzo9Wfnm//ExH5MBF8ecIPiKE9RH16ATed4t13xH6BOphPP1mxoto3K7HnWBwVBlRma9Md6exRBZqOqc048dCwVYCH4CZbMIGXqMQJBAPf8mAoIoBZO6cJLRah0g4ohqAy2WyjbPGzGSHXOApb4V4VSbHTKeV0InpE2V4k8otBUv9IzTTTsqVdWzk4YL1UCQQCUxSgSpkvze+e2nornIHMd1Doc3Zc9hKP1vIJigS0nt1ZBNxieEYJgRVJDp6JOiqyvKEtnuFIU1kWdopZLx28tAkAxH3ImmqrLgHpBqJN12Q6tcBlP21eXckY37dcwrsxIh40etcMSJ4F+8lQmw7L3VnGR/xe4Vb03fKHW0TUwtw25AkEAkc0LsgNi6lTjybllvpCx4WkOLx4IzFTDb+F5E1swSv1GPpHlwXy9fuZRclbHHhyQkvV1uUgOwbch8RTYIZpqXQJBALA4WSkoViz/1qVpbl3WBNbP8Yo2dcu2gxuE1Skx4aAg3oTtp010vUo1764ZLVHbovd4hWe3uUpovAvXv/hi1E8=";

    /**
     * 加密
     * 用公钥加密
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static String encryptByPublicKey(String data, String key) throws Exception {
        return encryptBASE64(encryptByPublicKey(data.getBytes(), key));
    }

    /**
     * 解密
     * 用私钥解密
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static String decryptByPrivateKey(String data, String key) throws Exception {
        return new String(decryptByPrivateKey(decryptBASE64(data), key));
    }

    /**
     * 加密
     * 用公钥加密
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptByPublicKey(byte[] data, String key) throws Exception {
        // 对公钥解密
        byte[] keyBytes = decryptBASE64(key);

        // 取得公钥
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key publicKey = keyFactory.generatePublic(x509KeySpec);

        // 对数据加密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        return cipher.doFinal(data);
    }

    /**
     * 解密
     * 用私钥解密
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptByPrivateKey(byte[] data, String key) throws Exception {
        // 对密钥解密
        byte[] keyBytes = decryptBASE64(key);

        // 取得私钥
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        Key privateKey = keyFactory.generatePrivate(pkcs8KeySpec);

        // 对数据解密
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        return cipher.doFinal(data);
    }

    /**
     * BASE64解密
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptBASE64(String key) throws Exception {
        return (new BASE64Decoder()).decodeBuffer(key);
    }

    /**
     * BASE64加密
     * @param key
     * @return
     * @throws Exception
     */
    public static String encryptBASE64(byte[] key) throws Exception {
        return (new BASE64Encoder()).encodeBuffer(key);
    }

    public static void main(String[] args) {
        try {
            String data = "{\n" +
                    "    \"appKey\": \"xxx\",\n" +
                    "    \"userSn\": \"xxx123\",\n" +
                    "    \"timestamp\": \"1514739661000\",\n" +
                    "    \"version\": \"1.0\",\n" +
                    "    \"params\": {}\n" +
                    "}";
            String encryptData = RSAUtils.encryptByPublicKey(data, PUBLICKEY);
            System.out.println("加密后：" + encryptData);
            String decryptData = RSAUtils.decryptByPrivateKey(encryptData, PRIVATEKEY);
            System.out.println("解密后：" + decryptData);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
