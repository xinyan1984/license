package com.test;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * RSA 加解密工具类
 */
public class RSAEncrypt {
    /**
     * 定义加密方式
     */
    private final static String KEY_RSA = "RSA";
    /**
     * 定义签名算法
     */
    private final static String KEY_RSA_SIGNATURE = "MD5withRSA";
    /**
     * 定义公钥算法
     */
    private final static String KEY_RSA_PUBLICKEY = "RSAPublicKey";
    /**
     * 定义私钥算法
     */
    private final static String KEY_RSA_PRIVATEKEY = "RSAPrivateKey";

    /**
     * 初始化密钥
     * @return
     */
    public static Map<String, Object> init() {
        Map<String, Object> map = null;
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(KEY_RSA);
            generator.initialize(1024);
            KeyPair keyPair = generator.generateKeyPair();
            // 公钥
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            // 私钥
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            // 将密钥封装为map
            map = new HashMap();
            map.put(KEY_RSA_PUBLICKEY, publicKey);
            map.put(KEY_RSA_PRIVATEKEY, privateKey);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return map;
    }

    /**
     * 用私钥对信息生成数字签名
     * @param data 加密数据
     * @param privateKey 私钥
     * @return
     */
    public static String sign(byte[] data, String privateKey) {
        String str = "";
        try {
            // 解密由base64编码的私钥
            byte[] bytes = decryptBase64(privateKey);
            // 构造PKCS8EncodedKeySpec对象
            PKCS8EncodedKeySpec pkcs = new PKCS8EncodedKeySpec(bytes);
            // 指定的加密算法
            KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
            // 取私钥对象
            PrivateKey key = factory.generatePrivate(pkcs);
            // 用私钥对信息生成数字签名
            Signature signature = Signature.getInstance(KEY_RSA_SIGNATURE);
            signature.initSign(key);
            signature.update(data);
            str = encryptBase64(signature.sign());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return str;
    }

    /**
     * 校验数字签名
     * @param data 加密数据
     * @param publicKey 公钥
     * @param sign 数字签名
     * @return 校验成功返回true，失败返回false
     */
    public static boolean verify(byte[] data, String publicKey, String sign) {
        boolean flag = false;
        try {
            // 解密由base64编码的公钥
            byte[] bytes = decryptBase64(publicKey);
            // 构造X509EncodedKeySpec对象
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
            // 指定的加密算法
            KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
            // 取公钥对象
            PublicKey key = factory.generatePublic(keySpec);
            // 用公钥验证数字签名
            Signature signature = Signature.getInstance(KEY_RSA_SIGNATURE);
            signature.initVerify(key);
            signature.update(data);
            flag = signature.verify(decryptBase64(sign));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return flag;
    }

    /**
     * 私钥解密
     * @param data 加密数据
     * @param key 私钥
     * @return
     */
    public static byte[] decryptByPrivateKey(byte[] data, String key) {
        byte[] result = null;
        try {
            // 对私钥解密
            byte[] bytes = decryptBase64(key);
            // 取得私钥
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
            KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
            PrivateKey privateKey = factory.generatePrivate(keySpec);
            // 对数据解密
            Cipher cipher = Cipher.getInstance(factory.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            result = cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * 私钥解密
     * @param source
     * @param privateKey
     * @return
     */
    public static String decryptByPublicKey(String source,String privateKey) throws Exception{
        byte[] word=decryptBase64(source);
        String decWord = new String(decryptByPrivateKey(word, privateKey));
        return decWord;
    }

    /**
     * 私钥解密
     * @param data 加密数据
     * @param key 公钥
     * @return
     */
    public static byte[] decryptByPublicKey(byte[] data, String key) {
        byte[] result = null;
        try {
            // 对公钥解密
            byte[] bytes = decryptBase64(key);
            // 取得公钥
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
            KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
            PublicKey publicKey = factory.generatePublic(keySpec);
            // 对数据解密
            Cipher cipher = Cipher.getInstance(factory.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            result = cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * 公钥加密
     * @param data 待加密数据
     * @param key 公钥
     * @return
     */
    public static byte[] encryptByPublicKey(byte[] data, String key) {
        byte[] result = null;
        try {
            byte[] bytes = decryptBase64(key);
            // 取得公钥
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
            KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
            PublicKey publicKey = factory.generatePublic(keySpec);
            // 对数据加密
            Cipher cipher = Cipher.getInstance(factory.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            result = cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * 私钥加密
     * @param data 待加密数据
     * @param key 私钥
     * @return
     */
    public static byte[] encryptByPrivateKey(byte[] data, String key) {
        byte[] result = null;
        try {
            byte[] bytes = decryptBase64(key);
            // 取得私钥
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytes);
            KeyFactory factory = KeyFactory.getInstance(KEY_RSA);
            PrivateKey privateKey = factory.generatePrivate(keySpec);
            // 对数据加密
            Cipher cipher = Cipher.getInstance(factory.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            result = cipher.doFinal(data);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * 获取公钥
     * @param map
     * @return
     */
    public static String getPublicKey(Map<String, Object> map) {
        String str = "";
        try {
            Key key = (Key) map.get(KEY_RSA_PUBLICKEY);
            str = encryptBase64(key.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return str;
    }

    /**
     * 获取私钥
     * @param map
     * @return
     */
    public static String getPrivateKey(Map<String, Object> map) {
        String str = "";
        try {
            Key key = (Key) map.get(KEY_RSA_PRIVATEKEY);
            str = encryptBase64(key.getEncoded());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return str;
    }

    /**
     * BASE64 解密
     * @param key 需要解密的字符串
     * @return 字节数组
     * @throws Exception
     */
    public static byte[] decryptBase64(String key) throws Exception {
        return (new BASE64Decoder()).decodeBuffer(key);
    }

    /**
     * BASE64 加密
     * @param key 需要加密的字节数组
     * @return 字符串
     * @throws Exception
     */
    public static String encryptBase64(byte[] key) throws Exception {
        return (new BASE64Encoder()).encodeBuffer(key);
    }


    public static String privateKey= "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKcsdtVapeDOkxJX\n" +
            "D8QxweV+R9Vt1mDMs44vS4zDa3cr/DVEvvecHAjc6jdpgwQ6k+H5Dx54JlHOk463\n" +
            "3YLI9Iy+1+opy13GXeQ2vdV95B7UQKxPhzcf092H0uA4RKelTYaYCghNLH7xflPB\n" +
            "lFM1le7KrLHEc4xngpUWx9Us8ETVAgMBAAECgYAxVJqgbMZkJzEZCV3arEAmQ3RZ\n" +
            "E7deCym0/FnT6NquaOlcorOjh4pyRxZKUbVaqxp2ZTND73qHS2kZhUI1VK1s3M9y\n" +
            "i7HuOKncuDp4W96CwI6owoDlAiGcvDXAuptMauXzvh3Woww7VrJ0xvSHwOMCPFxj\n" +
            "DN2nqDD7a+jjNVANZQJBAM1CjzizQn/M69ERkSSlbvJIXYNjdj1oYBOVINt2+Jjn\n" +
            "kZDuF7vqX+ycKB7XZDmX4rLvbLB8wI73vdaID+KlsGsCQQDQf7Goo5dXxiCE0XhG\n" +
            "W0/ARmsH5fefBQHRdAWmHMOoF8SapYiWnweyDyUrnBT4b0QVHC1hJ+Mh9lkBobM7\n" +
            "Si+/AkEAxOD72SnwNf9Ljaxo6JqZsWEB+T2Us1ADH6Vh77/MsXUkZbxKHZ+wRJZ/\n" +
            "0R1OcAOkmXcXbK0sUbWFbFnzyrScYwJAL8jUQr4bdXZnBYmscxOCV6LL7Od7tOpE\n" +
            "3Ggm00dMYD3yRS8i+sI/1UM7VZ9T/wwhImVu0RF/MM1w4LrahQAfqQJBAJo5L4IV\n" +
            "mQdbs6D3wflp4/lI4DTCM7fBISrT2j3nR/RMhTd4pcY62qADbGWjE6jEZWk/yQZV\n" +
            "ug8HHCCjeRVf6U4=\n";
    public static String publicKey= "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCnLHbVWqXgzpMSVw/EMcHlfkfV\n" +
            "bdZgzLOOL0uMw2t3K/w1RL73nBwI3Oo3aYMEOpPh+Q8eeCZRzpOOt92CyPSMvtfq\n" +
            "Kctdxl3kNr3VfeQe1ECsT4c3H9Pdh9LgOESnpU2GmAoITSx+8X5TwZRTNZXuyqyx\n" +
            "xHOMZ4KVFsfVLPBE1QIDAQAB\n";

}