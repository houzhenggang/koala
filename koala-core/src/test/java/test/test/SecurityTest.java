package test.test;

import org.junit.Test;
import org.koala.util.MD5Tool;
import org.koala.util.SecurityTool;

import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.Set;

import org.koala.util.BASE64;

public class SecurityTest {

    public static final String plainText = "sdtest1$12345678$test123";
    public static final String KEY = "sdgreennet";

    //    @Test
    public void testFind() {
        Set<String> set = SecurityTool.findServiceTypes();
        for (String serviceType : set) {
            System.out.println("@" + serviceType);
            Set<String> csets = SecurityTool.findCryptoImpls(serviceType);
            for (String crypto : csets) {
                System.out.println("#" + crypto);
            }
        }
        set = SecurityTool.findCryptoImpls("Cipher");
        for (String name : set) {
            System.out.println("$" + name);
        }
        set = SecurityTool.findCryptoImpls("KeyPairGenerator");
        for (String name : set) {
            System.out.println("#" + name);
        }
    }

    @Test
    public void testMac() {

        try {
            SecretKey key = new SecretKeySpec(KEY.getBytes(), "HmacMD5");
//            SecretKey key = getKey();

            if (key != null) {
                System.out.println("密钥：" + MD5Tool.getInstance().byteArrayToHexString(key.getEncoded()) + ":" + key.getAlgorithm());
                Mac mac = Mac.getInstance(key.getAlgorithm());
                mac.init(key);
                mac.update(plainText.getBytes());

                byte[] bts = mac.doFinal();
                System.out.println(new String(bts, "UTF-8"));
                System.out.println("MAC:" + MD5Tool.getInstance().bytesToHex(bts));
                System.out.println("MAC:" + MD5Tool.getInstance().byteArrayToHexString(bts));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //    @Test
    public void testFc() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(512);
            KeyPair kp = kpg.genKeyPair();
            PrivateKey privateKey = kp.getPrivate();
            PublicKey publicKey = kp.getPublic();

            Cipher cp = Cipher.getInstance("RSA");
            cp.init(Cipher.ENCRYPT_MODE, publicKey);

            String str = new String(BASE64.encode(cp.doFinal(plainText.getBytes())));
            System.out.println(str);

            cp.init(Cipher.DECRYPT_MODE, privateKey);
            System.out.println(new String(cp.doFinal(BASE64.decode(str))));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    //    @Test
    public void testKey() {
        try {
//			KeyGenerator kg = KeyGenerator.getInstance("DES");
//			SecretKey key = kg.generateKey();
//			String keyStr = be.encode(key.getEncode());
            String keyStr = "LIMaBAEE99w=";
            SecretKey key = new SecretKeySpec(BASE64.decode(keyStr), "DES");

            Cipher cp = Cipher.getInstance("DES");
            cp.init(Cipher.ENCRYPT_MODE, key);
            int blockSize = cp.getBlockSize();

            ByteBuffer inbuffer = ByteBuffer.wrap(plainText.getBytes());
            inbuffer.flip();
            int outSize = cp.getOutputSize(inbuffer.capacity());
            System.out.println("##" + outSize);
            ByteBuffer outbuffer = ByteBuffer.allocate(outSize);
            cp.update(inbuffer, outbuffer);

            String str1 = new String(BASE64.encode(cp.doFinal()));
            System.out.println("@1=@" + str1);

            String str = new String(BASE64.encode(cp.doFinal(plainText.getBytes())));
            System.out.println(str);

            cp.init(Cipher.DECRYPT_MODE, key);
            byte[] dbs = cp.doFinal(BASE64.decode(str));
            System.out.println(new String(dbs));

            System.out.println("@1=@" + new String(cp.doFinal(BASE64.decode(str1))));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public SecretKey getKey() {
        SecretKey key = null;
        try {
            KeyGenerator kg = KeyGenerator.getInstance("DES");
            key = kg.generateKey();
            key = new SecretKeySpec(KEY.getBytes(), "MAC");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return key;
    }
}
