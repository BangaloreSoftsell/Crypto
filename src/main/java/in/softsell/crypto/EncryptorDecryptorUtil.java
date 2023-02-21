/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package in.softsell.crypto;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author user1
 */
public class EncryptorDecryptorUtil {

    private int keySize;
    private Cipher cipher;

    public EncryptorDecryptorUtil(int keySize) {
        this.keySize = keySize;
        try {
            this.cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
        }
    }

    public String encryptMessage(String txtToEncrypt, String passphrase) {
        String combineData = "";
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            String saltHex = getRandomHexString(32);
            String ivHex = getRandomHexString(32);
            byte[] salt = hexStringToByteArray(saltHex);
            byte[] iv = hexStringToByteArray(ivHex);
            SecretKeySpec sKey = (SecretKeySpec) generateKeyFromPassword(passphrase, salt);
            cipher.init(1, sKey, new IvParameterSpec(iv));
            byte[] utf8 = txtToEncrypt.getBytes("UTF-8");
            byte[] enc = cipher.doFinal(utf8);
            combineData = saltHex + " " + ivHex + " " + Base64.getEncoder().encodeToString(enc);
        } catch (Exception e) {
            e.printStackTrace();
        }
        combineData = combineData.replaceAll("\n", "").replaceAll("\t", "").replaceAll("\r", "");
        return combineData;
    }

    public static String getRandomHexString(int numchars) {
        Random r = new Random();
        StringBuilder sb = new StringBuilder();
        while (sb.length() < numchars) {
            sb.append(Integer.toHexString(r.nextInt()));
        }
        return sb.toString().substring(0, numchars);
    }

    public static byte[] hexStringToByteArray(String s) {
        System.out.println("s:::::::" + s);
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[(i / 2)] = ((byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16)));
        }
        return data;
    }

    public static SecretKey generateKeyFromPassword(String password, byte[] saltBytes) throws GeneralSecurityException {
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), saltBytes, 100, 128);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        SecretKey secretKey = keyFactory.generateSecret(keySpec);
        return new SecretKeySpec(secretKey.getEncoded(), "AES");
    }

    public String decryptMessage(String str, String myKey) {
        String decrypted = null;
        try {
            if ((str != null) && (str.contains(" "))) {
                String salt = str.split(" ")[0];
                String iv = str.split(" ")[1];
                String encryptedText = str.split(" ")[2];
                EncryptorDecryptorUtil dec = new EncryptorDecryptorUtil(128);
                decrypted = dec.decrypt(salt, iv, myKey, encryptedText);
            } else {
                decrypted = str;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decrypted;
    }

    public String decrypt(String salt, String iv, String passphrase, String EncryptedText) {
        String decryptedValue = null;
        try {
            byte[] saltBytes = hexStringToByteArray(salt);
            SecretKeySpec sKey = (SecretKeySpec) generateKeyFromPassword(passphrase, saltBytes);
            byte[] ivBytes = hexStringToByteArray(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(ivBytes);
            this.cipher.init(2, sKey, ivParameterSpec);
            byte[] decordedValue = Base64.getDecoder().decode(EncryptedText);
            byte[] decValue = this.cipher.doFinal(decordedValue);
            decryptedValue = new String(decValue);
            return new String(decryptedValue);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decryptedValue;
    }

}
