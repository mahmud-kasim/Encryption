
package Odev_1;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import sun.misc.BASE64Decoder;

/**
 *
 * @author Mahmud
 */
public class Odev_1 {

         private static Key pubKey;
         private static IvParameterSpec ivv;
         private static final String ENCRYPTION_KEY = "RwcmlVpg";
	 private static final String ENCRYPTION_IV = "4e5Wa71fYoT7MFEX";
   
    
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException, GeneralSecurityException {
        
        KeyPairGenerator k1 = KeyPairGenerator.getInstance("RSA");  //key generation 
        k1.initialize(2048); // 2048 bit
        KeyPair kp = k1.genKeyPair();
        PublicKey key_1 = kp.getPublic();  //Generate public key  //Generate private key
        PrivateKey key_2 = kp.getPrivate();
        pubKey=key_1;
        KeyFactory f1 = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec publc = f1.getKeySpec(key_1, RSAPublicKeySpec.class);
        RSAPrivateKeySpec privat = f1.getKeySpec(key_2, RSAPrivateKeySpec.class);
        System.out.println("**************1.SORU****************");
        System.out.println("Public Key K+: "+ publc.getModulus());
        System.out.println("Private Key K-: "+ privat.getPrivateExponent());
        
        String base64PrivateModulus = Base64.encodeBase64String(privat.getModulus().toByteArray());
        String base64PrivateExponent = Base64.encodeBase64String(privat.getPrivateExponent().toByteArray());
        String base64PublicModulus = Base64.encodeBase64String(publc.getModulus().toByteArray());
        String base64PublicExponent = Base64.encodeBase64String(publc.getPublicExponent().toByteArray());
        
        System.out.println("RSA With String");
        System.out.print("Public Key K+ ");
        System.out.println(base64PublicModulus);
        
        System.out.print("Private Key K- ");
        System.out.println(base64PrivateExponent);

       
        System.out.println("-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------");
        KeyGenerator keygen = KeyGenerator.getInstance("AES") ;   //Genarating symmetric key 
        keygen.init(128) ;  //(with 128  bit)
        byte[] key = keygen.generateKey().getEncoded();
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
        System.out.println("----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------");
        
        System.out.println("\n");
        System.out.println("**************2.SORU****************");
        System.out.println("SYMMETRİC KEY ...........:"+skeySpec.getEncoded());
        String base64KS = Base64.encodeBase64String(skeySpec.getEncoded());
        System.out.println("ŞİFLENECEK ANAHTAR..................:"+base64KS);
        System.out.println("ENCRYPTİON : ");
        System.out.println(encryptRSA(base64KS, key_1));
        String sifreliKs=encryptRSA(base64KS, key_1);//Symmetric key ile bir şifreleme işlemi gerçekleştiriliyor  (ENcryption here)
        System.out.println("DECRYPTİON : ");
        System.out.println(decryptRSA(sifreliKs, key_2));  //BUrada ise şifre çözülme işlemi yapılmaktadır               (DECREPTİON HERE)
        System.out.println("-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------");
        
        System.out.println("\n");
        System.out.println("**************3.SORU****************");
        System.out.println("..............SHA2 ALGORİTMASI....\n");
        System.out.println("LÜTFEN ŞİFRELEMEK İSTEDİĞİNİZ MESAJI YAZINIZ...");
        Scanner scn=new Scanner(System.in);
        String m=scn.nextLine();
        System.out.println("SHA2 İLE ŞİFRELENMİŞTİR  : "+GenerateHash(m));
        String sha2m=GenerateHash(m);
        String sha2mpri=encryptRSA(sha2m, key_2);
        System.out.println("PRİVATE KEY K(-) İLE ENCRYPT EDİLİYOR: "+sha2mpri);
        Dijital_imza(m,sha2mpri);
        System.out.println("-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------");
        System.out.println("\n");
        System.out.println("**************4.SORU****************");
        System.out.println("..............HMAC ALGORİTMASI......");
        System.out.println("LÜTFEN HMAC'İNİ İSTEDİĞİNİZ METİNİ GİRİNİZ...");
        Scanner scan=new Scanner(System.in);
        String m2=scan.nextLine();
        HMAC(skeySpec,m2);
        System.out.println("--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------");
       
        System.out.println("\n");
        System.out.println("**************5.SORU****************");
        System.out.println(".............AES ALGORİTHM WİTH CBC MODE..");
        System.out.println("LÜTFEN AES(CBC) MODUNDA ŞİFRELEMEK İSTEDİĞİNİZ MESAJI GİRİNİZ...");
        Scanner scann=new Scanner(System.in);
        String m3=scann.nextLine();
        String akey = "Bar12345Bar12345"; // 128 bit key
        String initVector = "RandomInitVector"; // 16 bytes IV
        String sifreliaes=encryptAES(akey,initVector,m3);
        System.out.println("ENCRYPT EDİLİYOR: "+sifreliaes);
        String cozulen=decryptAES(akey,initVector,sifreliaes);
        System.out.println("DECRYPT EDİLDİ:  "+cozulen);
       
        System.out.println("\n");
        String textInBold = ":):):) ÖDEV TAMAM :):):)\n";//BOLD
        System.out.print("\033[0;1m" + textInBold);
    }
    
	//AES(CBC) MODE
     //ENCRYPTİONN BURADA
 public static String encryptAES(String key, String initVector, String value) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));

            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());

            
            String s = new String(java.util.Base64.getEncoder().encode(encrypted));
            return s;
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
 //DECRYPTİON BURADA

    public static String decryptAES(String key, String initVector, String encrypted) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            byte[] original = cipher.doFinal(java.util.Base64.getDecoder().decode(encrypted));

            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    
}
    //2 parametre alıyor RSA BURADa
    //ENCRYPT BURADA

     public static String encryptRSA(String rawText, Key Key) throws IOException, GeneralSecurityException {
         
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, Key);
        return Base64.encodeBase64String(cipher.doFinal(rawText.getBytes("UTF-8")));
    }
     
     //DECRYPT BURADA
    public static String decryptRSA(String cipherText, Key Key) throws IOException, GeneralSecurityException {
        
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, Key);
        return new String(cipher.doFinal(Base64.decodeBase64(cipherText)), "UTF-8");
    }
    public static String GenerateHash(String input) throws NoSuchAlgorithmException {
        
        MessageDigest objSHA = MessageDigest.getInstance("SHA-256");
        byte[] bytSHA = objSHA.digest(input.getBytes());
        BigInteger intNumber = new BigInteger(1, bytSHA);
        String strHashCode = intNumber.toString(16);
		
        while (strHashCode.length() < 64) {
            strHashCode = "0" + strHashCode;
        }
        return strHashCode;
    }

    private static void Dijital_imza(String m, String sha2mpri) throws IOException, GeneralSecurityException {
        System.out.println("***DİJİTAL İMZA OLUŞTURULUYOR.............");
        String cozpub=decryptRSA(sha2mpri, pubKey);
        System.out.println("PUBLİC KEY K(+) İLE DECRYPT EDLİYOR:  "+cozpub);
        System.out.println("\n");
        String sifrele=GenerateHash(m);
        if (sifrele.equals(cozpub)) {
            System.out.println(":):):) DİJİTAL İMZA BAŞARIYLA TAMAMLANMIŞIR :) :) :)");
        }else{
            System.out.println("ERROR, LÜTFEN TEKRAR DENEYİNİZ...");
        }
    }

    private static void HMAC(SecretKeySpec skeySpec, String m2) {
    try {
     Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
     sha256_HMAC.init(skeySpec);

     String hash = Base64.encodeBase64String(sha256_HMAC.doFinal(m2.getBytes()));
     System.out.println("SYMMETRİC KEY VE SHA2 KULLANILARAK HMAC OLUŞTURULUYOR  : "+hash);
    }
    catch (Exception e){
     System.out.println("ERROR, LÜTFEN TEKRAR DENEYİNİZ");
    }  
    }}
    
   
   
