package org.example;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jose.crypto.impl.AESGCM;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.EncryptedJWT;

import java.lang.reflect.Array;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.text.ParseException;
import java.util.Arrays;
import  java.security.NoSuchAlgorithmException;
//TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or
// click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.
public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException, JOSEException {
        //TIP Press <shortcut actionId="ShowIntentionActions"/> with your caret at the highlighted text
        // to see how IntelliJ IDEA suggests fixing it.
        System.out.println("Hello and welcome!");

        try {
            // header and payload
            JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A256GCM);
            Payload payload = new Payload("Hello and welcome!");

            // jwe object
            JWEObject jwe = new JWEObject(header, payload);

            String sysmeticKey = "3mt02DeniVTfmjzR";
            byte[] keyByte = sysmeticKey.getBytes();
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hashedKeyBytes = sha256.digest();

            System.out.println("hashedKeyBytes => " + Arrays.toString(hashedKeyBytes));
            System.out.println("hashedKeyBytes length = " + hashedKeyBytes.length);

            SecretKey key = new SecretKeySpec(hashedKeyBytes, "AES");
            DirectEncrypter encrypter = new DirectEncrypter(key);

            jwe.encrypt(encrypter);

            String jewString = jwe.serialize();
            System.out.println("JWE: " + jewString);

            System.out.println("\n==================================== Decryption ====================================");
            EncryptedJWT jweDerypt = EncryptedJWT.parse(jewString);
            DirectDecrypter decrypter = new DirectDecrypter(key);
            jweDerypt.decrypt(decrypter);

            // Get the payload
            String decryptPayload = jweDerypt.getPayload().toString();
            System.out.println("Decrypted Payload: " + decryptPayload);
        } catch (Exception ex){
            ex.printStackTrace();
        }

    }
}