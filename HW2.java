import java.io.*;
import java.util.*;
import java.text.DecimalFormat;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class HW2 {

    public static void main(String args[]) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        // add bouncy castle as security provider
        Security.addProvider(new BouncyCastleProvider());

        // get input
        System.out.print("Input: ");
        Scanner in = new Scanner(System.in);
        String plaintext = in.nextLine();

        byte[] encrypted;
        String decrypted;

        // AES
        SecretKey key = encryption("AES", 128);
        encrypted = encrypt("AES", plaintext, key); // encrypt
        decrypted = decrypt("AES", encrypted, key); // decrypt
        System.out.println("AES: " + decrypted); // print plaintext

        // Blowfish
        key = encryption("Blowfish", 128);
        encrypted = encrypt("Blowfish", plaintext, key); // encrypt
        decrypted = decrypt("Blowfish", encrypted, key); // decrypt
        System.out.println("Blowfish: " + decrypted); // print plaintext

        // RSA
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA"); // create key instance
        keyGen.initialize(2048); // specify key size recommended by NIST
        KeyPair keypair = keyGen.genKeyPair(); // generate key pair
        encrypted = encrypt("RSA", plaintext, keypair.getPublic()); // encrypt
        decrypted = decrypt("RSA", encrypted, keypair.getPrivate()); // decrypt
        System.out.println("RSA: " + decrypted); // print plaintext

        // RSA signature
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(keypair.getPrivate()); // sign data
        sig.update(plaintext.getBytes());
        byte[] sigBytes = sig.sign();

        // Verify RSA signature
        sig.initVerify(keypair.getPublic());
        sig.update(plaintext.getBytes());
        System.out.println("Verification Succeeded: " + sig.verify(sigBytes));

        // Extra Credit
        System.out.println("\nExtra Credit:");
        Random rand = new Random();
        String[] arr = new String[100];
        for (int i = 0; i < 100; i++) { // generate 100 random strings
            arr[i] = Long.toString(rand.nextLong());
        }

        // AES
        key = encryption("AES", 128);
        long startTime = System.nanoTime();
        for (int i = 0; i < 100; i++) {
            encrypted = encrypt("AES", arr[i], key);
        }
        long endTime = System.nanoTime();
        long aesTimeElapsed = endTime - startTime;
        System.out.println("AES:\t\t" + aesTimeElapsed + " nanoseconds");

        // Blowfish
        key = encryption("Blowfish", 128);
        startTime = System.nanoTime();
        for (int i = 0; i < 100; i++) {
            encrypted = encrypt("Blowfish", arr[i], key);
        }
        endTime = System.nanoTime();
        long bfTimeElapsed = endTime - startTime;
        System.out.println("Blowfish:\t" + bfTimeElapsed + " nanoseconds");

        // RSA
        startTime = System.nanoTime();
        for (int i = 0; i < 100; i++) {
            encrypted = encrypt("RSA", arr[i], keypair.getPublic());
        }
        endTime = System.nanoTime();
        long rsaTimeElapsed = endTime - startTime;
        System.out.println("RSA:\t\t" + rsaTimeElapsed + " nanoseconds\n");

        // Results
        DecimalFormat df = new DecimalFormat("0.00");
        System.out.println("AES : RSA:\t" + df.format(((double) rsaTimeElapsed / aesTimeElapsed)));
        System.out.println("AES : Blowfish\t" + df.format(((double) bfTimeElapsed / aesTimeElapsed)));
        System.out.println("Blowfish : RSA\t" + df.format(((double) rsaTimeElapsed / bfTimeElapsed)));
    }

    public static SecretKey encryption(final String alg, final int size) throws NoSuchAlgorithmException {
        KeyGenerator generator = KeyGenerator.getInstance(alg); // create key instance
        generator.init(size); // specify key size
        return generator.generateKey(); // generate key
    }

    public static byte[] encrypt(final String type, final String plaintext, final Key key) {
        byte[] encryptedVal = null;
        try {
            final Cipher cipher = Cipher.getInstance(type);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            encryptedVal = cipher.doFinal(plaintext.getBytes());
        } catch (Exception e) {
            System.out.println("The Exception is=" + e);
        }
        return encryptedVal;
    }

    public static String decrypt(final String type, final byte[] encrypted, final Key key) {
        String decryptedValue = null;
        try {
            final Cipher cipher = Cipher.getInstance(type);
            cipher.init(Cipher.DECRYPT_MODE, key);
            decryptedValue = new String(cipher.doFinal(encrypted));
        } catch (Exception e) {
            System.out.println("The Exception is=" + e);
            e.printStackTrace(System.err);
        }
        return decryptedValue;
    }
}