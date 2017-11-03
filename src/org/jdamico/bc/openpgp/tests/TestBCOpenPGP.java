package org.jdamico.bc.openpgp.tests;


import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Base64;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.jdamico.bc.openpgp.utils.PgpHelper;
import org.jdamico.bc.openpgp.utils.RSAKeyPairGenerator;


public class TestBCOpenPGP {

    private boolean isArmored = true;
    private String id = "damico";
    private String passwd = "******";
    private boolean integrityCheck = true;


    private String pubKeyFile = "test_out/pub.asc";
    private String privKeyFile = "test_out/secret.asc";

    private String plainTextFile = "test_out/plain-text.txt";
    private String cipherTextFile = "test_out/cypher-text.asc";
    private String decPlainTextFile = "test_out/dec-plain-text.txt";
    private String signatureFile = "test_out/signature.txt";

    @Before
    public void setUp() throws Exception {
        if (Files.notExists(Paths.get("test_out"))) {
            Files.createDirectory(Paths.get("test_out"));
        }

        if (Files.notExists(Paths.get(plainTextFile))) {
            byte[] rand = new byte[819200];
            new SecureRandom().nextBytes(rand);
            Files.write(Paths.get(plainTextFile), Base64.getEncoder().encode(rand));
        }
    }

    @Test
    public void genKeyPair() throws InvalidKeyException, NoSuchProviderException, SignatureException, IOException, PGPException, NoSuchAlgorithmException {

        RSAKeyPairGenerator rkpg = new RSAKeyPairGenerator();

        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");

        kpg.initialize(1024);

        KeyPair kp = kpg.generateKeyPair();

        FileOutputStream out1 = new FileOutputStream(privKeyFile);
        FileOutputStream out2 = new FileOutputStream(pubKeyFile);

        rkpg.exportKeyPair(out1, out2, kp.getPublic(), kp.getPrivate(), id, passwd.toCharArray(), isArmored);
    }

    @Test
    public void encrypt() throws NoSuchProviderException, IOException, PGPException {
        long start = System.currentTimeMillis();

        FileInputStream pubKeyIs = new FileInputStream(pubKeyFile);
        FileOutputStream cipheredFileIs = new FileOutputStream(cipherTextFile);
        PgpHelper.getInstance().encryptFile(cipheredFileIs, plainTextFile, PgpHelper.getInstance().readPublicKey(pubKeyIs), isArmored, integrityCheck);
        cipheredFileIs.close();
        pubKeyIs.close();

        System.out.println("encrypt() takes " + (int) ((System.currentTimeMillis() - start) / 1000) + " seconds.");

        byte[] orgF = Files.readAllBytes(Paths.get(plainTextFile));
        byte[] newF = Files.readAllBytes(Paths.get(cipherTextFile));

        assertNotEquals(Arrays.toString(orgF), Arrays.toString(newF));
    }

    @Test
    public void decrypt() throws Exception {
        long start = System.currentTimeMillis();

        FileInputStream cipheredFileIs = new FileInputStream(cipherTextFile);
        FileInputStream privKeyIn = new FileInputStream(privKeyFile);
        FileOutputStream plainTextFileIs = new FileOutputStream(decPlainTextFile);
        PgpHelper.getInstance().decryptFile(cipheredFileIs, plainTextFileIs, privKeyIn, passwd.toCharArray());
        cipheredFileIs.close();
        plainTextFileIs.close();
        privKeyIn.close();

        System.out.println("decrypt() takes " + (int) ((System.currentTimeMillis() - start) / 1000) + " seconds.");

        byte[] orgF = Files.readAllBytes(Paths.get(plainTextFile));
        byte[] newF = Files.readAllBytes(Paths.get(decPlainTextFile));

        assertArrayEquals(orgF, newF);
    }

    @Test
    public void signAndVerify() throws Exception {
        long start = System.currentTimeMillis();

        FileInputStream privKeyIn = new FileInputStream(privKeyFile);
        FileInputStream pubKeyIs = new FileInputStream(pubKeyFile);
        FileInputStream plainTextInput = new FileInputStream(plainTextFile);
        FileOutputStream signatureOut = new FileOutputStream(signatureFile);

        // todo: remove that?
        // byte[] bIn = PgpHelper.getInstance().inputStreamToByteArray(plainTextInput);

        byte[] sig = PgpHelper.getInstance().createSignature(plainTextFile, privKeyIn, signatureOut, passwd.toCharArray(), true);

        boolean res = PgpHelper.getInstance().verifySignature(plainTextFile, sig, pubKeyIs);

        System.out.println("signAndVerify() takes " + (int) ((System.currentTimeMillis() - start) / 1000) + " seconds.");

        assertTrue(res);
    }

}