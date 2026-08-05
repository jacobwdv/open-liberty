/*******************************************************************************
 * Copyright (c) 2025 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.crypto.ltpakeyutil;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;

import java.security.Key;
import java.util.Properties;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;

import org.junit.Assert;
import org.junit.Test;

/**
 * Unit tests for the AES/CBC/PKCS5Padding hardware-key cipher path used by
 * {@code ICSFKeyEncryptor}, and for {@link LTPAKeyFileUtilityImpl#generateLTPAKeys(KeyEncryptor, String)}.
 *
 * <p>ICSF CKDS keys are always AES-256. These tests use a software AES-256 key to exercise
 * the same cipher operations — the crypto is identical regardless of whether the key
 * is hardware- or software-backed.
 */
public class LTPACryptoHardwareKeyTest {

    private static final String AES_CBC = "AES/CBC/PKCS5Padding";
    private static final IvParameterSpec ZERO_IV = new IvParameterSpec(new byte[16]);

    /** Returns a fresh software AES-256 key simulating an opaque ICSF/CKDS key. */
    private static Key makeAes256Key() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        return kg.generateKey();
    }

    private static byte[] aesCbcEncrypt(byte[] data, Key key) throws Exception {
        Cipher ci = Cipher.getInstance(AES_CBC);
        ci.init(Cipher.ENCRYPT_MODE, key, ZERO_IV);
        return ci.doFinal(data);
    }

    private static byte[] aesCbcDecrypt(byte[] data, Key key) throws Exception {
        Cipher ci = Cipher.getInstance(AES_CBC);
        ci.init(Cipher.DECRYPT_MODE, key, ZERO_IV);
        return ci.doFinal(data);
    }

    /**
     * Verify that the AES/CBC/PKCS5Padding cipher with a zero IV round-trips correctly.
     */
    @Test
    public void testEncryptDecryptRoundTrip() throws Exception {
        Key key = makeAes256Key();

        byte[] plaintext = "This is a test LTPA secret key..".getBytes("UTF-8");
        byte[] encrypted = aesCbcEncrypt(plaintext, key);

        assertNotNull("Encrypted bytes must not be null", encrypted);

        byte[] decrypted = aesCbcDecrypt(encrypted, key);
        assertArrayEquals("Decrypted bytes must match original plaintext", plaintext, decrypted);
    }

    /**
     * Verify encrypt/decrypt consistency with the same key across two calls.
     */
    @Test
    public void testSameKeyConsistency() throws Exception {
        Key key = makeAes256Key();

        byte[] plaintext = "cross-encryptor test data foo!!.".getBytes("UTF-8");
        byte[] encrypted = aesCbcEncrypt(plaintext, key);
        byte[] decrypted = aesCbcDecrypt(encrypted, key);

        assertArrayEquals("decrypt(encrypt(x)) must equal x", plaintext, decrypted);
    }

    /**
     * Verify that {@link LTPAKeyFileUtilityImpl#generateLTPAKeys(KeyEncryptor, String)} produces
     * a valid Properties object containing all required LTPA key entries when given a
     * hardware-style (AES/CBC) encryptor.
     */
    @Test
    public void testGenerateLTPAKeysWithKeyEncryptor() throws Exception {
        Key key = makeAes256Key();

        KeyEncryptor encryptor = new KeyEncryptor() {
            @Override public byte[] encrypt(byte[] data) throws Exception { return aesCbcEncrypt(data, key); }
            @Override public byte[] decrypt(byte[] data) throws Exception { return aesCbcDecrypt(data, key); }
            @Override public String getLtpaVersion() { return "2.0"; }
            @Override public boolean supportsLegacyFallback() { return false; }
        };

        LTPAKeyFileUtilityImpl util = new LTPAKeyFileUtilityImpl();
        Properties props = util.generateLTPAKeys(encryptor, "testRealm");

        assertNotNull("SecretKey must be present",  props.get(LTPAKeyFileUtility.KEYIMPORT_SECRETKEY));
        assertNotNull("PrivateKey must be present",  props.get(LTPAKeyFileUtility.KEYIMPORT_PRIVATEKEY));
        assertNotNull("PublicKey must be present",   props.get(LTPAKeyFileUtility.KEYIMPORT_PUBLICKEY));
        Assert.assertEquals("testRealm", props.get(LTPAKeyFileUtility.KEYIMPORT_REALM));
        Assert.assertEquals("2.0", props.get(LTPAKeyFileUtility.LTPA_VERSION_PROPERTY));
    }
}
