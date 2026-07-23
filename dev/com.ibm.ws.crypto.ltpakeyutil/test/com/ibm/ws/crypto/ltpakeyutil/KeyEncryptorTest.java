/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
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

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

import com.ibm.wsspi.security.crypto.AesKeyProvider;
import com.ibm.wsspi.security.crypto.AesKeyProviderException;

/**
 * Unit tests for {@link KeyEncryptor} covering both construction modes.
 */
public class KeyEncryptorTest {

    private static final byte[] SOME_KEY_BYTES = new byte[32]; // 32 zero bytes — arbitrary plain-text key

    // ---------------------------------------------------------------------------
    // Password-derived (existing) path
    // ---------------------------------------------------------------------------

    @Test
    public void passwordDerivedRoundTrip() throws Exception {
        KeyEncryptor enc = new KeyEncryptor("WebAS".getBytes());
        byte[] encrypted = enc.encrypt(SOME_KEY_BYTES);
        assertNotNull("encrypt() returned null", encrypted);

        byte[] decrypted = enc.decrypt(encrypted);
        assertArrayEquals("password-derived round-trip failed", SOME_KEY_BYTES, decrypted);
    }

    @Test
    public void passwordDerivedRoundTrip_differentPassword_throwsOrMismatch() throws Exception {
        // Encrypting with one password and decrypting with another must not produce the original bytes.
        KeyEncryptor enc = new KeyEncryptor("WebAS".getBytes());
        byte[] encrypted = enc.encrypt(SOME_KEY_BYTES);

        KeyEncryptor other = new KeyEncryptor("WrongPw".getBytes());
        boolean caughtExpected = false;
        try {
            byte[] decrypted = other.decrypt(encrypted);
            // If no exception, the round trip must have produced different bytes.
            if (!java.util.Arrays.equals(SOME_KEY_BYTES, decrypted)) {
                caughtExpected = true;
            }
        } catch (Exception e) {
            // A cipher exception (e.g. BadPaddingException) is equally acceptable.
            caughtExpected = true;
        }
        org.junit.Assert.assertTrue("Wrong password should not decrypt correctly", caughtExpected);
    }

    // ---------------------------------------------------------------------------
    // Provider-backed path
    // ---------------------------------------------------------------------------

    /** Minimal {@link AesKeyProvider} backed by a freshly generated AES-256 key. */
    private static AesKeyProvider newProvider() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey k = kg.generateKey();
        return newProvider(k);
    }

    private static AesKeyProvider newProvider(SecretKey key) {
        return new AesKeyProvider() {
            @Override
            public SecretKey getKey() throws AesKeyProviderException {
                return key;
            }
        };
    }

    @Test
    public void providerBackedRoundTrip() throws Exception {
        AesKeyProvider provider = newProvider();
        KeyEncryptor enc = new KeyEncryptor(provider);
        byte[] encrypted = enc.encrypt(SOME_KEY_BYTES);
        assertNotNull("encrypt() returned null", encrypted);

        // Decrypting with a fresh KeyEncryptor that uses the same provider must recover the original bytes.
        KeyEncryptor dec = new KeyEncryptor(provider);
        byte[] decrypted = dec.decrypt(encrypted);
        assertArrayEquals("provider-backed round-trip failed", SOME_KEY_BYTES, decrypted);
    }

    @Test
    public void providerBackedEncrypt_differentProvider_cannotDecryptCorrectly() throws Exception {
        AesKeyProvider provider1 = newProvider();
        AesKeyProvider provider2 = newProvider();

        KeyEncryptor enc = new KeyEncryptor(provider1);
        byte[] encrypted = enc.encrypt(SOME_KEY_BYTES);

        KeyEncryptor dec = new KeyEncryptor(provider2);
        boolean caughtExpected = false;
        try {
            byte[] decrypted = dec.decrypt(encrypted);
            if (!java.util.Arrays.equals(SOME_KEY_BYTES, decrypted)) {
                caughtExpected = true;
            }
        } catch (Exception e) {
            caughtExpected = true;
        }
        org.junit.Assert.assertTrue("Different provider should not decrypt correctly", caughtExpected);
    }

}
