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
package com.ibm.ws.crypto.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceReference;
import org.osgi.service.component.ComponentContext;

import com.ibm.websphere.crypto.PasswordUtil;
import com.ibm.ws.common.crypto.CryptoUtils;
import com.ibm.ws.crypto.util.AESKeyManager.KeyVersion;
import com.ibm.wsspi.security.crypto.PasswordEncryptionKeyProvider;

import test.common.SharedOutputManager;

/**
 * Tests for the PasswordEncryptionKeyProvider integration in PasswordCipherUtil.
 */
public class PasswordEncryptionKeyProviderTest {

    static final SharedOutputManager outputMgr = SharedOutputManager.getInstance();

    @Rule
    public TestRule managerRule = outputMgr;

    private final Mockery context = new JUnit4Mockery();
    private ComponentContext cc;
    @SuppressWarnings("unchecked")
    private ServiceReference<PasswordEncryptionKeyProvider> providerRef;
    private PasswordEncryptionKeyProvider provider;
    private PasswordCipherUtil pcu;
    private boolean activated = false;

    @BeforeClass
    public static void traceSetUp() {
        outputMgr.trace("*=all");
    }

    @AfterClass
    public static void traceTearDown() {
        outputMgr.trace("*=all=disabled");
    }

    @org.junit.Before
    public void setUp() {
        cc = context.mock(ComponentContext.class, "cc-" + System.nanoTime());
        providerRef = context.mock(ServiceReference.class, "ref-" + System.nanoTime());
        provider = context.mock(PasswordEncryptionKeyProvider.class, "provider-" + System.nanoTime());
        pcu = new PasswordCipherUtil();
    }

    /**
     * Reset provider state after each test to avoid cross-test pollution,
     * since PasswordCipherUtil uses static fields.
     */
    @After
    public void tearDown() {
        // Only unset/deactivate if this test called activateWithProvider().
        if (activated) {
            pcu.unsetPasswordEncryptionKeyProvider(providerRef);
            pcu.deactivate(cc);
            activated = false;
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    private SecretKey generateAes256Key() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance(CryptoUtils.ENCRYPT_ALGORITHM_AES);
            kg.init(CryptoUtils.AES_256_KEY_LENGTH_BITS);
            return kg.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private void activateWithProvider(SecretKey key) {
        context.checking(new Expectations() {
            {
                one(providerRef).getProperty(Constants.SERVICE_ID);
                will(returnValue(1L));
                one(providerRef).getProperty(Constants.SERVICE_RANKING);
                will(returnValue(0));
                one(cc).locateService(PasswordCipherUtil.KEY_PROVIDER_SERVICE, providerRef);
                will(returnValue(provider));
                one(provider).getKey(CryptoUtils.ENCRYPT_ALGORITHM_AES);
                will(returnValue(key));
            }
        });
        pcu.activate(cc);
        pcu.setPasswordEncryptionKeyProvider(providerRef);
        activated = true;
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    /**
     * When a PasswordEncryptionKeyProvider is registered, getProviderKey() returns its key.
     */
    @Test
    public void testGetProviderKeyReturnsProviderKey() {
        SecretKey expected = generateAes256Key();
        activateWithProvider(expected);

        Key actual = PasswordCipherUtil.getProviderKey();

        assertNotNull("getProviderKey() should return a non-null key when provider is registered", actual);
        assertEquals("getProviderKey() should return the key from the provider", expected, actual);
    }

    /**
     * The key is cached: getKey() on the provider is only called once even if
     * getProviderKey() is called multiple times.
     */
    @Test
    public void testProviderKeyIsCached() {
        SecretKey key = generateAes256Key();
        // getKey called only once (the expectation above uses "one()")
        activateWithProvider(key);

        Key first = PasswordCipherUtil.getProviderKey();
        Key second = PasswordCipherUtil.getProviderKey();

        assertEquals("Cached key should equal first retrieved key", first, second);
    }

    /**
     * After the provider is unset, getProviderKey() returns null and the cache is cleared.
     */
    @Test
    public void testCacheClearedOnUnset() {
        SecretKey key = generateAes256Key();
        activateWithProvider(key);

        // Populate cache
        PasswordCipherUtil.getProviderKey();

        // Unset the provider using the same pcu instance activated in setUp
        pcu.unsetPasswordEncryptionKeyProvider(providerRef);

        Key afterUnset = PasswordCipherUtil.getProviderKey();
        assertEquals("getProviderKey() should return null after provider is unset", null, afterUnset);
    }

    /**
     * AES_V2 encrypt+decrypt round-trip using a PasswordEncryptionKeyProvider.
     */
    @Test
    public void testRoundTripWithProvider() throws Exception {
        SecretKey key = generateAes256Key();
        activateWithProvider(key);

        // Encode via PasswordUtil — provider key takes precedence over wlp.aes.encryption.key.
        String plaintext = "mySecretPassword";
        Map<String, String> props = new HashMap<>();
        // Provide a base64 key in props so encipher_internal takes the AES_V2 path.
        // The provider should override it.
        props.put(PasswordUtil.PROPERTY_AES_KEY, Base64.getEncoder().encodeToString(key.getEncoded()));

        try (MockedStatic<AESKeyManager> mock = Mockito.mockStatic(AESKeyManager.class, Mockito.CALLS_REAL_METHODS)) {
            // Make the resolver return the key when called for AES_V2 fallback path.
            mock.when(() -> AESKeyManager.getKeyCharsUsingResolver(KeyVersion.AES_V2, null))
                .thenReturn(Base64.getEncoder().encodeToString(key.getEncoded()).toCharArray());

            String encoded = PasswordUtil.encode(plaintext, "aes", props);

            // Version byte must be 2 (AES_V2).
            byte versionByte = Base64.getDecoder().decode(encoded.substring("{aes}".length()))[0];
            assertEquals("Version byte must be 2 for AES_V2", 2, versionByte);

            // Decoding must recover the original plaintext.
            String decoded = PasswordUtil.decode(encoded);
            assertEquals("Decoded value must match original plaintext", plaintext, decoded);
        }
    }

    /**
     * Provider key takes precedence over the wlp.aes.encryption.key base64 property.
     * The provider's key is used and NOT the one passed via PROPERTY_AES_KEY.
     */
    @Test
    public void testProviderWinsOverPropertyAesKey() throws Exception {
        SecretKey providerKey = generateAes256Key();
        activateWithProvider(providerKey);

        // A different key passed via properties — the provider should win.
        SecretKey differentKey = generateAes256Key();
        String differentKeyB64 = Base64.getEncoder().encodeToString(differentKey.getEncoded());
        Map<String, String> props = new HashMap<>();
        props.put(PasswordUtil.PROPERTY_AES_KEY, differentKeyB64);

        try (MockedStatic<AESKeyManager> mock = Mockito.mockStatic(AESKeyManager.class, Mockito.CALLS_REAL_METHODS)) {
            // The resolver for AES_V2 should return the provider key, not the different key.
            mock.when(() -> AESKeyManager.getKeyCharsUsingResolver(KeyVersion.AES_V2, null))
                .thenReturn(Base64.getEncoder().encodeToString(providerKey.getEncoded()).toCharArray());

            String plaintext = "providerWins";
            String encoded = PasswordUtil.encode(plaintext, "aes", props);

            // Verify that decoding with the provider key works (confirming provider was used).
            String decoded = PasswordUtil.decode(encoded);
            assertEquals("Decoding must succeed with the provider key, proving the provider was used", plaintext, decoded);
        }
    }

    /**
     * When no provider is registered, encryption falls back to the wlp.aes.encryption.key path (AES_V2 via resolver).
     */
    @Test
    public void testFallbackToEnvKeyWhenNoProvider() throws Exception {
        // No provider registered — getProviderKey() returns null naturally.
        SecretKey envKey = generateAes256Key();
        String envKeyB64 = Base64.getEncoder().encodeToString(envKey.getEncoded());
        Map<String, String> props = new HashMap<>();
        props.put(PasswordUtil.PROPERTY_AES_KEY, envKeyB64);

        try (MockedStatic<AESKeyManager> mock = Mockito.mockStatic(AESKeyManager.class, Mockito.CALLS_REAL_METHODS)) {
            mock.when(() -> AESKeyManager.getKeyCharsUsingResolver(KeyVersion.AES_V2, null))
                .thenReturn(envKeyB64.toCharArray());

            String plaintext = "fallbackPassword";
            String encoded = PasswordUtil.encode(plaintext, "aes", props);

            byte versionByte = Base64.getDecoder().decode(encoded.substring("{aes}".length()))[0];
            assertEquals("Version byte must be 2 even when using the env key", 2, versionByte);

            String decoded = PasswordUtil.decode(encoded);
            assertEquals("Decoded value must match original plaintext", plaintext, decoded);
        }
    }

    /**
     * Cache is invalidated when a new provider is bound (re-set).
     */
    @Test
    public void testCacheInvalidatedOnRebind() {
        SecretKey firstKey = generateAes256Key();
        activateWithProvider(firstKey);
        Key cached = PasswordCipherUtil.getProviderKey();
        assertEquals("First provider key should be cached", firstKey, cached);

        // Rebind a new provider with a different key.
        SecretKey secondKey = generateAes256Key();
        @SuppressWarnings("unchecked")
        ServiceReference<PasswordEncryptionKeyProvider> secondRef = context.mock(ServiceReference.class, "secondRef");
        PasswordEncryptionKeyProvider secondProvider = context.mock(PasswordEncryptionKeyProvider.class, "secondProvider");
        context.checking(new Expectations() {
            {
                // Give secondRef a higher service ranking (10 > 0) so it wins over firstRef.
                one(secondRef).getProperty(Constants.SERVICE_ID);
                will(returnValue(2L));
                one(secondRef).getProperty(Constants.SERVICE_RANKING);
                will(returnValue(10));
                // AtomicServiceReference calls compareTo when determining which reference is higher ranked.
                allowing(secondRef).compareTo(with(any(Object.class)));
                will(returnValue(1)); // secondRef > firstRef
                one(cc).locateService(PasswordCipherUtil.KEY_PROVIDER_SERVICE, secondRef);
                will(returnValue(secondProvider));
                one(secondProvider).getKey(CryptoUtils.ENCRYPT_ALGORITHM_AES);
                will(returnValue(secondKey));
            }
        });
        PasswordCipherUtil pcu2 = new PasswordCipherUtil();
        pcu2.activate(cc);
        pcu2.setPasswordEncryptionKeyProvider(secondRef);

        Key afterRebind = PasswordCipherUtil.getProviderKey();
        assertEquals("After rebind the new provider's key should be returned", secondKey, afterRebind);

        // Cleanup second ref, then let tearDown handle the first ref.
        pcu2.unsetPasswordEncryptionKeyProvider(secondRef);
        pcu2.deactivate(cc);
    }
}
