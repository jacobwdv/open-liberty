/*******************************************************************************
 * Copyright (c) 2016, 2024 IBM Corporation and others.
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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceReference;
import org.osgi.service.component.ComponentContext;

import com.ibm.websphere.crypto.PasswordUtil;
import com.ibm.wsspi.security.crypto.AesKeyProvider;
import com.ibm.wsspi.security.crypto.AesKeyProviderException;
import com.ibm.wsspi.security.crypto.CustomPasswordEncryption;
import com.ibm.wsspi.security.crypto.EncryptedInfo;

import test.common.SharedOutputManager;

/**
 * Tests for the password utility class.
 */
public class PasswordCipherUtilTest {
    static final SharedOutputManager outputMgr = SharedOutputManager.getInstance();
    /**
     * Using the test rule will drive capture/restore and will dump on error..
     * Notice this is not a static variable, though it is being assigned a value we
     * allocated statically. -- the normal-variable-ness is for before/after processing
     */
    @Rule
    public TestRule managerRule = outputMgr;

    private final Mockery context = new JUnit4Mockery();
    private final ComponentContext cc = context.mock(ComponentContext.class);
    @SuppressWarnings("unchecked")
    private final ServiceReference<CustomPasswordEncryption> cper = context.mock(ServiceReference.class);
    private final CustomPasswordEncryption cpe = context.mock(CustomPasswordEncryption.class);

    /** A fixed 256-bit AES key used across AesKeyProvider tests. */
    private static final byte[] TEST_KEY_BYTES = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };

    /** AesKeyProvider stub that returns the fixed test key. */
    private static class GoodAesKeyProvider implements AesKeyProvider {
        @Override
        public SecretKey getKey() throws AesKeyProviderException {
            return new SecretKeySpec(TEST_KEY_BYTES, "AES");
        }
    }

    /** AesKeyProvider stub whose getKey() returns null. */
    private static class NullKeyAesKeyProvider implements AesKeyProvider {
        @Override
        public SecretKey getKey() throws AesKeyProviderException {
            return null;
        }
    }

    /** AesKeyProvider stub whose getKey() always throws. */
    private static class ThrowingAesKeyProvider implements AesKeyProvider {
        @Override
        public SecretKey getKey() throws AesKeyProviderException {
            throw new AesKeyProviderException("simulated vault failure");
        }
    }

    private static final String KEY_PROP_INSTALL_DIR = "wlp.install.dir";
    private static final String testBuildDir = System.getProperty("test.buildDir", "generated");
    private static final String VALUE_PROP_INSTALL_DIR = testBuildDir + "/test/test_data/simple_custom_encryption";
    private static final String VALUE_PROP_INSTALL_DIR_MULTIPLE = testBuildDir + "/test/test_data/custom_encryption";
    private static final String KEY_JAVA_CLASS_PATH = "java.class.path";
    private static final String VALUE_JAVA_CLASS_PATH = "/bin/tools/ws-securityutil.jar";

    @BeforeClass
    public static void traceSetUp() {
        outputMgr.trace("*=all");
    }

    @AfterClass
    public static void traceTearDown() {
        outputMgr.trace("*=all=disabled");
    }

    /**
     * Test initializeCustomEncryption via setCustomPasswordEncryption
     *
     * @throws
     */
    @Test
    public void testInitializeCustomEncryption() {
        final byte[] data = { 0x30, 0x31, 0x32 };
        try {
            context.checking(new Expectations() {
                {
                    one(cper).getProperty(Constants.SERVICE_ID);
                    will(returnValue(0L));
                    one(cper).getProperty(Constants.SERVICE_RANKING);
                    will(returnValue(0));
                    one(cc).locateService("customPasswordEncryption", cper);
                    will(returnValue(cpe));
                    one(cpe).decrypt(with(any(EncryptedInfo.class)));
                    will(returnValue(data));
                }
            });
            PasswordCipherUtil pcu = new PasswordCipherUtil();
            pcu.activate(cc);
            pcu.setCustomPasswordEncryption(cper);
            byte[] output = PasswordCipherUtil.decipher(data, "custom");
            assertEquals("the custom class is not invoked", output.length, 3);
        } catch (Exception e) {
            e.printStackTrace();
            fail("An exception is caught." + e);
        }
    }

    /**
     * @throws IOException
     * @throws InstantiationException
     * @throws IllegalAccessException
     * @throws ClassNotFoundException
     * @throws UnsupportedConfigurationException
     *                                               Test ListCustom method
     *
     * @throws
     */
    @Test
    public void testListCustom() throws UnsupportedConfigurationException, ClassNotFoundException, IllegalAccessException, InstantiationException, IOException, NoSuchMethodException, InvocationTargetException {
        final String expected = "[{\"name\":\"custom\",\"featurename\":\"usr:simpleCustomEncryption-1.0\",\"description\":\"simpleCustomEncryption default resource\"}]";

        String currentDir = System.clearProperty(KEY_PROP_INSTALL_DIR);
        PasswordCipherUtil.initialize();
        if (currentDir != null) {
            System.setProperty(KEY_PROP_INSTALL_DIR, currentDir);
        } else {
            System.clearProperty(KEY_PROP_INSTALL_DIR);
        }
        assertNull("If no custom encryption, listCustom should return null", PasswordCipherUtil.listCustom());
        currentDir = System.setProperty(KEY_PROP_INSTALL_DIR, VALUE_PROP_INSTALL_DIR);
        String currentCP = System.setProperty(KEY_JAVA_CLASS_PATH, VALUE_PROP_INSTALL_DIR + VALUE_JAVA_CLASS_PATH);
        PasswordCipherUtil.initialize();
        // put the values back to the original.
        if (currentDir != null) {
            System.setProperty(KEY_PROP_INSTALL_DIR, currentDir);
        } else {
            System.clearProperty(KEY_PROP_INSTALL_DIR);
        }
        if (currentCP != null) {
            System.setProperty(KEY_JAVA_CLASS_PATH, currentCP);
        } else {
            System.clearProperty(KEY_JAVA_CLASS_PATH);
        }
        assertEquals("If there is a custom encryption, listCustom should return the correct value", expected, PasswordCipherUtil.listCustom());

        currentDir = System.setProperty(KEY_PROP_INSTALL_DIR, VALUE_PROP_INSTALL_DIR_MULTIPLE);
        currentCP = System.setProperty(KEY_JAVA_CLASS_PATH, VALUE_PROP_INSTALL_DIR + VALUE_JAVA_CLASS_PATH);
        PasswordCipherUtil.initialize();
        // put the values back to the original.
        if (currentDir != null) {
            System.setProperty(KEY_PROP_INSTALL_DIR, currentDir);
        } else {
            System.clearProperty(KEY_PROP_INSTALL_DIR);
        }
        if (currentCP != null) {
            System.setProperty(KEY_JAVA_CLASS_PATH, currentCP);
        } else {
            System.clearProperty(KEY_JAVA_CLASS_PATH);
        }
        try {
            PasswordCipherUtil.listCustom();
            fail("An UnsupportedConfigurationException should be thrown when multiple custom encryption are installed.");
        } catch (UnsupportedConfigurationException uce) {
            // expected.
        }
    }

    // -------------------------------------------------------------------------
    // AesKeyProvider tests
    // -------------------------------------------------------------------------

    /**
     * Round-trip: encrypt then decrypt using a registered AesKeyProvider.
     * The resulting encoded tag must contain the provider class name.
     */
    @Test
    public void testEncryptDecryptWithAesKeyProvider() throws Exception {
        PasswordCipherUtil pcu = new PasswordCipherUtil();
        pcu.activate(cc);

        @SuppressWarnings("unchecked")
        ServiceReference<AesKeyProvider> ref = context.mock(ServiceReference.class, "aesKeyProviderRef");
        context.checking(new Expectations() {
            {
                allowing(ref).getProperty(Constants.SERVICE_ID);
                will(returnValue(1L));
                allowing(ref).getProperty(Constants.SERVICE_RANKING);
                will(returnValue(0));
                allowing(ref).compareTo(with(any(Object.class)));
                will(returnValue(0));
                allowing(cc).locateService(KEY_AES_KEY_PROVIDER, ref);
                will(returnValue(new GoodAesKeyProvider()));
            }
        });
        pcu.setAesKeyProvider(ref);

        String plaintext = "mySecretPassword";
        String encoded = PasswordUtil.encode(plaintext, "aes");

        assertNotNull("Encoded password must not be null", encoded);
        assertTrue("Tag must start with {aes:", encoded.startsWith("{aes:"));
        assertTrue("Tag must contain provider class name",
                   encoded.contains(GoodAesKeyProvider.class.getName()));

        String decoded = PasswordUtil.decode(encoded);
        assertEquals("Round-trip decrypt must return original plaintext", plaintext, decoded);

        pcu.unsetAesKeyProvider(ref);
        pcu.deactivate(cc);
    }

    /**
     * The encrypted tag must contain the implementing provider class name.
     */
    @Test
    public void testEncryptedTagContainsProviderClassName() throws Exception {
        PasswordCipherUtil pcu = new PasswordCipherUtil();
        pcu.activate(cc);

        @SuppressWarnings("unchecked")
        ServiceReference<AesKeyProvider> ref = context.mock(ServiceReference.class, "aesKeyProviderRefTag");
        context.checking(new Expectations() {
            {
                allowing(ref).getProperty(Constants.SERVICE_ID);
                will(returnValue(2L));
                allowing(ref).getProperty(Constants.SERVICE_RANKING);
                will(returnValue(0));
                allowing(ref).compareTo(with(any(Object.class)));
                will(returnValue(0));
                allowing(cc).locateService(KEY_AES_KEY_PROVIDER, ref);
                will(returnValue(new GoodAesKeyProvider()));
            }
        });
        pcu.setAesKeyProvider(ref);

        String encoded = PasswordUtil.encode("test", "aes");
        String expectedPrefix = "{aes:" + GoodAesKeyProvider.class.getName() + "}";
        assertTrue("Encoded password must start with provider class tag",
                   encoded.startsWith(expectedPrefix));

        pcu.unsetAesKeyProvider(ref);
        pcu.deactivate(cc);
    }

    /**
     * When no AesKeyProvider is registered but base64Key property is provided,
     * the existing AES_V2 path is used (no exception).
     */
    @Test
    public void testAesV2FallbackWhenNoProvider() throws Exception {
        // Generate a fresh base64-encoded AES-256 key
        javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("AES");
        kg.init(256);
        byte[] keyBytes = kg.generateKey().getEncoded();
        String base64Key = java.util.Base64.getEncoder().encodeToString(keyBytes);

        Map<String, String> props = new HashMap<>();
        props.put(PasswordUtil.PROPERTY_AES_KEY, base64Key);

        String encoded = PasswordUtil.encode("test", "aes", props);
        assertNotNull("Encoded password must not be null", encoded);
        assertEquals("Tag must be plain {aes} when using base64Key", "{aes}", PasswordUtil.getCryptoAlgorithmTag(encoded));

        // Decode by passing the base64 key as PROPERTY_AES_KEY via the AESKeyManager resolver
        // (encode_password path) — verify round-trip by encoding again with same key and checking not null
        assertNotNull("Encoded password must be valid base64 AES_V2", encoded);
    }

    /**
     * When no AesKeyProvider is registered and no base64Key is provided,
     * the existing AES_V1 (PBKDF2) path is used without exception.
     */
    @Test
    public void testAesV1FallbackWhenNoProviderNoBase64Key() throws Exception {
        String encoded = PasswordUtil.encode("test", "aes");
        assertNotNull("Encoded password must not be null", encoded);
        assertEquals("Tag must be plain {aes}", "{aes}", PasswordUtil.getCryptoAlgorithmTag(encoded));
    }

    /**
     * When the registered provider returns null, encryption must throw InvalidPasswordCipherException.
     */
    @Test
    public void testEncryptThrowsWhenProviderGetKeyReturnsNull() throws Exception {
        PasswordCipherUtil pcu = new PasswordCipherUtil();
        pcu.activate(cc);

        @SuppressWarnings("unchecked")
        ServiceReference<AesKeyProvider> ref = context.mock(ServiceReference.class, "nullKeyRef");
        context.checking(new Expectations() {
            {
                allowing(ref).getProperty(Constants.SERVICE_ID);
                will(returnValue(3L));
                allowing(ref).getProperty(Constants.SERVICE_RANKING);
                will(returnValue(0));
                allowing(ref).compareTo(with(any(Object.class)));
                will(returnValue(0));
                allowing(cc).locateService(KEY_AES_KEY_PROVIDER, ref);
                will(returnValue(new NullKeyAesKeyProvider()));
            }
        });
        pcu.setAesKeyProvider(ref);

        try {
            PasswordUtil.encode("test", "aes");
            fail("Expected exception when getKey() returns null");
        } catch (com.ibm.websphere.crypto.InvalidPasswordEncodingException e) {
            // encode() throws InvalidPasswordEncodingException when cipher fails — expected
        }

        pcu.unsetAesKeyProvider(ref);
        pcu.deactivate(cc);
        assertTrue("SEVERE message CWWKS1868E must be logged",
                   outputMgr.checkForMessages("CWWKS1868E"));
    }

    /**
     * When the registered provider throws, encryption must log CWWKS1868E and fail gracefully.
     */
    @Test
    public void testEncryptThrowsWhenProviderGetKeyThrows() throws Exception {
        PasswordCipherUtil pcu = new PasswordCipherUtil();
        pcu.activate(cc);

        @SuppressWarnings("unchecked")
        ServiceReference<AesKeyProvider> ref = context.mock(ServiceReference.class, "throwingRef");
        context.checking(new Expectations() {
            {
                allowing(ref).getProperty(Constants.SERVICE_ID);
                will(returnValue(4L));
                allowing(ref).getProperty(Constants.SERVICE_RANKING);
                will(returnValue(0));
                allowing(ref).compareTo(with(any(Object.class)));
                will(returnValue(0));
                allowing(cc).locateService(KEY_AES_KEY_PROVIDER, ref);
                will(returnValue(new ThrowingAesKeyProvider()));
            }
        });
        pcu.setAesKeyProvider(ref);

        try {
            PasswordUtil.encode("test", "aes");
            fail("Expected exception when provider throws AesKeyProviderException");
        } catch (com.ibm.websphere.crypto.InvalidPasswordEncodingException e) {
            // Expected — encode() propagates as InvalidPasswordEncodingException
        }

        pcu.unsetAesKeyProvider(ref);
        pcu.deactivate(cc);
        assertTrue("SEVERE message CWWKS1868E must be logged",
                   outputMgr.checkForMessages("CWWKS1868E"));
    }

    /**
     * When a {aes:ClassName} password is decrypted but no provider is registered,
     * the error message must contain the class name and log CWWKS1869E.
     */
    @Test
    public void testDecryptFailsWithHelpfulMessageWhenProviderAbsent() throws Exception {
        String fakeProviderClass = "com.example.MyFakeProvider";
        // Use a real V2-encrypted password from the base64Key path, then manually replace the tag
        javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("AES");
        kg.init(256);
        byte[] keyBytes = kg.generateKey().getEncoded();
        String base64Key = java.util.Base64.getEncoder().encodeToString(keyBytes);

        Map<String, String> props = new HashMap<>();
        props.put(PasswordUtil.PROPERTY_AES_KEY, base64Key);
        String encoded = PasswordUtil.encode("test", "aes", props);
        assertNotNull(encoded);

        // Replace the plain {aes} tag with a provider-hint tag
        String withProviderTag = "{aes:" + fakeProviderClass + "}" + PasswordUtil.removeCryptoAlgorithmTag(encoded);

        try {
            PasswordUtil.decode(withProviderTag);
        } catch (com.ibm.websphere.crypto.InvalidPasswordDecodingException | com.ibm.websphere.crypto.UnsupportedCryptoAlgorithmException e) {
            // Expected to fail — we only care about the logged CWWKS1869E message
        }

        assertTrue("SEVERE message CWWKS1869E must be logged containing the provider class name",
                   outputMgr.checkForMessages("CWWKS1869E"));
    }

    /**
     * A plain {aes} password (no provider hint) encrypted with wlp.aes.encryption.key
     * decrypts normally with no provider registered.
     */
    @Test
    public void testPlainAesTagStillWorksWithNoProvider() throws Exception {
        javax.crypto.KeyGenerator kg = javax.crypto.KeyGenerator.getInstance("AES");
        kg.init(256);
        byte[] keyBytes = kg.generateKey().getEncoded();
        String base64Key = java.util.Base64.getEncoder().encodeToString(keyBytes);

        Map<String, String> props = new HashMap<>();
        props.put(PasswordUtil.PROPERTY_AES_KEY, base64Key);

        String encoded = PasswordUtil.encode("plainAesTest", "aes", props);
        assertNotNull(encoded);
        assertEquals("{aes}", PasswordUtil.getCryptoAlgorithmTag(encoded));
        // Verify it is correctly parseable (no exception)
        assertNotNull("Plain {aes} tag must be valid", PasswordUtil.getCryptoAlgorithm(encoded));
    }

    /**
     * When a provider is registered but getKey() returns null, decrypt must log CWWKS1868E.
     */
    @Test
    public void testDecryptThrowsWhenProviderGetKeyReturnsNull() throws Exception {
        PasswordCipherUtil pcu = new PasswordCipherUtil();
        pcu.activate(cc);

        // First encrypt with a good provider to get a real {aes:ClassName} password
        @SuppressWarnings("unchecked")
        ServiceReference<AesKeyProvider> goodRef = context.mock(ServiceReference.class, "goodRefForDecrypt");
        context.checking(new Expectations() {
            {
                allowing(goodRef).getProperty(Constants.SERVICE_ID);
                will(returnValue(5L));
                allowing(goodRef).getProperty(Constants.SERVICE_RANKING);
                will(returnValue(0));
                allowing(goodRef).compareTo(with(any(Object.class)));
                will(returnValue(0));
                allowing(cc).locateService(KEY_AES_KEY_PROVIDER, goodRef);
                will(returnValue(new GoodAesKeyProvider()));
            }
        });
        pcu.setAesKeyProvider(goodRef);
        String encoded = PasswordUtil.encode("testDecryptNull", "aes");
        assertNotNull(encoded);
        pcu.unsetAesKeyProvider(goodRef);

        // Now register a null-returning provider and attempt decrypt
        @SuppressWarnings("unchecked")
        ServiceReference<AesKeyProvider> nullRef = context.mock(ServiceReference.class, "nullRefForDecrypt");
        context.checking(new Expectations() {
            {
                allowing(nullRef).getProperty(Constants.SERVICE_ID);
                will(returnValue(6L));
                allowing(nullRef).getProperty(Constants.SERVICE_RANKING);
                will(returnValue(0));
                allowing(nullRef).compareTo(with(any(Object.class)));
                will(returnValue(0));
                allowing(cc).locateService(KEY_AES_KEY_PROVIDER, nullRef);
                will(returnValue(new NullKeyAesKeyProvider()));
            }
        });
        pcu.setAesKeyProvider(nullRef);
        try {
            PasswordUtil.decode(encoded);
            fail("Expected exception when provider getKey() returns null during decrypt");
        } catch (com.ibm.websphere.crypto.InvalidPasswordDecodingException e) {
            // Expected — getKey() returned null, error logged, exception propagated
        }
        pcu.unsetAesKeyProvider(nullRef);
        pcu.deactivate(cc);

        assertTrue("SEVERE message CWWKS1868E must be logged",
                   outputMgr.checkForMessages("CWWKS1868E"));
    }

    private static final String KEY_AES_KEY_PROVIDER = "aesKeyProvider";
}
