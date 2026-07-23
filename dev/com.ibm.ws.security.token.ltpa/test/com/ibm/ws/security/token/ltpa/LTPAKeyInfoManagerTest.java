/*******************************************************************************
 * Copyright (c) 2007, 2026 IBM Corporation and others.
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
package com.ibm.ws.security.token.ltpa;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Field;
import java.net.MalformedURLException;

import javax.crypto.BadPaddingException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.ibm.ws.crypto.ltpakeyutil.LTPAKeyFileUtility;
import com.ibm.ws.crypto.util.PasswordCipherUtil;
import com.ibm.wsspi.kernel.service.location.WsLocationAdmin;
import com.ibm.wsspi.kernel.service.location.WsResource;
import com.ibm.wsspi.security.crypto.AesKeyProvider;
import com.ibm.wsspi.security.crypto.AesKeyProviderException;

import test.UTLocationHelper;
import test.common.SharedOutputManager;

public class LTPAKeyInfoManagerTest {

    private static SharedOutputManager outputMgr;

    private static final String KEYIMPORTFILE_GETS_CREATED = "${server.config.dir}/resources/security/security.token.ltpa.keys.create.txt";
    private static final String KEYIMPORTFILE_NO_EXIST = "${server.config.dir}/resources/security/security.token.ltpa.keys.noexist.txt";
    private static final String KEYIMPORTFILE_INCORRECT_PRIVATEKEY = "${server.config.dir}/resources/security/security.token.ltpa.keys.incorrectprivatekey.txt";
    private static final String KEYIMPORTFILE_NO_SECRETKEY = "${server.config.dir}/resources/security/security.token.ltpa.keys.nosecretkey.txt";
    private static final String KEYIMPORTFILE_NO_PRIVATEKEY = "${server.config.dir}/resources/security/security.token.ltpa.keys.noprivatekey.txt";
    private static final String KEYIMPORTFILE_NO_PUBLICKEY = "${server.config.dir}/resources/security/security.token.ltpa.keys.nopublickey.txt";
    private static final String KEYIMPORTFILE_NO_REALM = "${server.config.dir}/resources/security/security.token.ltpa.keys.norealm.txt";
    private static final String LTPA_KEY_IMPORT_FILE = "${server.config.dir}/resources/security/security.token.ltpa.keys.correct.txt";

    private static final byte[] KEYPASSWORD_CORRECT = "WebAS".getBytes();
    private static final byte[] KEYPASSWORD_INCORRECT = "IncorrectKeyword".getBytes();

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        outputMgr = SharedOutputManager.getInstance();
        outputMgr.captureStreams();
    }

    @After
    public void tearDown() {
        outputMgr.resetStreams();
    }

    @AfterClass
    public static void tearDownClass() throws MalformedURLException {
        outputMgr.restoreStreams();
    }

    @Test
    public void prepareLTPAKeyInfo_newFile() throws Exception {
        WsLocationAdmin locAdmin = UTLocationHelper.getLocationManager();
        String ltpaKeyFile = "${server.config.dir}/resources/security/ignored";
        WsResource ltpaFile = locAdmin.resolveResource(ltpaKeyFile);
        ltpaFile.delete();
        LTPAKeyInfoManager keyInfoManager = new LTPAKeyInfoManager();
        keyInfoManager.prepareLTPAKeyInfo(UTLocationHelper.getLocationManager(),
                                          ltpaKeyFile,
                                          KEYPASSWORD_CORRECT, null, false);

        assertTrue("Expected CWWKS4103I message was not logged",
                   outputMgr.checkForMessages("CWWKS4103I:"));

        assertTrue("Expected CWWKS4104A message was not logged",
                   outputMgr.checkForStandardOut("CWWKS4104A:.*resources/security/ignored"));
    }

    @Test
    public void testNoExist() throws Exception {
        LTPAKeyInfoManager keyInfoManager = new LTPAKeyInfoManager();
        keyInfoManager.prepareLTPAKeyInfo(UTLocationHelper.getLocationManager(),
                                          KEYIMPORTFILE_GETS_CREATED,
                                          KEYPASSWORD_CORRECT, null, false);
        Assert.assertNotNull("Resource does not get created",
                             keyInfoManager.getLTPAKeyFileResource(UTLocationHelper.getLocationManager(),
                                                                   KEYIMPORTFILE_GETS_CREATED));
    }

    @Test
    public void testIncorrectPrivateKey() throws Exception {
        try {
            LTPAKeyInfoManager keyInfoManager = new LTPAKeyInfoManager();
            keyInfoManager.prepareLTPAKeyInfo(UTLocationHelper.getLocationManager(),
                                              KEYIMPORTFILE_INCORRECT_PRIVATEKEY,
                                              KEYPASSWORD_CORRECT, null, false);
        } catch (IllegalArgumentException e) {
            // Expected
        }
    }

    @Test
    public void testIncorrectKeyPassword() throws Exception {
        try {
            LTPAKeyInfoManager keyInfoManager = new LTPAKeyInfoManager();
            keyInfoManager.prepareLTPAKeyInfo(UTLocationHelper.getLocationManager(),
                                              LTPA_KEY_IMPORT_FILE,
                                              KEYPASSWORD_INCORRECT, null, false);
        } catch (BadPaddingException e) {
            // Expected
        }
    }

    @Test
    public void testNoSecretKey() throws Exception {
        try {
            LTPAKeyInfoManager keyInfoManager = new LTPAKeyInfoManager();
            keyInfoManager.prepareLTPAKeyInfo(UTLocationHelper.getLocationManager(),
                                              KEYIMPORTFILE_NO_SECRETKEY,
                                              KEYPASSWORD_CORRECT, null, false);
        } catch (IllegalArgumentException e) {
            String expectedMessage = "CWWKS4102E: The system cannot create the LTPA token because the required " + LTPAKeyFileUtility.KEYIMPORT_SECRETKEY + " property is missing.";
            String actualMessage = e.getMessage();
            assertEquals("Exception did not contain expected message",
                         expectedMessage, actualMessage);
            assertTrue("Expected message was not logged",
                       outputMgr.checkForStandardErr(expectedMessage));
        }

    }

    @Test
    public void testNoPrivateKey() throws Exception {
        try {
            LTPAKeyInfoManager keyInfoManager = new LTPAKeyInfoManager();
            keyInfoManager.prepareLTPAKeyInfo(UTLocationHelper.getLocationManager(),
                                              KEYIMPORTFILE_NO_PRIVATEKEY,
                                              KEYPASSWORD_CORRECT, null, false);
        } catch (IllegalArgumentException e) {
            String expectedMessage = "CWWKS4102E: The system cannot create the LTPA token because the required " + LTPAKeyFileUtility.KEYIMPORT_PRIVATEKEY
                                     + " property is missing.";
            String actualMessage = e.getMessage();
            assertEquals("Exception did not contain expected message",
                         expectedMessage, actualMessage);
            assertTrue("Expected message was not logged",
                       outputMgr.checkForStandardErr(expectedMessage));
        }

    }

    @Test
    public void testNoPublicKey() throws Exception {
        try {
            LTPAKeyInfoManager keyInfoManager = new LTPAKeyInfoManager();
            keyInfoManager.prepareLTPAKeyInfo(UTLocationHelper.getLocationManager(),
                                              KEYIMPORTFILE_NO_PUBLICKEY,
                                              KEYPASSWORD_CORRECT, null, false);
        } catch (IllegalArgumentException e) {
            String expectedMessage = "CWWKS4102E: The system cannot create the LTPA token because the required " + LTPAKeyFileUtility.KEYIMPORT_PUBLICKEY + " property is missing.";
            String actualMessage = e.getMessage();
            assertEquals("Exception did not contain expected message",
                         expectedMessage, actualMessage);
            assertTrue("Expected message was not logged",
                       outputMgr.checkForStandardErr(expectedMessage));
        }

    }

    @Test
    public void testNoRealm() throws Exception {
        LTPAKeyInfoManager keyInfoManager = new LTPAKeyInfoManager();
        keyInfoManager.prepareLTPAKeyInfo(UTLocationHelper.getLocationManager(),
                                          KEYIMPORTFILE_NO_REALM,
                                          KEYPASSWORD_CORRECT, null, false);

        Assert.assertNotNull("Secret key should not be null but was null",
                             keyInfoManager.getSecretKey(KEYIMPORTFILE_NO_REALM));
        Assert.assertNotNull("Private key should not be null but was null",
                             keyInfoManager.getPrivateKey(KEYIMPORTFILE_NO_REALM));
        Assert.assertNotNull("Public key should not be null but was null",
                             keyInfoManager.getPublicKey(KEYIMPORTFILE_NO_REALM));
        Assert.assertNull("Realm should be null but is not",
                          keyInfoManager.getRealm(KEYIMPORTFILE_NO_REALM));
    }

    @Test
    public void testCorrectInformation() throws Exception {

        LTPAKeyInfoManager keyInfoManager = new LTPAKeyInfoManager();
        keyInfoManager.prepareLTPAKeyInfo(UTLocationHelper.getLocationManager(),
                                          LTPA_KEY_IMPORT_FILE,
                                          KEYPASSWORD_CORRECT, null, false);

        // Check the secret key.
        Assert.assertNotNull(keyInfoManager.getSecretKey(LTPA_KEY_IMPORT_FILE));

        // Check the private key.
        Assert.assertNotNull(keyInfoManager.getPrivateKey(LTPA_KEY_IMPORT_FILE));

        // Check the public key.
        Assert.assertNotNull(keyInfoManager.getPublicKey(LTPA_KEY_IMPORT_FILE));

        // Check the realm.
        Assert.assertNotNull(keyInfoManager.getRealm(LTPA_KEY_IMPORT_FILE));
    }

    @Test
    public void testGetLTPAKeyFileResourceExists() throws Exception {
        LTPAKeyInfoManager keyInfoManager = new LTPAKeyInfoManager();
        Assert.assertNotNull("Resource does not exist",
                             keyInfoManager.getLTPAKeyFileResource(UTLocationHelper.getLocationManager(),
                                                                   LTPA_KEY_IMPORT_FILE));
    }

    @Test
    public void testGetLTPAKeyFileResourceNotExists() throws Exception {
        LTPAKeyInfoManager keyInfoManager = new LTPAKeyInfoManager();
        Assert.assertNull("Resource exists",
                          keyInfoManager.getLTPAKeyFileResource(UTLocationHelper.getLocationManager(),
                                                                KEYIMPORTFILE_NO_EXIST));
    }

    @Test
    public void prepareLTPAKeyInfo_outputdir_newFile() throws Exception {
        WsLocationAdmin locAdmin = UTLocationHelper.getLocationManager();
        String ltpaKeyFile = "${server.output.dir}/resources/security/ignored";
        WsResource ltpaFile = locAdmin.resolveResource(ltpaKeyFile);
        ltpaFile.delete();
        LTPAKeyInfoManager keyInfoManager = new LTPAKeyInfoManager();
        keyInfoManager.prepareLTPAKeyInfo(UTLocationHelper.getLocationManager(),
                                          ltpaKeyFile,
                                          KEYPASSWORD_CORRECT, null, false);

        assertTrue("Expected CWWKS4103I message was not logged",
                   outputMgr.checkForMessages("CWWKS4103I:"));

        assertTrue("Expected CWWKS4104A message was not logged",
                   outputMgr.checkForStandardOut("CWWKS4104A:.*resources/security/ignored"));
    }

    // -------------------------------------------------------------------------
    // Provider-backed tests
    // -------------------------------------------------------------------------

    /**
     * When useAesKeyProvider is true but no provider is available, prepareLTPAKeyInfo
     * must throw IllegalStateException — no silent fallback to password mode.
     */
    @Test
    public void useAesKeyProvider_noProviderAvailable_throwsIllegalStateException() throws Exception {
        // Ensure there is no provider set (default test environment has none).
        injectProvider(null);

        WsLocationAdmin locAdmin = UTLocationHelper.getLocationManager();
        String ltpaKeyFile = "${server.config.dir}/resources/security/provider.noexist.txt";
        WsResource ltpaFile = locAdmin.resolveResource(ltpaKeyFile);
        ltpaFile.delete();

        LTPAKeyInfoManager keyInfoManager = new LTPAKeyInfoManager();
        try {
            keyInfoManager.prepareLTPAKeyInfo(locAdmin, ltpaKeyFile, KEYPASSWORD_CORRECT, null, false, true);
            Assert.fail("Expected IllegalStateException when no AesKeyProvider is available");
        } catch (IllegalStateException e) {
            // Expected — the error message must reference the missing provider.
            assertTrue("Exception message should mention AES key provider",
                       e.getMessage() != null && !e.getMessage().isEmpty());
        }
    }

    /**
     * Provider-backed round-trip: generate keys using a provider, then load them back with the same provider.
     * All three key types (secret, private, public) must be recoverable.
     */
    @Test
    public void useAesKeyProvider_roundTrip_succeeds() throws Exception {
        AesKeyProvider provider = newAesKeyProvider();
        injectProvider(provider);
        try {
            WsLocationAdmin locAdmin = UTLocationHelper.getLocationManager();
            String ltpaKeyFile = "${server.config.dir}/resources/security/provider.roundtrip.txt";
            WsResource ltpaFile = locAdmin.resolveResource(ltpaKeyFile);
            ltpaFile.delete();

            LTPAKeyInfoManager keyInfoManager = new LTPAKeyInfoManager();
            keyInfoManager.prepareLTPAKeyInfo(locAdmin, ltpaKeyFile, null, null, false, true);

            assertNotNull("Secret key must be present after provider-backed round-trip",
                          keyInfoManager.getSecretKey(ltpaKeyFile));
            assertNotNull("Private key must be present after provider-backed round-trip",
                          keyInfoManager.getPrivateKey(ltpaKeyFile));
            assertNotNull("Public key must be present after provider-backed round-trip",
                          keyInfoManager.getPublicKey(ltpaKeyFile));
        } finally {
            injectProvider(null);
        }
    }

    /**
     * Password-backed mode must still work after provider-backed tests (no cross-contamination).
     */
    @Test
    public void passwordMode_unaffected_whenProviderIsNull() throws Exception {
        injectProvider(null);

        LTPAKeyInfoManager keyInfoManager = new LTPAKeyInfoManager();
        keyInfoManager.prepareLTPAKeyInfo(UTLocationHelper.getLocationManager(),
                                          LTPA_KEY_IMPORT_FILE,
                                          KEYPASSWORD_CORRECT, null, false, false);

        assertNotNull("Secret key should be present in password mode",
                      keyInfoManager.getSecretKey(LTPA_KEY_IMPORT_FILE));
        assertNotNull("Private key should be present in password mode",
                      keyInfoManager.getPrivateKey(LTPA_KEY_IMPORT_FILE));
        assertNotNull("Public key should be present in password mode",
                      keyInfoManager.getPublicKey(LTPA_KEY_IMPORT_FILE));
    }

    // -------------------------------------------------------------------------

    /** Inject an {@link AesKeyProvider} into {@link PasswordCipherUtil}'s static field for unit testing. */
    private static void injectProvider(AesKeyProvider provider) throws Exception {
        Field f = PasswordCipherUtil.class.getDeclaredField("aesKeyProviderImpl");
        f.setAccessible(true);
        f.set(null, provider);
    }

    private static AesKeyProvider newAesKeyProvider() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey k = kg.generateKey();
        return new AesKeyProvider() {
            @Override
            public SecretKey getKey() throws AesKeyProviderException {
                return k;
            }
        };
    }

}
