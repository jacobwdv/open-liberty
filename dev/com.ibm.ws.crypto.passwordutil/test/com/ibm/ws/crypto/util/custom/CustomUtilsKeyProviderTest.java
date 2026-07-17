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
package com.ibm.ws.crypto.util.custom;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.ibm.wsspi.security.crypto.PasswordEncryptionKeyProvider;

/**
 * Tests for {@link CustomUtils#findAndInstantiateKeyProvider()}.
 */
public class CustomUtilsKeyProviderTest {

    private static final String KEY_PROP_INSTALL_DIR = "wlp.install.dir";
    private static final String testBuildDir = System.getProperty("test.buildDir", "generated");

    /** Root that contains a valid ws-passwordEncryptionKeyProvider extension JAR. */
    private static final String VALUE_PROP_INSTALL_DIR_WITH_PROVIDER =
            testBuildDir + "/test/test_data/simple_key_provider";

    /** Root that has NO ws-passwordEncryptionKeyProvider directory at all. */
    private static final String VALUE_PROP_INSTALL_DIR_NO_PROVIDER =
            testBuildDir + "/test/test_data/simple_custom_encryption";

    private String savedInstallDir;

    @Before
    public void saveInstallDir() {
        savedInstallDir = System.getProperty(KEY_PROP_INSTALL_DIR);
    }

    @After
    public void restoreInstallDir() {
        if (savedInstallDir != null) {
            System.setProperty(KEY_PROP_INSTALL_DIR, savedInstallDir);
        } else {
            System.clearProperty(KEY_PROP_INSTALL_DIR);
        }
    }

    /**
     * When a valid ws-passwordEncryptionKeyProvider JAR with IBM-KeyProviderClass is present,
     * findAndInstantiateKeyProvider() returns a non-null provider instance.
     */
    @Test
    public void testFindAndInstantiateKeyProviderFound() throws Exception {
        System.setProperty(KEY_PROP_INSTALL_DIR, VALUE_PROP_INSTALL_DIR_WITH_PROVIDER);
        PasswordEncryptionKeyProvider provider = CustomUtils.findAndInstantiateKeyProvider();
        assertNotNull("findAndInstantiateKeyProvider() should return a provider when a JAR is present", provider);
        // The provider must be callable — getKey("AES") must return a non-null key.
        assertNotNull("Provider.getKey(\"AES\") must return a non-null key", provider.getKey("AES"));
    }

    /**
     * When no ws-passwordEncryptionKeyProvider directory exists, findAndInstantiateKeyProvider() returns null.
     */
    @Test
    public void testFindAndInstantiateKeyProviderNotFound() throws Exception {
        System.setProperty(KEY_PROP_INSTALL_DIR, VALUE_PROP_INSTALL_DIR_NO_PROVIDER);
        PasswordEncryptionKeyProvider provider = CustomUtils.findAndInstantiateKeyProvider();
        assertNull("findAndInstantiateKeyProvider() should return null when no provider JAR is present", provider);
    }

}
