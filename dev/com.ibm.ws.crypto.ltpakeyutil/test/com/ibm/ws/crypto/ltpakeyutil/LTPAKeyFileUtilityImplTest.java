/*******************************************************************************
 * Copyright (c) 2016, 2026 IBM Corporation and others.
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

import java.util.Properties;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.Assert;
import org.junit.Test;

import com.ibm.wsspi.security.crypto.AesKeyProvider;
import com.ibm.wsspi.security.crypto.AesKeyProviderException;

/**
 *
 */
public class LTPAKeyFileUtilityImplTest {

    @Test
    public void testLTPAKeyGeneration() throws Exception {
        LTPAKeyFileUtilityImpl creator = new LTPAKeyFileUtilityImpl();
        Properties keyInfo = creator.generateLTPAKeys("WebAS".getBytes(), "myRealm");

        // Check the secret key.
        Assert.assertNotNull(keyInfo.get(LTPAKeyFileUtility.KEYIMPORT_SECRETKEY));

        // Check the private key.
        Assert.assertNotNull(keyInfo.get(LTPAKeyFileUtility.KEYIMPORT_PRIVATEKEY));

        // Check the public key.
        Assert.assertNotNull(keyInfo.get(LTPAKeyFileUtility.KEYIMPORT_PUBLICKEY));

        // Check the realm.
        Assert.assertEquals("myRealm", keyInfo.get(LTPAKeyFileUtility.KEYIMPORT_REALM));

        // Check the host.
        Assert.assertNotNull(keyInfo.get(LTPAKeyFileUtility.CREATION_HOST_PROPERTY));

        // Check the version.
        Assert.assertNotNull(keyInfo.get(LTPAKeyFileUtility.LTPA_VERSION_PROPERTY));

        // Check the creation date.
        Assert.assertNotNull(keyInfo.get(LTPAKeyFileUtility.CREATION_DATE_PROPERTY));
    }

    /**
     * Provider-backed key generation produces the same required properties as the password-derived path.
     */
    @Test
    public void testLTPAKeyGeneration_providerBacked() throws Exception {
        AesKeyProvider provider = newAesKeyProvider();
        LTPAKeyFileUtilityImpl creator = new LTPAKeyFileUtilityImpl();
        Properties keyInfo = creator.generateLTPAKeys(provider, "myRealm");

        Assert.assertNotNull(keyInfo.get(LTPAKeyFileUtility.KEYIMPORT_SECRETKEY));
        Assert.assertNotNull(keyInfo.get(LTPAKeyFileUtility.KEYIMPORT_PRIVATEKEY));
        Assert.assertNotNull(keyInfo.get(LTPAKeyFileUtility.KEYIMPORT_PUBLICKEY));
        Assert.assertEquals("myRealm", keyInfo.get(LTPAKeyFileUtility.KEYIMPORT_REALM));
        Assert.assertNotNull(keyInfo.get(LTPAKeyFileUtility.CREATION_HOST_PROPERTY));
        Assert.assertNotNull(keyInfo.get(LTPAKeyFileUtility.LTPA_VERSION_PROPERTY));
        Assert.assertNotNull(keyInfo.get(LTPAKeyFileUtility.CREATION_DATE_PROPERTY));
    }

    // -------------------------------------------------------------------------

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
