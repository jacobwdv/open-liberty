/*******************************************************************************n * Copyright (c) 2023 IBM Corporation and others.n * All rights reserved. This program and the accompanying materialsn * are made available under the terms of the Eclipse Public License 2.0n * which accompanies this distribution, and is available atn * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0n *n * Contributors:n *     IBM Corporation - initial API and implementationn *******************************************************************************/
package com.ibm.ws.install.internal;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.time.Instant;
import java.util.Date;

import org.bouncycastle.openpgp.PGPPublicKey;
import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
import org.jmock.lib.legacy.ClassImposteriser;
import org.junit.Test;

import com.ibm.ws.install.InstallException;

/**
 *
 */
public class VerifySignatureUtilityTest {
    protected final Mockery mockery = new JUnit4Mockery() {
        {
            setImposteriser(ClassImposteriser.INSTANCE);
        }
    };
    PGPPublicKey publicKey = mockery.mock(PGPPublicKey.class);
    VerifySignatureUtility utility = new VerifySignatureUtility();

    /**
     * Test method for {@link com.ibm.ws.install.internal.VerifySignatureUtility#VerifySignatureUtility()}.
     */
//    @Test
//    public void testVerifySignatureUtility() {
//        fail("Not yet implemented");
//    }
//
//    /**
//     * Test method for {@link com.ibm.ws.install.internal.VerifySignatureUtility#isKeyValid(java.nio.file.Path)}.
//     */
//    @Test
//    public void testIsKeyValid() {
//        fail("Not yet implemented");
//    }
//
//    /**
//     * Test method for
//     * {@link com.ibm.ws.install.internal.VerifySignatureUtility#downloadPublicKeys(java.util.Collection, com.ibm.ws.install.InstallConstants.VerifyOption, java.util.Map)}.
//     */
//    @Test
//    public void testDownloadPublicKeys() {
//        fail("Not yet implemented");
//    }
//
//    /**
//     * Test method for {@link com.ibm.ws.install.internal.VerifySignatureUtility#verifySignatures(java.util.Collection, java.util.List, java.util.List)}.
//     */
//    @Test
//    public void testVerifySignatures() {
//        fail("Not yet implemented");
//    }

    @Test
    public void testValidatePublicKeyPass() throws InstallException {
        mockery.checking(new Expectations() {
            {
                allowing(publicKey).hasRevocation();
                will(returnValue(false));
                allowing(publicKey).getValidSeconds();
                will(returnValue(0L));
                allowing(publicKey).getKeyID();
                will(returnValue(0L));
            }
        });
        assertTrue(utility.validatePublicKey(publicKey));
    }

    @Test
    public void testValidatePublicKeyRevoked() {
        boolean pass = false;

        mockery.checking(new Expectations() {
            {
                allowing(publicKey).hasRevocation();
                will(returnValue(true));
                allowing(publicKey).getValidSeconds();
                will(returnValue(0L));
                allowing(publicKey).getKeyID();
                will(returnValue(1L));
            }
        });
        try {
            utility.validatePublicKey(publicKey);
        } catch (InstallException e) {
            pass = true;
            assertTrue(e.getMessage().contains(getKeyID(publicKey)));
        }
        assertTrue(pass);
    }

    @Test
    public void testValidatePublicKeyTimedOut() {
        boolean pass = false;

        mockery.checking(new Expectations() {
            {
                allowing(publicKey).hasRevocation();
                will(returnValue(false));
                allowing(publicKey).getCreationTime();
                will(returnValue(new Date(0L)));
                allowing(publicKey).getValidSeconds();
                will(returnValue(1L));
                allowing(publicKey).getKeyID();
                will(returnValue(1L));
            }
        });
        Instant expiryDate = publicKey.getCreationTime().toInstant().plusSeconds(publicKey.getValidSeconds());
        try {
            utility.validatePublicKey(publicKey);
        } catch (InstallException e) {
            pass = true;
            assertTrue(e.getMessage().contains(getKeyID(publicKey)));
            assertTrue(e.getMessage().contains(expiryDate.toString()));
        }
        assertTrue(pass);
    }

    @Test
    public void testValidatePublicKeyTimedOutAndRevoked() {
        boolean pass = false;

        mockery.checking(new Expectations() {
            {
                allowing(publicKey).hasRevocation();
                will(returnValue(true));
                allowing(publicKey).getValidSeconds();
                will(returnValue(0L));
                allowing(publicKey).getCreationTime();
                will(returnValue(new Date(0L)));
                allowing(publicKey).getValidSeconds();
                will(returnValue(1L));
                allowing(publicKey).getKeyID();
                will(returnValue(1L));
            }
        });
        Instant expiryDate = publicKey.getCreationTime().toInstant().plusSeconds(publicKey.getValidSeconds());

        try {
            utility.validatePublicKey(publicKey);
        } catch (InstallException e) {
            pass = true;
            assertTrue(e.getMessage().contains(getKeyID(publicKey)));
            assertFalse(e.getMessage().contains(expiryDate.toString()));
        }
        assertTrue(pass);
    }

    /**
     * @param publicKey2
     * @return
     */
    private String getKeyID(PGPPublicKey key) {
        // TODO Auto-generated method stub
        return String.format("%x", publicKey.getKeyID());
    }

}
