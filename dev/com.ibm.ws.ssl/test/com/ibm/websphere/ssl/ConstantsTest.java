/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package com.ibm.websphere.ssl;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

/**
 *
 */
public class ConstantsTest {

    @Test
    public void testRemoveCipherSuiteModifier() {
        String[] ciphers = new String[] { "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" };
        String modifier = "-TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
        assertEquals("Returned list should be empty", 0, Constants.adjustSupportedCiphers(ciphers, modifier).length);
    }

    @Test
    public void testAddCipherSuiteModifier() {
        String[] ciphers = new String[0];
        String modifier = "+TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
        String[] adjustedCiphers = Constants.adjustSupportedCiphers(ciphers, modifier);
        assertEquals("Returned list should be length 1", 1, adjustedCiphers.length);
        assertEquals("Only cipher suite should be TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", adjustedCiphers[0]);
    }

    @Test
    public void testAddAndRemoveCipherSuiteModifier() {
        String[] ciphers = new String[] { "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" };
        String modifier = "-TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 +TLS_AES_256_GCM_SHA384";
        String[] adjustedCiphers = Constants.adjustSupportedCiphers(ciphers, modifier);
        assertEquals("Returned list should be length 1", 1, adjustedCiphers.length);
        assertEquals("Only cipher suite should be TLS_AES_256_GCM_SHA384", "TLS_AES_256_GCM_SHA384", adjustedCiphers[0]);
    }

}
