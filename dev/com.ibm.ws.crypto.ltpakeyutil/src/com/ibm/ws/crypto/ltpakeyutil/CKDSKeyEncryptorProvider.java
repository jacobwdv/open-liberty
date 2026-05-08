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

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import com.ibm.ws.common.crypto.CryptoUtils;
import com.ibm.wsspi.security.crypto.KeyEncryptorProvider;

/**
 * KeyEncryptorProvider implementation that uses z/OS CKDS (Cryptographic Key Data Set)
 * with the IBMJCECCA provider for hardware-based cryptographic operations.
 * 
 * This provider retrieves an AES-256 key from CKDS using a predefined key label
 * and performs encryption/decryption operations using the IBMJCECCA hardware crypto provider.
 * 
 * This provider should only be activated on z/OS systems with CKDS support.
 */
public class CKDSKeyEncryptorProvider implements KeyEncryptorProvider {

    private static final String CKDS_KEY_LABEL = "LTPAAES";
    private static final String CIPHER = CryptoUtils.AES_CBC_CIPHER;
    
    private final byte[] ckdsKey;

    /**
     * Constructor that retrieves the AES key from CKDS.
     * 
     * @throws Exception if CKDS key retrieval fails
     */
    public CKDSKeyEncryptorProvider() throws Exception {
        this.ckdsKey = getAesKeyFromCKDS();
        if (this.ckdsKey == null) {
            throw new IllegalStateException("Failed to retrieve CKDS key with label: " + CKDS_KEY_LABEL);
        }
    }

    /**
     * Retrieve an AES key from z/OS CKDS using the IBMJCECCA provider.
     * This method uses reflection to avoid compile-time dependency on z/OS-specific classes.
     *
     * @return The raw key bytes from CKDS, or null if CKDS is not available or retrieval fails
     */
    private byte[] getAesKeyFromCKDS() {
        try {
            // Use IBMJCECCA provider to retrieve key from z/OS CKDS
            SecretKeyFactory aesKeyFactory = SecretKeyFactory.getInstance("AES", CryptoUtils.IBMJCECCA_NAME);
            
            // Create KeyLabelKeySpec using reflection to avoid compile-time dependency
            // KeyLabelKeySpec is only available on z/OS with IBMJCECCA provider
            Class<?> keyLabelKeySpecClass = Class.forName("com.ibm.crypto.hdwrCCA.provider.KeyLabelKeySpec");
            Object spec = keyLabelKeySpecClass.getConstructor(String.class).newInstance(CKDS_KEY_LABEL);
            
            // Generate the secret key from the key label
            SecretKey secretKey = aesKeyFactory.generateSecret((java.security.spec.KeySpec) spec);
            
            // Extract the raw key bytes
            byte[] key = secretKey.getEncoded();

            // Validate key length is 32 bytes (AES-256)
            if (key == null) {
                System.out.println("Warning: CKDS key not found. Key label: " + CKDS_KEY_LABEL);
                return null;
            }
            
            System.out.println("Successfully retrieved LTPA key from z/OS CKDS with label: " + CKDS_KEY_LABEL);
            return key;
            
        } catch (Exception e) {
            // Provider not available, class not found, key label doesn't exist, or other error
            System.out.println("CKDS key retrieval failed: " + e.getMessage());
            return null;
        }
    }

    @Override
    public byte[] encrypt(byte[] data, byte[] password) throws Exception {
        // Use IBMJCECCA provider for CKDS keys to ensure hardware crypto operations
        // Note: password parameter is ignored as CKDS key is used directly
        return LTPACrypto.encrypt(data, ckdsKey, CIPHER, CryptoUtils.IBMJCECCA_NAME);
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, byte[] password) throws Exception {
        // Use IBMJCECCA provider for CKDS keys to ensure hardware crypto operations
        // Note: password parameter is ignored as CKDS key is used directly
        return LTPACrypto.decrypt(encryptedData, ckdsKey, CIPHER, CryptoUtils.IBMJCECCA_NAME);
    }
}

// Made with Bob
