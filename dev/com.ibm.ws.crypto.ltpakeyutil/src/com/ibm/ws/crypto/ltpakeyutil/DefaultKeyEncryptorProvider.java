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

import java.security.MessageDigest;

import com.ibm.ws.common.crypto.CryptoUtils;
import com.ibm.wsspi.security.crypto.KeyEncryptorProvider;

/**
 * Default implementation of KeyEncryptorProvider that uses password-based
 * key derivation with SHA MessageDigest. This is the original algorithm
 * used by KeyEncryptor before the service loader pattern was introduced.
 * 
 * This provider supports both FIPS (AES-256) and non-FIPS (3DES) modes.
 */
public class DefaultKeyEncryptorProvider implements KeyEncryptorProvider {

    private static final boolean fipsEnabled = CryptoUtils.isFips140_3Enabled();

    /**
     * Derive an encryption key from the password using SHA MessageDigest.
     * 
     * @param password The password to derive the key from
     * @return A tuple containing [derivedKey, keySize, cipher]
     */
    private Object[] deriveKey(byte[] password) throws Exception {
        int keySize = fipsEnabled ? 32 : 24; // AES-256 for FIPS, 3DES for non-FIPS
        
        MessageDigest md = MessageDigest.getInstance(CryptoUtils.MESSAGE_DIGEST_ALGORITHM);
        byte[] digest = md.digest(password);
        byte[] derivedKey = new byte[keySize];
        System.arraycopy(digest, 0, derivedKey, 0, digest.length);
        
        if (!fipsEnabled) {
            // For non-FIPS 3DES, pad the key
            derivedKey[20] = (byte) 0x00;
            derivedKey[21] = (byte) 0x00;
            derivedKey[22] = (byte) 0x00;
            derivedKey[23] = (byte) 0x00;
        }
        
        String cipher = CryptoUtils.getCipher();
        
        return new Object[] { derivedKey, keySize, cipher };
    }

    @Override
    public byte[] encrypt(byte[] data, byte[] password) throws Exception {
        Object[] keyInfo = deriveKey(password);
        byte[] key = (byte[]) keyInfo[0];
        String cipher = (String) keyInfo[2];
        
        return LTPACrypto.encrypt(data, key, cipher);
    }

    @Override
    public byte[] decrypt(byte[] encryptedData, byte[] password) throws Exception {
        Object[] keyInfo = deriveKey(password);
        byte[] key = (byte[]) keyInfo[0];
        String cipher = (String) keyInfo[2];
        
        return LTPACrypto.decrypt(encryptedData, key, cipher);
    }
}

// Made with Bob
