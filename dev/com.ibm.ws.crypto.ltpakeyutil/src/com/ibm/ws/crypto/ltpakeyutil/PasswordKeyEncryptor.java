/*******************************************************************************
 * Copyright (c) 1997, 2025 IBM Corporation and others.
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

/**
 * Password-based {@link KeyEncryptor} implementation.
 * The supplied password bytes are digested to produce the symmetric key material
 * used for encrypt/decrypt via the standard Liberty cipher (DES/ECB in non-FIPS,
 * AES/CBC in FIPS mode).
 */
public class PasswordKeyEncryptor implements KeyEncryptor {

    private static final boolean FIPS_ENABLED = CryptoUtils.isFips140_3Enabled();
    private static final int size = (FIPS_ENABLED ? 32 : 24);
    private static final String CIPHER = CryptoUtils.getCipher();
    private static final String LTPA_VERSION = FIPS_ENABLED ? "2.0" : "1.0";

    private final byte[] key;

    /**
     * Constructs a {@link PasswordKeyEncryptor} from raw password bytes.
     * The bytes are digested with {@link CryptoUtils#MESSAGE_DIGEST_ALGORITHM} to derive
     * the symmetric key material.
     *
     * @param password The admin password bytes
     */
    public PasswordKeyEncryptor(byte[] password) throws Exception {
        MessageDigest md = MessageDigest.getInstance(CryptoUtils.MESSAGE_DIGEST_ALGORITHM);
        byte[] digest = md.digest(password);
        key = new byte[size];
        System.arraycopy(digest, 0, key, 0, digest.length);
        if (!FIPS_ENABLED) {
            key[20] = (byte) 0x00;
            key[21] = (byte) 0x00;
            key[22] = (byte) 0x00;
            key[23] = (byte) 0x00;
        }
    }

    /** {@inheritDoc} */
    @Override
    public byte[] encrypt(byte[] data) throws Exception {
        return LTPACrypto.encrypt(data, key, CIPHER);
    }

    /** {@inheritDoc} */
    @Override
    public byte[] decrypt(byte[] encryptedData) throws Exception {
        return LTPACrypto.decrypt(encryptedData, key, CIPHER);
    }

    /** {@inheritDoc} */
    @Override
    public String getLtpaVersion() {
        return LTPA_VERSION;
    }

    /** {@inheritDoc} */
    @Override
    public boolean supportsLegacyFallback() {
        return true;
    }
}
