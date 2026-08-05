/*******************************************************************************
 * Copyright (c) 1997, 2026 IBM Corporation and others.
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

/**
 * Abstraction for encrypting and decrypting LTPA key material.
 *
 * <p>The standard implementation is {@link PasswordKeyEncryptor}, which derives a symmetric key
 * from an admin password via message-digest. Platform-specific implementations (e.g. for
 * hardware-backed keys on z/OS) may be registered as OSGi services via {@link KeyEncryptorFactory}
 * and must honour the contract that {@link java.security.Key#getEncoded()} is never called on
 * any opaque hardware key.
 */
public interface KeyEncryptor {

    /**
     * Encrypts the given plaintext key material.
     *
     * @param data The plaintext bytes to encrypt
     * @return The encrypted bytes
     * @throws Exception if encryption fails
     */
    byte[] encrypt(byte[] data) throws Exception;

    /**
     * Decrypts the given ciphertext key material.
     *
     * @param encryptedData The ciphertext bytes to decrypt
     * @return The decrypted plaintext bytes
     * @throws Exception if decryption fails
     */
    byte[] decrypt(byte[] encryptedData) throws Exception;

    /**
     * Returns the LTPA key file version string this encryptor produces.
     * Password-based encryptors return {@code "1.0"} normally or {@code "2.0"} when FIPS
     * 140-3 is enabled. Hardware-backed encryptors always return {@code "2.0"}.
     */
    String getLtpaVersion();

    /**
     * Returns {@code true} if this encryptor supports falling back to the legacy
     * {@code "WebAS"} default password when a {@code BadPaddingException} is encountered
     * during key load. Hardware-backed encryptors return {@code false}.
     */
    boolean supportsLegacyFallback();
}
