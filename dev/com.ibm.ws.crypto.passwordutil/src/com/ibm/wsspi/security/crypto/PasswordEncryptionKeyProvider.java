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
package com.ibm.wsspi.security.crypto;

import javax.crypto.SecretKey;

/**
 * An SPI for providing the encryption key used by the Liberty AES_V2 password
 * encoding scheme. Implementations of this interface allow users to supply a
 * {@link javax.crypto.SecretKey} programmatically — for example, by retrieving
 * the key from a hardware security module (HSM), a secrets vault, or custom
 * key-derivation logic — rather than setting a static base64-encoded key via the
 * {@code wlp.aes.encryption.key} environment variable.
 *
 * <p>When a {@code PasswordEncryptionKeyProvider} OSGi service is registered
 * (typically via the BELL feature with {@code spiVisibility="true"}), Liberty
 * will call {@link #getKey(String)} to obtain the key for AES_V2 encrypt and
 * decrypt operations. The returned key takes precedence over any key configured
 * through {@code wlp.aes.encryption.key}. The key is cached after the first
 * call and is re-fetched only when the OSGi service is re-bound.
 *
 * <p>The returned {@link SecretKey} must be a 256-bit AES key
 * ({@code key.getAlgorithm()} must return {@code "AES"} and
 * {@code key.getEncoded().length} must be {@code 32}).
 *
 * <p>If more than one {@code PasswordEncryptionKeyProvider} service is
 * registered, Liberty logs a warning and uses the service with the highest
 * OSGi service ranking.
 *
 * @ibm-spi
 */
public interface PasswordEncryptionKeyProvider {

    /**
     * Returns the {@link SecretKey} to be used for AES_V2 password
     * encryption and decryption.
     *
     * <p>The {@code algorithm} parameter indicates the cipher algorithm for
     * which the key is requested. Liberty currently always passes {@code "AES"}.
     * Implementations may use this value to support future algorithms without
     * requiring an interface change.
     *
     * @param algorithm the cipher algorithm for which the key is requested;
     *                  currently always {@code "AES"}
     * @return a non-null 256-bit {@link SecretKey} for the specified algorithm
     */
    SecretKey getKey(String algorithm);

}
