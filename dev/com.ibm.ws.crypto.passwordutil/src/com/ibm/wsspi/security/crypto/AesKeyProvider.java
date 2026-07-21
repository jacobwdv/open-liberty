/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
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
 * SPI that allows users to supply a programmatic AES-256 key for Liberty password encoding and decoding.
 *
 * <p>When an implementation of this interface is registered as an OSGi service (or deployed via the
 * {@code ws-aesKeyProvider} extension directory for {@code securityUtility} CLI use), Liberty uses the
 * returned key as the encryption key for the AES_V2 code path. Passwords encrypted this way are stored
 * with the tag {@code {aes:<className>}}, where {@code <className>} is the fully-qualified name of the
 * implementing class. This tag is informational only; it is used solely to produce a helpful error
 * message if the provider is absent at decryption time.</p>
 *
 * <p><strong>Key requirements:</strong></p>
 * <ul>
 *   <li>The returned {@link SecretKey} must use the {@code "AES"} algorithm.</li>
 *   <li>The key must be exactly 256 bits (32 bytes).</li>
 * </ul>
 *
 * <p><strong>Precedence:</strong> When registered, this provider takes precedence over the
 * {@code wlp.aes.encryption.key} server variable. The {@code --passwordBase64Key} CLI argument
 * still takes precedence over this provider.</p>
 *
 * <p><strong>Performance note:</strong> {@code getKey()} may be called on every encrypt and decrypt
 * operation. Implementations that retrieve the key from an external source (such as a key vault)
 * should cache the key internally to avoid repeated expensive lookups.</p>
 *
 * @ibm-spi
 */
public interface AesKeyProvider {

    /**
     * Returns the AES-256 {@link SecretKey} to be used for password encryption and decryption.
     *
     * @return a 256-bit AES {@link SecretKey}; must not be {@code null}.
     * @throws AesKeyProviderException if the key cannot be retrieved.
     */
    SecretKey getKey() throws AesKeyProviderException;
}
