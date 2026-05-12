/*******************************************************************************
 * Copyright (c) 1997, 2024 IBM Corporation and others.
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

/**
 * The interface for performing encryption and decryption of keys.
 *
 * @ibm-spi
 *
 */
public interface KeyEncryptor {

    /**
     * Decrypt the key.
     *
     * @param encryptedKey The encrypted key
     * @return The decrypted key
     */
    public byte[] decrypt(byte[] encryptedKey) throws Exception;

    /**
     * Encrypt the key
     *
     * @param key The key
     * @return The encrypted key
     */
    public byte[] encrypt(byte[] key) throws Exception;

}


