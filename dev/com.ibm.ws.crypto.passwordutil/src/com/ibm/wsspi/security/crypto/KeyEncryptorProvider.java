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

/**
 * The interface for providing key encryption/decryption implementations.
 * This allows different features to provide alternative encryption algorithms
 * for LTPA keys, such as hardware-based encryption on z/OS.
 *
 * @ibm-spi
 */
public interface KeyEncryptorProvider {

    /**
     * Encrypt the key using this provider's algorithm.
     *
     * @param data The key data to encrypt
     * @param password The password used for encryption
     * @return The encrypted key
     * @throws Exception if encryption fails
     */
    byte[] encrypt(byte[] data, byte[] password) throws Exception;

    /**
     * Decrypt the key using this provider's algorithm.
     *
     * @param encryptedData The encrypted key data
     * @param password The password used for decryption
     * @return The decrypted key
     * @throws Exception if decryption fails
     */
    byte[] decrypt(byte[] encryptedData, byte[] password) throws Exception;
}

// Made with Bob
