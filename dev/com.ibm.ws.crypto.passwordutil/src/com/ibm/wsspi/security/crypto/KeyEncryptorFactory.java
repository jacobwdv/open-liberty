/*******************************************************************************
 * Copyright (c) 2024 IBM Corporation and others.
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
 * Factory interface for creating KeyEncryptor instances.
 * Providers should implement this to create encryptors with passwords.
 *
 * @ibm-spi
 */
public interface KeyEncryptorFactory {
    /**
     * Create a KeyEncryptor instance for the given password.
     *
     * @param password The key password
     * @return A KeyEncryptor instance
     * @throws Exception if the encryptor cannot be created
     */
    KeyEncryptor createKeyEncryptor(byte[] password) throws Exception;
}


