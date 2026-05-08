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
package com.ibm.ws.crypto.ltpakeyutil;

import com.ibm.wsspi.security.crypto.KeyEncryptorProvider;

/**
 * A package local class for performing encryption and decryption of keys based
 * on admin's password.
 *
 * This class now uses a service loader pattern to delegate encryption/decryption
 * operations to a KeyEncryptorProvider implementation. The provider can be:
 * - DefaultKeyEncryptorProvider: Original password-based algorithm (default)
 * - CKDSKeyEncryptorProvider: z/OS CKDS with IBMJCECCA hardware crypto
 * - Custom provider: Registered by other features via OSGi Declarative Services
 */
public class KeyEncryptor {

	private final byte[] password;
	private final KeyEncryptorProvider provider;

	/**
	 * A KeyEncryptor constructor.
	 *
	 * @param password The key password
	 */
	public KeyEncryptor(byte[] password) throws Exception {
		this.password = password;
		this.provider = KeyEncryptorProviderManager.getProvider();
	}

	/**
	 * Decrypt the key.
	 *
	 * @param encryptedKey The encrypted key
	 * @return The decrypted key
	 */
	public byte[] decrypt(byte[] encryptedKey) throws Exception {
		return provider.decrypt(encryptedKey, password);
	}

	/**
	 * Encrypt the key
	 *
	 * @param key The key
	 * @return The encrypted key
	 */
	public byte[] encrypt(byte[] key) throws Exception {
		return provider.encrypt(key, password);
	}
}
