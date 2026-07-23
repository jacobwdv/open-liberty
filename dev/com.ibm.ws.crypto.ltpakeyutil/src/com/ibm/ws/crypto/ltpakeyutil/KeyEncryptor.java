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

import java.security.MessageDigest;

import javax.crypto.SecretKey;

import com.ibm.ws.common.crypto.CryptoUtils;
import com.ibm.wsspi.security.crypto.AesKeyProvider;

/**
 * A package local class for performing encryption and decryption of keys based
 * on admin's password, or on a key supplied by an explicit {@link AesKeyProvider}.
 *
 * <p>Two construction modes are supported:
 * <ul>
 *   <li><strong>Password-derived</strong> ({@link #KeyEncryptor(byte[])}): the existing
 *       SHA-digest-based path. Cipher is chosen by {@link CryptoUtils#getCipher()} at
 *       class-load time (DES/ECB in non-FIPS mode, AES/CBC in FIPS mode).</li>
 *   <li><strong>Provider-backed</strong> ({@link #KeyEncryptor(AesKeyProvider)}): the
 *       original {@link SecretKey} from {@link AesKeyProvider#getKey()} is retained for
 *       provider-backed cipher initialization. Encoded key bytes, when available, are
 *       kept only for IV support. AES/CBC is always used for this instance, regardless
 *       of FIPS mode. Callers that encrypt with a provider-backed instance <em>must</em>
 *       also decrypt with a provider-backed instance using the same provider, because
 *       the on-disk LTPA key file format does not record which cipher was used.</li>
 * </ul>
 */
public class KeyEncryptor {

	private static final boolean fipsEnabled = CryptoUtils.isFips140_3Enabled();
	private static final int size = (fipsEnabled ? 32 : 24);
	private final String cipher;
	private final byte[] key;
	private final SecretKey providerKey;

	/**
	 * Password-derived constructor. Behavior is identical to the original implementation:
	 * the key is a SHA digest of the supplied password bytes and the cipher is chosen by
	 * {@link CryptoUtils#getCipher()}.
	 *
	 * @param password The key password
	 */
	public KeyEncryptor(byte[] password) throws Exception {
		MessageDigest md = MessageDigest.getInstance(CryptoUtils.MESSAGE_DIGEST_ALGORITHM);
		byte[] digest = md.digest(password);
		key = new byte[size];
		System.arraycopy(digest, 0, key, 0, digest.length);
		if (!fipsEnabled) {
			key[20] = (byte) 0x00;
			key[21] = (byte) 0x00;
			key[22] = (byte) 0x00;
			key[23] = (byte) 0x00;
		}
		cipher = CryptoUtils.getCipher();
		providerKey = null;
	}

	/**
	 * Provider-backed constructor. The original {@link SecretKey} supplied by the
	 * provider is retained for provider-backed cipher initialization. Encoded bytes,
	 * when available, are retained only for IV support.
	 *
	 * @param provider The {@link AesKeyProvider} that supplies the AES-256 key
	 */
	public KeyEncryptor(AesKeyProvider provider) throws Exception {
		providerKey = provider.getKey();
		key = providerKey.getEncoded();
		cipher = CryptoUtils.AES_CBC_CIPHER;
	}

	/**
	 * Decrypt the key.
	 *
	 * @param encryptedKey The encrypted key
	 * @return The decrypted key
	 */
	public byte[] decrypt(byte[] encryptedKey) throws Exception {
		if (providerKey != null) {
			return LTPACrypto.decrypt(encryptedKey, key, providerKey, cipher);
		}
		return LTPACrypto.decrypt(encryptedKey, key, cipher);
	}

	/**
	 * Encrypt the key
	 *
	 * @param key The key
	 * @return The encrypted key
	 */
	public byte[] encrypt(byte[] key) throws Exception {
		if (providerKey != null) {
			return LTPACrypto.encrypt(key, this.key, providerKey, cipher);
		}
		return LTPACrypto.encrypt(key, this.key, cipher);
	}
}
