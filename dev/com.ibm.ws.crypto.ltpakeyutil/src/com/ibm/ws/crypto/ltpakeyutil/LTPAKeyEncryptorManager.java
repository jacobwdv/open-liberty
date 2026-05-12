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
package com.ibm.ws.crypto.ltpakeyutil;

import java.util.concurrent.atomic.AtomicReference;

import com.ibm.websphere.ras.annotation.Sensitive;
import com.ibm.wsspi.security.crypto.KeyEncryptor;
import com.ibm.wsspi.security.crypto.KeyEncryptorFactory;

/**
 * Manager class for KeyEncryptor implementations.
 * Follows the same pattern as AESKeyManager for dynamic service resolution.
 */
public class LTPAKeyEncryptorManager {

    private static final AtomicReference<KeyEncryptorFactory> encryptorProvider = new AtomicReference<KeyEncryptorFactory>();

    static {
        setKeyEncryptorProvider(null);
    }

    /**
     * Get a KeyEncryptor instance for the given password.
     * 
     * @param password The key password
     * @return A KeyEncryptor instance
     * @throws Exception if the encryptor cannot be created
     */
    public static KeyEncryptor getKeyEncryptor(@Sensitive byte[] password) throws Exception {
        KeyEncryptorFactory factory = encryptorProvider.get();
        return factory.createKeyEncryptor(password);
    }

    /**
     * Set the KeyEncryptor provider. If null, a default factory is used.
     * 
     * @param provider The KeyEncryptor provider to use
     */
    public static void setKeyEncryptorProvider(KeyEncryptorFactory provider) {
        if (provider == null) {
            // Default factory that creates DefaultKeyEncryptor instances
            provider = new KeyEncryptorFactory() {
                @Override
                public KeyEncryptor createKeyEncryptor(@Sensitive byte[] password) throws Exception {
                    return new DefaultKeyEncryptor(password);
                }
            };
        }
        encryptorProvider.set(provider);
    }

}
