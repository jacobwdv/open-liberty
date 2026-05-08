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
package com.ibm.ws.crypto.ltpakeyutil;

import java.util.concurrent.atomic.AtomicReference;

import com.ibm.wsspi.security.crypto.KeyEncryptorProvider;

/**
 * Manager for KeyEncryptorProvider instances. This class maintains a registry
 * of the active provider and allows features to override the default implementation.
 * Similar to how AESKeyManager manages KeyStringResolver instances.
 * 
 * By default, uses DefaultKeyEncryptorProvider. Other features can register
 * alternative providers (e.g., CKDSKeyEncryptorProvider for z/OS hardware crypto).
 */
public class KeyEncryptorProviderManager {

    private static final AtomicReference<KeyEncryptorProvider> _provider = new AtomicReference<KeyEncryptorProvider>();

    static {
        // Initialize with the default provider
        setProvider(new DefaultKeyEncryptorProvider());
    }

    /**
     * Set the active KeyEncryptorProvider. If null is provided, resets to
     * the default provider.
     *
     * @param provider The provider to use, or null to reset to default
     */
    public static void setProvider(KeyEncryptorProvider provider) {
        if (provider == null) {
            provider = new DefaultKeyEncryptorProvider();
        }
        _provider.set(provider);
    }

    /**
     * Get the currently active KeyEncryptorProvider.
     *
     * @return The active provider (never null)
     */
    public static KeyEncryptorProvider getProvider() {
        return _provider.get();
    }
}

// Made with Bob
