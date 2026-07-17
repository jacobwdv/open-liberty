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
package com.ibm.ws.crypto.util.custom;

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.ibm.wsspi.security.crypto.PasswordEncryptionKeyProvider;

/**
 * A minimal {@link PasswordEncryptionKeyProvider} used in unit tests.
 * Returns a freshly generated 256-bit AES key on every call.
 */
public class SimpleKeyProvider implements PasswordEncryptionKeyProvider {

    @Override
    public SecretKey getKey(String algorithm) {
        try {
            KeyGenerator kg = KeyGenerator.getInstance(algorithm);
            kg.init(256);
            return kg.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Could not generate test key", e);
        }
    }

}
