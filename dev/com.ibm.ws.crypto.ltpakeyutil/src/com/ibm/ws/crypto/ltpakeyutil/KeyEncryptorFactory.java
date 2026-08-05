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

/**
 * OSGi service interface that creates a {@link KeyEncryptor} backed by a hardware key
 * (e.g. an ICSF/CKDS key on z/OS) for use in encrypting and decrypting the LTPA keys file.
 *
 * <p>When a component registers this service (for example, the {@code zosPasswordEncryptionKey}
 * configuration element with {@code encryptLtpa="true"} and {@code type="CKDS"}),
 * {@code LTPAConfigurationImpl} will pick it up via an optional DS reference and route all
 * LTPA key file encrypt/decrypt operations through the produced {@link KeyEncryptor} instead
 * of deriving a key from {@code keysPassword}.
 *
 * <p><b>Contract:</b>
 * <ul>
 *   <li>Implementations must return a {@link KeyEncryptor} whose underlying hardware key
 *       material never leaves the hardware security module.</li>
 *   <li>Each call to {@link #createKeyEncryptor()} may return a new {@link KeyEncryptor}
 *       instance, but all instances must represent the same underlying hardware key for the
 *       lifetime of the service registration.</li>
 * </ul>
 */
public interface KeyEncryptorFactory {

    /**
     * Creates and returns a {@link KeyEncryptor} backed by a hardware key.
     *
     * @return a new {@link KeyEncryptor}; never {@code null}
     * @throws Exception if the hardware key cannot be retrieved or the encryptor cannot be created
     */
    KeyEncryptor createKeyEncryptor() throws Exception;
}
