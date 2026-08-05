/*******************************************************************************
 * Copyright (c) 2016, 2025 IBM Corporation and others.
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
package com.ibm.ws.security.token.ltpa.internal;

import java.util.Properties;

import com.ibm.websphere.ras.annotation.Sensitive;
import com.ibm.ws.crypto.ltpakeyutil.KeyEncryptor;
import com.ibm.ws.crypto.ltpakeyutil.LTPAKeyFileUtility;
import com.ibm.wsspi.kernel.service.location.WsLocationAdmin;

/**
 * Utility class to create the LTPA keys file.
 */
public interface LTPAKeyFileCreator extends LTPAKeyFileUtility {

    /**
     * Create the LTPA keys file at the specified location using the supplied
     * {@link KeyEncryptor}.
     *
     * @param locService
     * @param keyFile
     * @param encryptor  The encryptor to use for key material
     * @return A Properties object containing the various attributes created for the LTPA keys
     * @throws Exception
     */
    public Properties createLTPAKeysFile(WsLocationAdmin locService, String keyFile, KeyEncryptor encryptor) throws Exception;

    /**
     * Re-encrypt existing LTPA key material using the supplied {@link KeyEncryptor}.
     * The pre-decrypted key bytes are passed in directly and re-encrypted under the new encryptor.
     *
     * @param locService
     * @param keyFile
     * @param encryptor       The encryptor to use for the re-encrypted key material
     * @param sharedKeyBytes  The decrypted shared key bytes
     * @param privateKeyBytes The decrypted private key bytes
     * @param publicKeyBytes  The public key bytes
     * @return A Properties object containing the re-encrypted LTPA key material
     * @throws Exception
     */
    public Properties createLTPAKeysFile(WsLocationAdmin locService, String keyFile, KeyEncryptor encryptor,
                                         @Sensitive byte[] sharedKeyBytes, @Sensitive byte[] privateKeyBytes,
                                         @Sensitive byte[] publicKeyBytes) throws Exception;

}
