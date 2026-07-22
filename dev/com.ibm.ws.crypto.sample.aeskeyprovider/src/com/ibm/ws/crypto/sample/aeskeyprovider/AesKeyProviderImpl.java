/*******************************************************************************
 * Copyright (c) 2026 IBM Corporation and others.
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

package com.ibm.ws.crypto.sample.aeskeyprovider;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Deactivate;

import com.ibm.wsspi.security.crypto.AesKeyProvider;
import com.ibm.wsspi.security.crypto.AesKeyProviderException;

/**
 * Sample AES key provider implementation for testing and reference purposes.
 *
 * <p><strong>WARNING:</strong> This implementation uses a hard-coded key and is NOT
 * suitable for production use. In a real implementation, retrieve the key from a
 * secure source such as a key vault or hardware security module.</p>
 */
@Component(service = AesKeyProvider.class,
           immediate = true,
           name = "com.ibm.ws.crypto.sample.aeskeyprovider.AesKeyProviderImpl",
           configurationPolicy = ConfigurationPolicy.OPTIONAL,
           property = { "service.vendor=IBM" })
public class AesKeyProviderImpl implements AesKeyProvider {

    /**
     * Hard-coded 256-bit (32-byte) AES key for sample/test purposes only.
     * Do NOT use this key in production.
     */
    private static final byte[] SAMPLE_KEY_BYTES = {
        'S', 'a', 'm', 'p', 'l', 'e', 'A', 'e',
        's', 'K', 'e', 'y', 'F', 'o', 'r', 'T',
        'e', 's', 't', 'i', 'n', 'g', 'O', 'n',
        'l', 'y', '!', '!', '!', '!', '!', '!'
    };

    @Activate
    protected void activate(ComponentContext cc) {}

    @Deactivate
    protected void deactivate(ComponentContext cc) {}

    /** {@inheritDoc} */
    @Override
    public SecretKey getKey() throws AesKeyProviderException {
        System.out.println("JAKE: GETKEY IS CALLED!");
        return new SecretKeySpec(SAMPLE_KEY_BYTES, "AES");
    }
}
