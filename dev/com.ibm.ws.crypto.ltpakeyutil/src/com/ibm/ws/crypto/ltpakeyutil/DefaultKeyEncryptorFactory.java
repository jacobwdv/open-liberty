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

import com.ibm.websphere.ras.annotation.Sensitive;
import com.ibm.wsspi.security.crypto.KeyEncryptor;
import com.ibm.wsspi.security.crypto.KeyEncryptorFactory;

/**
 * Default factory for creating KeyEncryptor implementations.
 * This class is registered as an OSGi service and provides the default
 * DefaultKeyEncryptor implementation to the LTPAKeyEncryptorManager.
 */
public class DefaultKeyEncryptorFactory implements KeyEncryptorFactory {

    /**
     * Called by OSGi when this service is activated.
     */
    public void activate() {
        LTPAKeyEncryptorManager.setKeyEncryptorProvider(this);
    }

    /**
     * Called by OSGi when this service is deactivated.
     */
    public void deactivate() {
        LTPAKeyEncryptorManager.setKeyEncryptorProvider(null);
    }

    @Override
    public KeyEncryptor createKeyEncryptor(@Sensitive byte[] password) throws Exception {
        return new DefaultKeyEncryptor(password);
    }
}
