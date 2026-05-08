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

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;
import org.osgi.service.component.annotations.Deactivate;

import com.ibm.websphere.ras.Tr;
import com.ibm.websphere.ras.TraceComponent;

/**
 * OSGi Declarative Services component that registers the CKDSKeyEncryptorProvider
 * with the KeyEncryptorProviderManager when activated.
 * 
 * This component should only be activated on z/OS systems with CKDS support.
 * It will be part of a separate feature that can be enabled when hardware crypto is desired.
 */
@Component(configurationPolicy = ConfigurationPolicy.IGNORE,
           immediate = true,
           service = {})
public class CKDSKeyEncryptorProviderComponent {

    private static final TraceComponent tc = Tr.register(CKDSKeyEncryptorProviderComponent.class);

    private CKDSKeyEncryptorProvider provider;

    @Activate
    protected void activate() {
        try {
            provider = new CKDSKeyEncryptorProvider();
            KeyEncryptorProviderManager.setProvider(provider);
            if (tc.isInfoEnabled()) {
                Tr.info(tc, "CKDS KeyEncryptorProvider activated successfully");
            }
        } catch (Exception e) {
            // If CKDS provider fails to initialize, log error but don't fail activation
            // The default provider will continue to be used
            if (tc.isWarningEnabled()) {
                Tr.warning(tc, "Failed to activate CKDS KeyEncryptorProvider, using default provider: " + e.getMessage());
            }
        }
    }

    @Deactivate
    protected void deactivate() {
        // Reset to default provider when this component is deactivated
        KeyEncryptorProviderManager.setProvider(null);
        provider = null;
        if (tc.isInfoEnabled()) {
            Tr.info(tc, "CKDS KeyEncryptorProvider deactivated, reverted to default provider");
        }
    }
}

// Made with Bob
