/*******************************************************************************
 * Copyright (c) 2012, 2024 IBM Corporation and others.
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
package com.ibm.ws.security.auth.data.internal;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.ConfigurationPolicy;

import com.ibm.websphere.crypto.PasswordUtil;
import com.ibm.websphere.ras.annotation.Sensitive;
import com.ibm.websphere.security.auth.data.AuthData;
import com.ibm.wsspi.kernel.service.utils.SerializableProtectedString;

import io.openliberty.checkpoint.spi.CheckpointPhase;

/**
 * The auth data from server.xml.
 */
@Component(service = com.ibm.websphere.security.auth.data.AuthData.class, configurationPid = "com.ibm.ws.security.jca.internal.authdata.config", configurationPolicy = ConfigurationPolicy.REQUIRE, immediate = true, property = { "service.vendor=IBM" })
public class AuthDataImpl implements AuthData {

    protected static final String CFG_KEY_ID = "id";
    protected static final String CFG_KEY_DISPLAY_ID = "config.displayId";
    protected static final String CFG_KEY_USER = "user";
    protected static final String CFG_KEY_PASSWORD = "password";

    private String username;
    private String password;
    private String principal;
    private Path krb5TicketCache;

    @Activate
    protected void activate(@Sensitive Map<String, Object> props) {
        username = (String) props.get(CFG_KEY_USER);
        SerializableProtectedString sps = (SerializableProtectedString) props.get(CFG_KEY_PASSWORD);
        String configuredPassword = sps == null ? "" : new String(sps.getChars());

        // Cipher algorithims may be unavailable at server checkpoint
        password = configuredPassword;
        CheckpointPhase.onRestore(() -> {
            password = PasswordUtil.passwordDecode(configuredPassword);
        });

        principal = (String) props.get("krb5Principal");
        String sCcache = (String) props.get("krb5TicketCache");
        if (sCcache != null) {
            krb5TicketCache = Paths.get(sCcache);
        } else {
            krb5TicketCache = null;
        }
    }

    /**
     * Gets the user name as defined in the configuration.
     *
     * @return the user name.
     */
    @Override
    public String getUserName() {
        return username;
    }

    /**
     * Gets the password as a char[] as defined in the configuration.
     *
     * @return the char[] representation of the password.
     */
    @Override
    @Sensitive
    public char[] getPassword() {
        return password.toCharArray();
    }

    /** {@inheritDoc} */
    @Override
    public String getKrb5Principal() {
        return principal;
    }

    /** {@inheritDoc} */
    @Override
    public Path getKrb5TicketCache() {
        return krb5TicketCache;
    }

}
