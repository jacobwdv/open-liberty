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

package com.ibm.wsspi.security.crypto;

/**
 * Exception thrown when an {@link AesKeyProvider} fails to supply a key.
 *
 * @ibm-spi
 */
public class AesKeyProviderException extends Exception {
    private static final long serialVersionUID = 1L;

    /**
     * Constructs an AesKeyProviderException with the specified detail message.
     *
     * @param message the detail message.
     */
    public AesKeyProviderException(String message) {
        super(message);
    }

    /**
     * Constructs an AesKeyProviderException with the specified detail message and cause.
     *
     * @param message the detail message.
     * @param cause   the cause.
     */
    public AesKeyProviderException(String message, Throwable cause) {
        super(message, cause);
    }
}
