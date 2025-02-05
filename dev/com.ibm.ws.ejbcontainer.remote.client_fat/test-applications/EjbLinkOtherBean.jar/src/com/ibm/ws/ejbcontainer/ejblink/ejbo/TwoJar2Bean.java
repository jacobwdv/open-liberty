/*******************************************************************************
 * Copyright (c) 2006, 2020 IBM Corporation and others.
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

package com.ibm.ws.ejbcontainer.ejblink.ejbo;

import javax.ejb.Stateless;

import com.ibm.ws.ejbcontainer.ejblink.ejb.AutoLinkLocal2OtherJar;

/**
 * Basic Stateless Bean implementation for testing AutoLink to a bean interface
 * that was implemented in an alternate jar twice.
 **/
@Stateless
public class TwoJar2Bean implements AutoLinkLocal2OtherJar {
    private static final String CLASS_NAME = TwoJar2Bean.class.getName();

    /**
     * Verify injected EJB is the expected bean
     **/
    @Override
    public String getBeanName() {
        return CLASS_NAME;
    }

    public TwoJar2Bean() {
        // intentionally blank
    }
}
