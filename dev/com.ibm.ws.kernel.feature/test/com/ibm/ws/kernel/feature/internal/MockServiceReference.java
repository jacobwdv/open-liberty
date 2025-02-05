/*******************************************************************************
 * Copyright (c) 2011,2024 IBM Corporation and others.
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
package com.ibm.ws.kernel.feature.internal;

import java.util.Dictionary;
import java.util.Hashtable;

import org.osgi.framework.Bundle;
import org.osgi.framework.ServiceReference;

public class MockServiceReference<T> implements ServiceReference<T> {
    T service;

    public MockServiceReference(T serv) {
        this.service = serv;
    }

    public <A> A adapt(Class<A> arg0) {
        return null;
    }

    public T getService() {
        return this.service;
    }

    @Override
    public Object getProperty(String key) {
        return null;
    }

    @Override
    public String[] getPropertyKeys() {
        return null;
    }

    @Override
    public Bundle getBundle() {
        return null;
    }

    @Override
    public Bundle[] getUsingBundles() {
        return null;
    }

    @Override
    public boolean isAssignableTo(Bundle bundle, String className) {
        return false;
    }

    @Override
    public int compareTo(Object reference) {
        return 0;
    }

    public Dictionary<String, Object> getProperties() {
        return new Hashtable<>();
    }
}