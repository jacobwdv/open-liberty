/*******************************************************************************
 * Copyright (c) 2018 IBM Corporation and others.
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
package com.ibm.ws.microprofile.config13.sources;

import java.util.ArrayList;

import org.eclipse.microprofile.config.spi.ConfigSource;

import com.ibm.ws.microprofile.config.sources.DefaultSources;
import com.ibm.ws.microprofile.config.sources.SystemConfigSource;

import io.openliberty.microprofile.config.internal.serverxml.AppPropertyConfigSource;
import io.openliberty.microprofile.config.internal.serverxml.ServerXMLDefaultVariableConfigSource;
import io.openliberty.microprofile.config.internal.serverxml.ServerXMLVariableConfigSource;

public class Config13DefaultSources extends DefaultSources {

    /**
     * The classloader's loadResources method is used to locate resources of
     * name {#link ConfigConstants.CONFIG_PROPERTIES} as well as process environment
     * variables and Java System.properties
     *
     * @param classloader
     * @return the default sources found
     */
    public static ArrayList<ConfigSource> getDefaultSources(ClassLoader classloader) {
        ArrayList<ConfigSource> sources = new ArrayList<>();

        sources.add(new SystemConfigSource());
        sources.add(new EnvConfig13Source());
        sources.add(new AppPropertyConfigSource());
        sources.add(new ServerXMLVariableConfigSource());
        sources.add(new ServerXMLDefaultVariableConfigSource());

        sources.addAll(getPropertiesFileConfigSources(classloader));

        return sources;
    }
}