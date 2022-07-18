/*******************************************************************************
 * Copyright (c) 2022 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package mpapp1;

import static org.junit.Assert.assertEquals;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.context.Initialized;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.eclipse.microprofile.config.Config;

@ApplicationScoped
public class ApplicationScopedOnCheckpointBeanWithConfigObject {

    public void observeInit(@Observes @Initialized(ApplicationScoped.class) Object event) {
        System.out.println(getClass() + ": " + "Initializing application context");
    }

    @Inject
    Config config;

    public void appScopeDefaultValueTest() {
        check("defaultValue");
    }

    public void appScopeEnvValueTest() {
        check("envValue");
    }

    public void appScopeEnvValueChangeTest() {
        check("envValueChange");
    }

    public void appScopeServerValueTest() {
        check("serverValue");
    }

    public void appScopeAnnoValueTest() {
        check("annoValue");
    }

    private void check(String expected) {
        String actual = config.getOptionalValue("test_key", String.class).orElse("annoValue");
        assertEquals("Wrong value for test key.", expected, actual);
    }
}
