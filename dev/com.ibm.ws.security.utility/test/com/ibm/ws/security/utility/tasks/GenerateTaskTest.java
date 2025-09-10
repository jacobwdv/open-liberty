/*******************************************************************************
 * Copyright (c) 2025 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package com.ibm.ws.security.utility.tasks;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.File;
import java.io.PrintStream;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import com.ibm.ws.crypto.util.AESKeyManager;
import com.ibm.ws.security.utility.IFileUtility;
import com.ibm.ws.security.utility.tasks.GenerateTask.PasswordEncryptionConfigXMLBuilder;
import com.ibm.ws.security.utility.utils.ConsoleWrapper;

/**
 *
 */
public class GenerateTaskTest {

    private final ConsoleWrapper stdin = mock(ConsoleWrapper.class, "stdin");
    private final PrintStream stdout = mock(PrintStream.class, "stdout");
    private final PrintStream stderr = mock(PrintStream.class, "stderr");
    final IFileUtility fileUtil = mock(IFileUtility.class);
    private GenerateTask generate;

    @Before
    public void setUp() {
        generate = new GenerateTask(fileUtil, "myScript");
    }

    @After
    public void tearDown() {
        reset(fileUtil);
    }

    @Test
    public void testNoKeySpecified() throws Exception {

        try (MockedStatic<PasswordEncryptionConfigXMLBuilder> xmlBuilder = Mockito.mockStatic(PasswordEncryptionConfigXMLBuilder.class, Mockito.CALLS_REAL_METHODS)) {
            String outfile = "/path/keys.xml";
            generate.handleTask(stdin, stdout, stderr, new String[] { "--file=" + outfile });
            xmlBuilder.verify(() -> PasswordEncryptionConfigXMLBuilder.generateRandomAes256Key(), times(1));
            xmlBuilder.verifyNoMoreInteractions();
            verify(fileUtil, times(1)).writeToFile(any(), anyString(), any());

        }
    }

    @Test
    public void testKeySpecified() throws Exception {

        String pass = "passw0rd";
        String passKey = "lcJWjIt38ZjBBvYfNWLEgp/I0DQFTbFmA5zFl6zCU30=";
        String outFile = "/path/keys.xml";
        StringBuilder xml = new StringBuilder();
        xml.append("<server>\n");
        xml.append("    <variable name=\"").append(AESKeyManager.NAME_WLP_BASE64_AES_ENCRYPTION_KEY).append("\" value=\"").append(passKey).append("\" />\n");
        xml.append("</server>");
        try (MockedStatic<PasswordEncryptionConfigXMLBuilder> xmlBuilder = Mockito.mockStatic(PasswordEncryptionConfigXMLBuilder.class, Mockito.CALLS_REAL_METHODS)) {
            generate.handleTask(stdin, stdout, stderr, new String[] { "--key=" + pass, "--file=/path/keys.xml" });
            xmlBuilder.verify(() -> PasswordEncryptionConfigXMLBuilder.generateAes256KeyWithPBKDF2(pass), times(1));
            xmlBuilder.verifyNoMoreInteractions();
            verify(fileUtil, times(1)).writeToFile(stderr, xml.toString(), new File(outFile));
        }
    }

}
