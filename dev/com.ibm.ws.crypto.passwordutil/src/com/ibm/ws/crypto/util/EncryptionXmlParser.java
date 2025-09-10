/*******************************************************************************
 * Copyright (c) 2025 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License 2.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-2.0/
 *
 * SPDX-License-Identifier: EPL-2.0
 *******************************************************************************/
package com.ibm.ws.crypto.util;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.ibm.websphere.crypto.PasswordUtil;
import com.ibm.ws.kernel.productinfo.ProductInfo;

/**
 * A class for parsing xml and retrieving values for wlp.aes.encryption.key and wlp.password.encryption.key
 * This is used by the command line tasks to parse xml in order to encode passwords.
 */
public class EncryptionXmlParser {
    private static final String ATTR_VALUE = "value";
    private static final String ATTR_NAME = "name";

    /**
     *
     * @param xmlFilePath the path of the XML file to be parsed.
     * @return a Map containing keysPasswordUtil.PROPERTY_AES_KEY and/or PasswordUtil.PROPERTY_CRYPTO_KEY
     *         if they are found within the parsed file.
     * @throws Exception if an exception occurs while parsing the XML file.
     */
    public static Map<String, String> parseAesEncryptionXmlFile(String xmlFilePath) throws Exception {

        String base64variableName = AESKeyManager.NAME_WLP_BASE64_AES_ENCRYPTION_KEY;
        String passKeyVariableName = AESKeyManager.NAME_WLP_PASSWORD_ENCRYPTION_KEY;
        Map<String, String> props = new HashMap<>();
        if (!ProductInfo.getBetaEdition()) {
            return props;
        }
        try {
            Map<String, String> xmlVariables = extractXmlVariables(xmlFilePath);

            String base64Key = xmlVariables.get(base64variableName);
            String passKey = xmlVariables.get(passKeyVariableName);

            if (base64Key != null) {
                props.put(PasswordUtil.PROPERTY_AES_KEY, base64Key);
            }
            if (passKey != null) {
                props.put(PasswordUtil.PROPERTY_CRYPTO_KEY, passKey);
            }
            return props;
        } catch (IOException | SAXException | ParserConfigurationException e) {
            throw e;
        }
    }

    /**
     *
     * @param xmlFilePath the xml file's path
     * @return a map containing all 'variables' defined in the file specified in xmlFilePath
     * @throws IOException
     * @throws SAXException
     * @throws ParserConfigurationException
     */
    private static Map<String, String> extractXmlVariables(String xmlFilePath) throws IOException, SAXException, ParserConfigurationException {
        Map<String, String> variables = new HashMap<>();
        try (InputStream is = Files.newInputStream(Paths.get(xmlFilePath))) {
            Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(is);
            Element element = doc.getDocumentElement();
            String TAG_VARIABLE = "variable";
            NodeList varList = element.getElementsByTagName(TAG_VARIABLE);
            for (int j = 0; j < varList.getLength(); j++) {
                Node vl = varList.item(j);
                if (vl.getNodeType() != Node.ELEMENT_NODE) {
                    continue;
                }
                Element vlElement = (Element) vl;
                String varName = vlElement.getAttribute(ATTR_NAME);
                String varVal;
                if (vlElement.getAttribute(ATTR_VALUE).isEmpty()) {
                    varVal = null;
                } else {
                    varVal = vlElement.getAttribute(ATTR_VALUE);
                }
                variables.put(varName, varVal);
            }
        }
        return variables;
    }
}
