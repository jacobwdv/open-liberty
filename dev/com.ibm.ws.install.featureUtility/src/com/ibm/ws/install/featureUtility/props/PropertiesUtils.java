/*******************************************************************************
 * Copyright (c) 2020, 2023 IBM Corporation and others.
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
package com.ibm.ws.install.featureUtility.props;

import com.ibm.ws.install.InstallConstants;
import com.ibm.ws.install.InstallConstants.VerifyOption;
import com.ibm.ws.install.InstallException;
import com.ibm.ws.install.RepositoryConfigValidationResult;
import com.ibm.ws.install.internal.InstallLogUtils;
import com.ibm.ws.install.internal.InstallUtils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PropertiesUtils {
//    private static final Logger logger = Logger.getLogger(InstallConstants.LOGGER_NAME);
    private static Locale locale;
    private static ResourceBundle featureUtilityMessages;
    private static ResourceBundle featureUtilitySampleConfigurations;
    public final static String WLP_REPO = "default";
    public final static String USE_WLP_REPO = "useDefaultRepository";
    public final static String URL_SUFFIX = ".url";
    public final static String USER_SUFFIX = ".user";
    public final static String PWD_SUFFIX = ".password";
    public final static String COMMENT_PREFIX = "#";
    public final static String PROXY_HOST = "proxyHost";
    public final static String PROXY_PORT = "proxyPort";
    public final static String PROXY_USER = "proxyUser";
    public final static String PROXY_PASSWORD = "proxyPassword";
    public final static String FEATURE_LOCAL_REPO = "featureLocalRepo";
    public final static String FEATURES_BOM = ".featuresbom";
    public final static String FEATURE_VERIFY = "feature.verify";
    public final static String EQUALS = "=";
    private static final String UBUNTU_HOST = "keyserver.ubuntu.com";
    private static final String PGP_HOST = "keys.openpgp.org";
    private static final String MIT_HOST = "pgp.mit.edu";
    private final static String[] SUPPORTED_KEYS = { USE_WLP_REPO, PROXY_HOST, PROXY_PORT, PROXY_USER, PROXY_PASSWORD,
	    FEATURE_LOCAL_REPO, FEATURE_VERIFY };
    private final static String[] SUPPORTED_KEYSERVERS = { UBUNTU_HOST, PGP_HOST, MIT_HOST };
    private static final Logger logger = Logger.getLogger(InstallConstants.LOGGER_NAME);



    public class CmdlineConstants {
        public static final String DASHES = "----------------------------------------------------------------------";
        public static final String HIDDEN_PASSWORD = "********";
    }

    public static synchronized String getMessage(String key, Object... args) {
        if (featureUtilityMessages == null) {
            if (locale == null)
                locale = Locale.getDefault();
            featureUtilityMessages = ResourceBundle.getBundle("com.ibm.ws.install.featureUtility.internal.resources.FeatureUtilityMessages", locale);
        }
        String message = featureUtilityMessages.getString(key);
        if (args.length == 0)
            return message;
        MessageFormat messageFormat = new MessageFormat(message, locale);
        return messageFormat.format(args);
    }

    /**
     *
     * @return formated message for SAMPLE_CONFIGURATION key
     */
    public static synchronized String getSampleConfig() {
        if (featureUtilitySampleConfigurations == null) {
            if (locale == null)
                locale = Locale.getDefault();
            featureUtilitySampleConfigurations = ResourceBundle.getBundle("com.ibm.ws.install.featureUtility.internal.resources.FeatureUtilitySampleConfiguration", locale);
        }
        String message = featureUtilitySampleConfigurations.getString("SAMPLE_CONFIG");

        return message;
    }

    public static boolean isFileProtocol(String urlStr) {
        try {
            URL url = new URL(urlStr);
            if (url.getProtocol().equalsIgnoreCase("file")) {
                return true;
            }
            return false;
        } catch (MalformedURLException e) {
            return false;
        }

    }

    /**
     * Checks that properties in the repository preoperty file are valid.
     *
     * @param repoProperties the Repository Properties
     * @return A list of RepositoryConfigValidationResults
     * @throws InstallException
     */
    public static List<RepositoryConfigValidationResult> validateRepositoryPropertiesFile(Properties repoProperties) throws InstallException {

        List<RepositoryConfigValidationResult> validationResults = new ArrayList<RepositoryConfigValidationResult>();
        // Retrieves the Repository Properties file
        File repoPropertiesFile = FeatureUtilityProperties.getRepoPropertiesFile();
        Map<String, String> configMap = new HashMap<String, String>();
        Map<String, Integer> lineMap = new HashMap<String, Integer>();

        if (repoPropertiesFile.exists() && repoPropertiesFile.isFile()) {
            logger.log(Level.FINE, InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("LOG_VALIDATING", repoPropertiesFile.getPath()));
            //Load repository properties
            FileInputStream repoPropertiesInput = null;
            BufferedReader repoPropertiesReader = null;
            try {
                repoPropertiesInput = new FileInputStream(repoPropertiesFile);
                repoPropertiesReader = new BufferedReader(new InputStreamReader(repoPropertiesInput));
                String line;
                int lineNum = 0;
                //Validate configurations in the repositories.properties file
                while ((line = repoPropertiesReader.readLine()) != null) {
                    lineNum++;
                    validateRepositoryPropertiesLine(repoProperties, line, lineNum, configMap, lineMap, validationResults);
                }
                //Missing Host
                if (configMap.containsKey(PROXY_HOST)) {
                    int ln = lineMap.get(PROXY_HOST);
                    if (!configMap.containsKey(PROXY_PORT)) {
                        validationResults.add(new RepositoryConfigValidationResult(ln, RepositoryConfigValidationResult.ValidationFailedReason.MISSING_PORT, InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("MSG_VALIDATION_MISSING_PORT_VALUE",
                                configMap.get(PROXY_HOST))));
                    } else {
                        /**
                         * verify proxy host url along with the port number
                         */
                        String proxyHost = repoProperties.getProperty(InstallConstants.REPO_PROPERTIES_PROXY_HOST);
                        String proxyPort = repoProperties.getProperty(InstallConstants.REPO_PROPERTIES_PROXY_PORT);
                        try {
                            //Trim any trailing whitespaces
                            proxyHost = proxyHost.trim();
                            proxyPort = proxyPort.trim();
                            URL proxyUrl = null;
                            if (proxyHost.toLowerCase().contains("://")) {
                                proxyUrl = new URL(proxyHost + ":" + proxyPort);
                                if (!proxyUrl.getProtocol().toLowerCase().equals("http"))
                                    validationResults.add(new RepositoryConfigValidationResult(ln, RepositoryConfigValidationResult.ValidationFailedReason.INVALID_HOST, InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("MSG_VALIDATION_INVALID_HOST",
                                            configMap.get(PROXY_HOST))));
                            } else {
                                new URL("http://" + proxyHost + ":" + proxyPort);
                            }

                        } catch (MalformedURLException e) {
                            validationResults.add(new RepositoryConfigValidationResult(ln, RepositoryConfigValidationResult.ValidationFailedReason.INVALID_HOST, InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("MSG_VALIDATION_INVALID_HOST",
                                    configMap.get(PROXY_HOST))));
                        }
                    }
                } else if (configMap.containsKey(PROXY_PORT) || configMap.containsKey(PROXY_USER) || configMap.containsKey(PROXY_PASSWORD)) {
                    int ln = 0;
                    if (lineMap.containsKey(PROXY_PORT))
                        ln = lineMap.get(PROXY_PORT);
                    else if (lineMap.containsKey(PROXY_USER))
                        ln = lineMap.get(PROXY_USER);
                    else
                        ln = lineMap.get(PROXY_PASSWORD);
                    validationResults.add(new RepositoryConfigValidationResult(ln, RepositoryConfigValidationResult.ValidationFailedReason.MISSING_HOST, InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("MSG_VALIDATION_MISSING_HOST")));
		}
		/*
		 * Check if key ID exists for the keyserver
		 */
		if (!FeatureUtilityProperties.getKeyMap().isEmpty()) {
		    for (String keyName : FeatureUtilityProperties.getKeyMap().keySet()) {
			if (FeatureUtilityProperties.getKeyMap().get(keyName).get(InstallConstants.KEYID_QUALIFIER) == null) {
			    int ln = lineMap.get(keyName + "." + InstallConstants.KEYSERVER_QUALIFIER);
			    validationResults.add(new RepositoryConfigValidationResult(ln,
				    RepositoryConfigValidationResult.ValidationFailedReason.MISSING_KEYID,
				    InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES
					    .getLogMessage("MSG_VALIDATION_MISSING_KEYID")));
			}
		    }
                }
            } catch (IOException e) {
                throw new InstallException(InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("ERROR_TOOL_REPOSITORY_PROPS_NOT_LOADED",
                        repoPropertiesFile.getPath()), InstallException.IO_FAILURE);
            } finally {
                InstallUtils.close(repoPropertiesInput);
                InstallUtils.close(repoPropertiesReader);
            }
            logger.log(Level.FINE, InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("LOG_VALIDATION_DONE"));
        }

        return validationResults;

    }



    /**
     * Checks if the inputed key is a supported property key
     *
     * @param key The Property key
     * @return True if the key is supported
     */
    private static boolean isKeySupported(String key) {
        if (Arrays.asList(SUPPORTED_KEYS).contains(key))
            return true;
        if (key.endsWith(URL_SUFFIX)  ||
		key.endsWith(USER_SUFFIX) || key.endsWith(PWD_SUFFIX) || key.endsWith(FEATURES_BOM)
		|| key.endsWith(InstallConstants.KEYID_QUALIFIER) || key.endsWith(InstallConstants.KEYSERVER_QUALIFIER))
            return true;
        return false;
    }

    private static void validateRepositoryPropertiesLine(Properties repoProperties, String line, int lineNum, Map<String, String> configMap, Map<String, Integer> lineMap,
                                                         List<RepositoryConfigValidationResult> validationResults) {

        line = line.trim();
        //skip comment
        if (!line.isEmpty() && !line.startsWith(COMMENT_PREFIX)) {
            String keyValue[] = line.split(EQUALS);
            String key = null;
            String value = null;

            if (keyValue.length >= 2) {
                key = keyValue[0];
                value = keyValue[1];
            } else if (keyValue.length == 1) {
                key = keyValue[0];
            }

            //empty key check
            if (key == null || key.isEmpty()) {
                validationResults.add(new RepositoryConfigValidationResult(lineNum, RepositoryConfigValidationResult.ValidationFailedReason.EMPTY_KEY, InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("MSG_VALIDATION_EMPTY_KEY")));
                return;
            }

            if (!isKeySupported(key)) {
 	                validationResults.add(new RepositoryConfigValidationResult(lineNum, RepositoryConfigValidationResult.ValidationFailedReason.INVALID_KEY, InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("MSG_VALIDATION_INVALID_KEY",
 	                        key)));
                 return;
             }

            /**
             * emptyRepoName
             */
            if (key.endsWith(URL_SUFFIX) || key.endsWith(PWD_SUFFIX) || key.endsWith(USER_SUFFIX)) {
                int suffixIndex = key.lastIndexOf(".");
                String suffix = key.substring(suffixIndex);
                String repoName = keyValue[0].substring(0, keyValue[0].length() - suffix.length()).trim();
                //Check for empty repository names
                if (repoName.isEmpty()) {
                    validationResults.add(new RepositoryConfigValidationResult(lineNum, RepositoryConfigValidationResult.ValidationFailedReason.MISSING_REPONAME, InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("MSG_VALIDATION_EMPTY_REPONAME")));
                    return;
                }
            }

	    /**
	     * emptyKeyName
	     */
	    if (key.endsWith(URL_SUFFIX) || key.endsWith(PWD_SUFFIX) || key.endsWith(USER_SUFFIX)) {
		int suffixIndex = key.lastIndexOf(".");
		String suffix = key.substring(suffixIndex);
		String keyName = keyValue[0].substring(0, keyValue[0].length() - suffix.length()).trim();
		// Check for empty key names
		if (keyName.isEmpty()) {
		    validationResults.add(new RepositoryConfigValidationResult(lineNum,
			    RepositoryConfigValidationResult.ValidationFailedReason.MISSING_PUBKEY_NAME,
			    InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES
				    .getLogMessage("MSG_VALIDATION_EMPTY_PUBKEY_NAME")));
		    return;
		}
	    }

            /**
             * duplicate keys
             */
            if (configMap.containsKey(key)) {
                validationResults.add(new RepositoryConfigValidationResult(lineNum, RepositoryConfigValidationResult.ValidationFailedReason.DUPLICATE_KEY, InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("MSG_VALIDATION_DUPLICATE_KEY",
                        key,
                        lineMap.get(key))));
                return;
            } else {
                configMap.put(key, value);
                lineMap.put(key, lineNum);
            }

            //empty value check
            if (value == null || value.isEmpty()) {
                validationResults.add(new RepositoryConfigValidationResult(lineNum, RepositoryConfigValidationResult.ValidationFailedReason.EMPTY_VALUE, InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("MSG_VALIDATION_EMPTY_VALUE",
                        key)));
                return;
            }

            /**
             * value is invalid useDefaultRepository
             */
            if (key.equals(USE_WLP_REPO)) {
                if (!(value.toLowerCase().equals("true") || value.toLowerCase().equals("false"))) {
                    validationResults.add(new RepositoryConfigValidationResult(lineNum, RepositoryConfigValidationResult.ValidationFailedReason.INVALID_VALUE, InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("MSG_VALIDATION_INVALID_DEFAULTREPO_VALUE",
                            value)));
                    return;
                }
            }

	    if (key.endsWith(URL_SUFFIX) || key.endsWith(InstallConstants.KEYSERVER_QUALIFIER)) {
                /**
                 * invalid url
                 *
                 */
                String url = value;
                url = repoProperties.getProperty(key);
                try {
                    url = url.trim();
                    if (InstallUtils.isURL(url)) {

                        URL repoUrl = new URL(url);
                        /**
                         * unsupported protocol
                         */
                        String protocol = repoUrl.getProtocol();
                        if (!protocol.equalsIgnoreCase("http") && !protocol.equalsIgnoreCase("https") && !protocol.equalsIgnoreCase("file")) {
                            validationResults.add(new RepositoryConfigValidationResult(lineNum, RepositoryConfigValidationResult.ValidationFailedReason.UNSUPPORTED_PROTOCOL, InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("MSG_VALIDATION_UNSUPPORT_PROTOCOL",
                                    value)));
                            return;
                        }
			/*
			 * Check keyserver
			 */
			if (key.endsWith(InstallConstants.KEYSERVER_QUALIFIER)
				&& (protocol.equalsIgnoreCase("http") || protocol.equalsIgnoreCase("https"))) {
			    boolean isSupported = false;
			    for (String server : SUPPORTED_KEYSERVERS) {
				if (url.toLowerCase().contains(server)) {
				    isSupported = true;
				    break;
				}
			    }
			    if (!isSupported) {
				validationResults.add(new RepositoryConfigValidationResult(lineNum,
					RepositoryConfigValidationResult.ValidationFailedReason.INVALID_KEYSERVER,
					InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES
						.getLogMessage("MSG_VALIDATION_UNSUPPORT_KERYSERVER", url)));
				return;
			    }
			}
                    }

                } catch (MalformedURLException e) {
                    validationResults.add(new RepositoryConfigValidationResult(lineNum, RepositoryConfigValidationResult.ValidationFailedReason.INVALID_URL, InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("MSG_VALIDATION_INVALID_URL",
                            value)));
                    return;
                }

            }

	    /*
	     * / feature verify can be "enforce", "warn", "skip", or "all".
	     */
	    if (key.equals(FEATURE_VERIFY)) {
		try {
		    VerifyOption.valueOf(value.toLowerCase());
		} catch (Exception e) {
		    validationResults.add(new RepositoryConfigValidationResult(lineNum,
			    RepositoryConfigValidationResult.ValidationFailedReason.INVALID_VALUE,
			    InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES
				    .getLogMessage("MSG_VALIDATION_INVALID_VERIFY_OPTION", value)));
		    return;
		}
	    }

	    /*
	     * / key id should be long 64 bits or 32 bits(not recommended)
	     */
	    if (key.endsWith(InstallConstants.KEYID_QUALIFIER)) {
		if (value.startsWith("0x")) {
		    value = value.substring(2);
		}
		if (value.length() != 16 && value.length() != 8) {
		    validationResults.add(new RepositoryConfigValidationResult(lineNum,
			    RepositoryConfigValidationResult.ValidationFailedReason.INVALID_KEYID,
			    InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES
				    .getLogMessage("MSG_VALIDATION_INVALID_KEYID", value)));
		    return;
		}
	    }

            /**
             * port number is between 1-65535
             */

            if (key.equals(PROXY_PORT)) {
                try {
                    int port = Integer.parseInt(value);
                    //Check proxy port number in range
                    if (port <= 0 || port > 0xFFFF) {
                        validationResults.add(new RepositoryConfigValidationResult(lineNum, RepositoryConfigValidationResult.ValidationFailedReason.INVALID_PORT, InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("MSG_VALIDATION_INVALID_PORT_VALUE",
                                value)));
                        return;
                    }
                } catch (Exception e) {
                    validationResults.add(new RepositoryConfigValidationResult(lineNum, RepositoryConfigValidationResult.ValidationFailedReason.INVALID_PORT, InstallLogUtils.Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("MSG_VALIDATION_INVALID_PORT_VALUE",
                            value)));
                    return;
                }

            }
        }

    }


}


