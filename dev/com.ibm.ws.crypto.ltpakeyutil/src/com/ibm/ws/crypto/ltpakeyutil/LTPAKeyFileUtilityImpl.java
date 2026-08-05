/*******************************************************************************
 * Copyright (c) 2016, 2025 IBM Corporation and others.
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

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Properties;

import com.ibm.ws.common.encoder.Base64Coder;

/**
 * 
 */
public class LTPAKeyFileUtilityImpl implements LTPAKeyFileUtility {

    /** {@inheritDoc} */
    @Override
    public Properties createLTPAKeysFile(String keyFile, KeyEncryptor encryptor) throws Exception {
        Properties ltpaProps = generateLTPAKeys(encryptor, "defaultRealm");
        addLTPAKeysToFile(getOutputStream(keyFile), ltpaProps);
        return ltpaProps;
    }

    /**
     * Generates new LTPA key pairs and shared key, encrypts them with the supplied
     * {@link KeyEncryptor}, and returns the result as a Properties object.
     *
     * @param encryptor The encryptor to use (password-derived or hardware-backed)
     * @param realm     The LTPA realm name
     * @return Properties containing the encrypted LTPA key material
     * @throws Exception
     */
    protected final Properties generateLTPAKeys(KeyEncryptor encryptor, final String realm) throws Exception {
        LTPAKeyPair pair = LTPADigSignature.generateLTPAKeyPair();
        byte[] publicKeyBytes = pair.getPublic().getEncoded();
        byte[] privateKeyBytes = pair.getPrivate().getEncoded();
        return generateLTPAKeys(encryptor, publicKeyBytes, privateKeyBytes, null, realm);
    }

    /**
     * Encrypts the supplied key material (or generates new material where {@code null} is passed)
     * using the supplied {@link KeyEncryptor} and returns the result as a Properties object.
     *
     * <p>Used for both fresh key creation (pass {@code null} for all key bytes) and re-encryption
     * of existing keys (pass the decrypted bytes).
     *
     * @param encryptor      The encryptor to use
     * @param publicKeyBytes  Existing public key bytes (may be {@code null} to generate)
     * @param privateKeyBytes Existing private key bytes (may be {@code null} to generate)
     * @param sharedKeyBytes  Existing shared key bytes (may be {@code null} to generate)
     * @param realm           The LTPA realm name
     * @return Properties containing the encrypted LTPA key material
     * @throws Exception
     */
    protected final Properties generateLTPAKeys(KeyEncryptor encryptor,
                                                byte[] publicKeyBytes, byte[] privateKeyBytes,
                                                byte[] sharedKeyBytes, final String realm) throws Exception {
        if (publicKeyBytes == null || privateKeyBytes == null) {
            LTPAKeyPair pair = LTPADigSignature.generateLTPAKeyPair();
            publicKeyBytes = pair.getPublic().getEncoded();
            privateKeyBytes = pair.getPrivate().getEncoded();
        }
        byte[] encryptedPrivateKeyBytes = encryptor.encrypt(privateKeyBytes);

        if (sharedKeyBytes == null) {
            sharedKeyBytes = LTPACrypto.generateSharedKey();
        }
        byte[] encryptedSharedKeyBytes = encryptor.encrypt(sharedKeyBytes);

        String tmpShared  = Base64Coder.base64EncodeToString(encryptedSharedKeyBytes);
        String tmpPrivate = Base64Coder.base64EncodeToString(encryptedPrivateKeyBytes);
        String tmpPublic  = Base64Coder.base64EncodeToString(publicKeyBytes);

        Properties expProps = new Properties();
        expProps.put(KEYIMPORT_SECRETKEY,         tmpShared);
        expProps.put(KEYIMPORT_PRIVATEKEY,        tmpPrivate);
        expProps.put(KEYIMPORT_PUBLICKEY,         tmpPublic);
        expProps.put(KEYIMPORT_REALM,             realm);
        expProps.put(CREATION_HOST_PROPERTY,      "localhost");
        expProps.put(LTPA_VERSION_PROPERTY,       encryptor.getLtpaVersion());
        expProps.put(CREATION_DATE_PROPERTY,      (new java.util.Date()).toString());
        return expProps;
    }

    /**
     * Obtain the OutputStream for the given file.
     * 
     * @param keyFile
     * @return
     * @throws IOException
     */
    private OutputStream getOutputStream(final String keyFile) throws IOException {
        try {
            return AccessController.doPrivileged(new PrivilegedExceptionAction<OutputStream>() {
                @Override
                public OutputStream run() throws IOException {
                    return new FileOutputStream(new File(keyFile));
                }
            });
        } catch (PrivilegedActionException e) {
            // Wrap the wrapped IOException from doPriv in an IOException and re-throw
            throw new IOException(e.getCause());
        }
    }

    /**
     * Write the LTPA key properties to the given OutputStream. This method
     * will close the OutputStream.
     *
     * @param keyImportFile The import file to be created
     * @param ltpaProps The properties containing the LTPA keys
     *
     * @throws TokenException
     * @throws IOException
     */
    protected void addLTPAKeysToFile(OutputStream os, Properties ltpaProps) throws Exception {
        try {
            ltpaProps.store(os, null);
        } catch (IOException e) {
            throw e;
        } finally {
            if (os != null)
                try {
                    os.close();
                } catch (IOException e) {
                }
        }
    }

}
