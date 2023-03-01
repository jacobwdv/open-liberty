/*******************************************************************************
 * Copyright (c) 2023 IBM Corporation and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Contributors:
 *     IBM Corporation - initial API and implementation
 *******************************************************************************/
package com.ibm.ws.install.internal;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;

import com.ibm.ws.install.InstallConstants;
import com.ibm.ws.install.InstallConstants.VerifyOption;
import com.ibm.ws.install.InstallException;
import com.ibm.ws.install.internal.InstallLogUtils.Messages;
import com.ibm.ws.kernel.boot.cmdline.Utils;

/**
 *
 */
public class VerifySignatureUtility {

    private static final Logger logger = InstallLogUtils.getInstallLogger();
    private static final String DEFAULT_LIBERTY_KEY_ID = "0x4D210F6946102B8E";
    private static final String UBUNTU_HOST = "keyserver.ubuntu.com";
    private static final String PGP_HOST = "keys.openpgp.org";
    private static final String MIT_HOST = "pgp.mit.edu";
    private static final String UbuntuServerURL = "https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search=";
    private static final String MITServerURL = "https://pgp.mit.edu/pks/lookup?op=get&options=mr&search=";
    private static final String PGPServerURL = "https://keys.openpgp.org/pks/lookup?op=get&options=mr&search=";

    private final ProgressBar progressBar = ProgressBar.getInstance();

    VerifySignatureUtility() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public boolean isKeyValid(Path keyPath) throws InstallException {
        File pubKey = keyPath.toFile();
        try (FileInputStream fis = new FileInputStream(pubKey); InputStream keyIn = new BufferedInputStream(fis)) {

            PGPPublicKeyRing pgpPubKeyRing = new PGPPublicKeyRing(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());
            PGPPublicKey publicKey = pgpPubKeyRing.getPublicKey();
            String keyID = String.format("%x", pgpPubKeyRing.getPublicKey().getKeyID());

            //Check if the key is revoked
            if (publicKey.hasRevocation()) {
                throw new InstallException(Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("ERROR_REVOKED_PUBLIC_KEY", keyID));
            }

            if (publicKey.getValidSeconds() > 0) { //0 mean no expiry date
                Instant expiryDate = publicKey.getCreationTime().toInstant().plusSeconds(publicKey.getValidSeconds());
                if (expiryDate.isBefore(Instant.now())) {
                    throw new InstallException(Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("ERROR_EXPIRED_PUBLIC_KEY", keyID, expiryDate));
                }
            }
        } catch (IOException e) {
            logger.fine(keyPath.toString() + " is corrupted. ");
            return false;
        }

        return true;
    }

    public List<File> downloadPublicKeys(Collection<Map<String, String>> keys, VerifyOption verify, Map<String, Object> envMap) throws InstallException {
        List<String> allKeys = getPublicKeyURL(keys, verify);
        List<File> downloadedKeys = new ArrayList<>();

        for (String key : allKeys) {
            //download all keys;
            URLConnection conn;
            try {
                logger.fine("Downloading key... " + key);
                URL keyUrl = new URL(key);
                Proxy proxy;
                if (envMap.get("https.proxyHost") != null) {
                    proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress((String) envMap.get("https.proxyHost"), Integer.parseInt((String) envMap.get("https.proxyPort"))));
                } else if (envMap.get("http.proxyHost") != null) {
                    proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress((String) envMap.get("http.proxyHost"), Integer.parseInt((String) envMap.get("http.proxyPort"))));
                } else {
                    proxy = Proxy.NO_PROXY;
                }
                conn = keyUrl.openConnection(proxy);
                conn.setConnectTimeout(10000);

                try (BufferedInputStream in = new BufferedInputStream(conn.getInputStream())) {
                    File tempFile = File.createTempFile("signature", ".asc", Utils.getInstallDir());
                    tempFile.deleteOnExit(); //Delete when JVM exits
                    try (FileOutputStream fileOutputStream = new FileOutputStream(tempFile)) {
                        byte dataBuffer[] = new byte[1024];
                        int bytesRead;
                        while ((bytesRead = in.read(dataBuffer, 0, 1024)) != -1) {
                            fileOutputStream.write(dataBuffer, 0, bytesRead);
                        }
                        if (isKeyValid(tempFile.toPath())) {
                            downloadedKeys.add(tempFile);
                        }
                    }
                }

            } catch (IOException e) {
                // handle exception
                throw new InstallException(Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("ERROR_FAILED_TO_DOWNLOAD_KEY_FROM_KEY_SERVER", e.getMessage()));
            }
        }

        return downloadedKeys;
    }

    private List<String> getPublicKeyURL(Collection<Map<String, String>> keys, VerifyOption verify) throws InstallException {
        List<String> pubKeyUrls = new ArrayList<>();

        //TODO check pubkey shipped from liberty package
        if (!isKeyValid(Paths.get("/Path_to_liberty_key"))) {
            String liberty_keyID = System.getProperty("com.ibm.ws.install.libertyKeyID", DEFAULT_LIBERTY_KEY_ID);
            String PUBKEY_URL = UbuntuServerURL + liberty_keyID;
            pubKeyUrls.add(PUBKEY_URL);
        }

        //get users public keys
        for (Map<String, String> keyMap : keys) {
            String keyServer = keyMap.get(InstallConstants.KEYSERVER_QUALIFIER);
            String keyID = keyMap.get(InstallConstants.KEYID_QUALIFIER);
            URL keyURL;
            if (keyServer == null) { //default key server
                keyServer = UBUNTU_HOST;
            }
            keyServer = keyServer.trim();

            if (!InstallUtils.isURL(keyServer)) {
                if (keyServer.equalsIgnoreCase(UBUNTU_HOST) || keyServer.equalsIgnoreCase(PGP_HOST) || keyServer.equalsIgnoreCase(MIT_HOST)) {
                    keyServer = "https://" + keyServer;
                } else {
                    File f = new File(keyServer);
                    if (!f.exists()) {
                        if (verify == VerifyOption.all) {
                            throw new InstallException(Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("ERROR_KEYSERVER_UNSUPPORTED", keyServer));
                        } else {
                            logger.warning(Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("ERROR_KEYSERVER_UNSUPPORTED", keyServer));
                        }
                        break;
                    }
                    try {
                        keyServer = f.toURI().toURL().toString();
                    } catch (MalformedURLException e1) {
                        logger.log(Level.FINEST, "Failed to convert " + f.getAbsolutePath() + " to url format", e1);
                    }
                }
            }

            try {
                keyURL = new URL(keyServer);
            } catch (MalformedURLException e) {
                if (verify == VerifyOption.all) {
                    throw new InstallException(e.getMessage());
                } else {
                    logger.warning(e.getMessage());
                }
                break;
            }

            String protocol = keyURL.getProtocol();
            if (protocol.equalsIgnoreCase("https") || protocol.equalsIgnoreCase("http")) {
                if (keyID != null && !keyServer.contains(keyID)) {
                    if (!keyID.startsWith("0x")) {
                        keyID = "0x" + keyID;
                    }
                    String hostName = keyURL.getHost().toLowerCase();
                    switch (hostName) {
                        case UBUNTU_HOST:
                            pubKeyUrls.add(UbuntuServerURL + keyID);
                            break;
                        case PGP_HOST:
                            pubKeyUrls.add(PGPServerURL + keyID);
                            break;
                        case MIT_HOST:
                            pubKeyUrls.add(MITServerURL + keyID);
                            break;
                        default:
                            throw new InstallException(Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("ERROR_KEYSERVER_UNSUPPORTED", hostName));
                    }

                } else if (keyID != null && keyServer.contains(keyID)) {
                    pubKeyUrls.add(keyServer);
                } else {
                    if (verify == VerifyOption.all) {
                        throw new InstallException(Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("ERROR_KEYID_NOT_PROVIDED", keyServer));
                    } else {
                        logger.warning(Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("ERROR_KEYID_NOT_PROVIDED", keyServer));
                    }
                }
            } else if (protocol.equalsIgnoreCase("file")) {
                pubKeyUrls.add(keyServer);
            } else {
                if (verify == VerifyOption.all) {
                    throw new InstallException(Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("ERROR_KEYSERVER_UNSUPPORTED_PROTOCOL", keyURL));
                } else {
                    logger.warning(Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("ERROR_KEYSERVER_UNSUPPORTED_PROTOCOL", keyURL));
                }
            }

        }

        return pubKeyUrls;
    }

    /**
     * Verify the signatures of the features
     *
     * @param ESA artifacts downloaded from Maven repository
     * @throws InstallException
     * @throws Excetion
     */
    public void verifySignatures(Collection<File> artifacts, List<File> pubKeys, List<File> failedFeatures) throws InstallException {

        logger.info(Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("STATE_STARTING_VERIFY"));
        PGPPublicKeyRingCollection pgpPubRingCollection = null;

        try {
            // Read and import all public keys to the key ring
            for (File key : pubKeys) {
                try (InputStream keyIn = new BufferedInputStream(new FileInputStream(key))) {
                    if (pgpPubRingCollection == null) {
                        pgpPubRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());
                    } else {
                        PGPPublicKeyRing pgpPubKeyRing = new PGPPublicKeyRing(PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());
                        pgpPubRingCollection = PGPPublicKeyRingCollection.addPublicKeyRing(pgpPubRingCollection,
                                                                                           pgpPubKeyRing);
                    }
                }
            }

            //check if the public key was found
            Iterator<PGPPublicKeyRing> iterator = pgpPubRingCollection.getKeyRings();
            StringBuilder str = new StringBuilder();
            str.append("Available public keyIDs: ");
            while (iterator.hasNext()) {
                PGPPublicKey publicKey = iterator.next().getPublicKey();
                String keyID = String.format("%x", publicKey.getKeyID());
                str.append(keyID + "\t");
            }
            logger.fine(str.toString());

        } catch (IOException | PGPException e) {
            throw new InstallException(e.getMessage());
        }

        double increment = progressBar.getMethodIncrement("verifyFeatures") / (artifacts.size());
        for (File f : artifacts) {
            String esa_path = f.getAbsolutePath();
            String sig_path = esa_path + ".asc";
            try {
                logger.fine(Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("STATE_VERIFYING", f.getName()));
                if (!isValidSignature(esa_path, sig_path, pgpPubRingCollection)) {
                    failedFeatures.add(f);
                } else {
                    logger.fine(Messages.INSTALL_KERNEL_MESSAGES.getLogMessage("LOG_VERIFIED_FEATURE", f.getName()));
                }
                progressBar.updateProgress(increment);

            } catch (IOException | PGPException | GeneralSecurityException e) {
                failedFeatures.add(f);
            }
        }
        progressBar.manuallyUpdate();

    }

    /*
     * verify the signature against the file fileName.
     */
    private boolean isValidSignature(
                                     String fileName,
                                     String sig_path,
                                     PGPPublicKeyRingCollection pgpPubRingCollection) throws GeneralSecurityException, IOException, PGPException {

        // Read signature file
        PGPSignatureList signatureList = getSignatureList(fileName, sig_path);
        //TODO: check sig list length.. throw exception if necessary
        PGPSignature sig = signatureList.get(0);
        logger.fine(String.format("Key ID used in signature: %x", sig.getKeyID()));

        // Check if the key ID that created the signature exists in our public key
        // collection
        PGPPublicKey pubKey = pgpPubRingCollection.getPublicKey(sig.getKeyID());
        if (pubKey == null) {
            logger.fine(String.format("Public key ID %x was not found.", sig.getKeyID()));
            return false;
        }
        logger.fine("Public key ID used: " + pubKey.getKeyID());
        return verifySignature(fileName, sig, pubKey);
    }

    /**
     * @param fileName
     * @param sig
     * @param pubKey
     * @return
     * @throws IOException
     * @throws FileNotFoundException
     */
    private boolean verifySignature(String fileName, PGPSignature sig, PGPPublicKey pubKey) throws IOException, FileNotFoundException, PGPException {
        sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), pubKey);

        // Read file to verify
        try (InputStream dIn = new BufferedInputStream(new FileInputStream(fileName))) {
            int ch;
            while ((ch = dIn.read()) >= 0) {
                sig.update((byte) ch);
            }
        }

        return sig.verify();
    }

    /**
     * @param fileName
     * @param sig_path
     * @param signatureList
     * @return
     * @throws IOException
     * @throws FileNotFoundException
     */
    private PGPSignatureList getSignatureList(String fileName, String sig_path) throws IOException, FileNotFoundException, PGPException {
        PGPSignatureList signatureList = null;
        try (InputStream sigIn = new BufferedInputStream(new FileInputStream(sig_path));
                        InputStream decoderStream = PGPUtil.getDecoderStream(sigIn)) {

            JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(decoderStream);

            Object o;
            while ((o = pgpFact.nextObject()) != null) {
                if (o instanceof PGPCompressedData) {
                    PGPCompressedData c1 = (PGPCompressedData) o;

                    pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

                    signatureList = (PGPSignatureList) pgpFact.nextObject();
                } else {
                    signatureList = (PGPSignatureList) o;
                }

                if (signatureList.isEmpty()) {
                    logger.fine("The PGP signature could not be processed for the following : " + fileName);
                }
            }
        }
        return signatureList;
    }

}
