/* Copyright (c) 2019, Matthias Bläsing, All Rights Reserved
 *
 * The contents of this file is dual-licensed under 2  alternative Open Source
 * /Free licenses: LGPL 2.1 or later and Apache License 2.0.
 *
 * You can freely decide which license you want to apply to
 * the project.
 *
 * You may obtain a copy of the LGPL License at:
 *
 * http://www.gnu.org/licenses/licenses.html
 *
 *
 * You may obtain a copy of the Apache License at:
 *
 * http://www.apache.org/licenses/
 *
 */

package edu.udo.itmc.dev.blaesing.tsautils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.X509Certificate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.asn1.tsp.TimeStampReq;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.StoreException;

public class DFNTimestampService {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final AlgorithmIdentifier SHA256_OID;
    private static final KeyStore BUILT_IN_DFN_ANCHORS;
    private static final URL BUILT_IN_TSA_URL;

    private final URL tsaUrl;
    private final KeyStore runtimeKeystore;

    static {
        Security.addProvider(new BouncyCastleProvider());
        DigestAlgorithmIdentifierFinder algorithmFinder = new DefaultDigestAlgorithmIdentifierFinder();
        SHA256_OID = algorithmFinder.find("SHA-256");

        try {
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            KeyStore anchors = KeyStore.getInstance(KeyStore.getDefaultType());
            anchors.load(null);
            try (InputStream is = Main.class.getResourceAsStream("/META-INF/dfn-services-chain.pem")) {
                int dfnCount = 0;
                for (Certificate cert : certificateFactory.generateCertificates(is)) {
                    dfnCount++;
                    anchors.setCertificateEntry("DFN-SERVICES-" + dfnCount, cert);
                }
            }

            BUILT_IN_DFN_ANCHORS = anchors;
        } catch (CertificateException | IOException | KeyStoreException | NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }

        try {
            BUILT_IN_TSA_URL = new URL("http://zeitstempel.dfn.de/");
        } catch (MalformedURLException ex) {
            throw new RuntimeException(ex);
        }
    }

    public DFNTimestampService() {
        this(BUILT_IN_TSA_URL);
    }

    public DFNTimestampService(URL tsaUrl) {
        this(tsaUrl, null);
    }

    public DFNTimestampService(URL tsaUrl, KeyStore additionalTruststore) {
        this.tsaUrl = tsaUrl;
        if(additionalTruststore == null) {
            this.runtimeKeystore = BUILT_IN_DFN_ANCHORS;
        } else {
            try {
                this.runtimeKeystore = KeyStore.getInstance(KeyStore.getDefaultType());
                int count = 0;
                for(KeyStore ks: new KeyStore[] {BUILT_IN_DFN_ANCHORS, additionalTruststore}) {
                    Enumeration<String> enumeration = ks.aliases();
                    while(enumeration.hasMoreElements()) {
                        count++;
                        String inputAlias = enumeration.nextElement();
                        if(ks.isCertificateEntry(inputAlias)) {
                            this.runtimeKeystore.setCertificateEntry(
                                    Integer.toString(count),
                                    ks.getCertificate(inputAlias));
                        }
                    }
                }
            } catch (KeyStoreException ex) {
                throw new RuntimeException(ex);
            }
        }
    }

    /**
     * Request a timestamp token for the supplied input stream. The supplied
     * input stream will be hashed and a timestamp token will be requested.
     * After validation the timestamp token will be returned to the caller.
     *
     * @param is InputStream to create the timestamp for
     * @return TimeStampToken on success
     * @throws IOException
     * @throws TSPException
     */
    public TimeStampToken timestamp(InputStream is) throws IOException, TSPException {
        try {
            byte[] hash = hashStream(is, SHA256_OID);

            MessageImprint imprint = new MessageImprint(SHA256_OID, hash);

            TimeStampReq request = new TimeStampReq(
                    imprint,
                    null,
                    new ASN1Integer(RANDOM.nextLong()),
                    ASN1Boolean.TRUE,
                    null);

            byte[] body = request.getEncoded();
            byte[] responseBytes = getTSAResponse(body);

            ASN1StreamParser asn1Sp = new ASN1StreamParser(responseBytes);
            TimeStampResp tspResp = TimeStampResp.getInstance(asn1Sp.readObject());
            TimeStampResponse tsr = new TimeStampResponse(tspResp);

            checkTSAReplyForErrors(tsr);

            // validate communication level attributes (RFC 3161 PKIStatus)
            tsr.validate(new TimeStampRequest(request));

            return tsr.getTimeStampToken();
        } catch (NoSuchAlgorithmException ex) {
            // A fixed algorithm is used, this should be caught by unittests
            throw new RuntimeException(ex);
        }
    }

    /**
     * Validate a supplied TimeStampToken data
     *
     * @param data
     * @param tstBytes
     * @return
     * @throws IOException
     * @throws TSPException
     */
    public ZonedDateTime validate(InputStream data, byte[] tstBytes) throws IOException, TSPException {
        try {
            TimeStampToken tst = new TimeStampToken(new CMSSignedData(tstBytes));

            try {
                byte[] dataHash = hashStream(data, tst.getTimeStampInfo().getHashAlgorithm());
                if(! Arrays.equals(tst.getTimeStampInfo().getMessageImprintDigest(), dataHash)) {
                    throw new TSPException("Validation failed - message imprint did not match data imprint");
                }
            } catch (NoSuchAlgorithmException ex) {
                throw new TSPException("Unsupported hash: " + tst.getTimeStampInfo().getHashAlgorithm());
            }

            validateCertpath(tst);

            Date signDate = getSigningTime(tst);
            ZonedDateTime zdt = ZonedDateTime.ofInstant(signDate.toInstant(), ZoneId.of("UTC"));
            return zdt;
        } catch (CMSException ex) {
            throw new TSPException("Illegal Message Format", ex);
        } catch (CertificateException | OperatorCreationException | KeyStoreException | InvalidAlgorithmParameterException | NoSuchAlgorithmException ex) {
            throw new IOException("Failed to create verifier", ex);
        }
    }

    /**
     * Create a SHA256 messagedigest for the supplied inputstream.The
     * inputstream will be read completely, but not closed.
     *
     * @param is InputStream to read
     * @param algorithmIdentifier algorithm to use
     * @return message digest
     * @throws IOException
     * @throws java.security.NoSuchAlgorithmException
     */
    protected byte[] hashStream(InputStream is, AlgorithmIdentifier algorithmIdentifier) throws IOException, NoSuchAlgorithmException {
        byte[] hash;
        MessageDigest md = getMessageDigest(algorithmIdentifier);
        byte[] buffer = new byte[100 * 1024];
        int read;
        while ((read = is.read(buffer)) > 0) {
            md.update(buffer, 0, read);
        }
        hash = md.digest();
        return hash;
    }

    /**
     * Do a sanity check of the TSA response.
     *
     * <p>
     * Implementation note: Currently the following checks are performed:</p>
     *
     * <ul>
     * <li></li>
     * </ul>
     *
     * @param tsr
     * @throws IOException
     * @throws TSPException
     */
    protected void checkTSAReplyForErrors(TimeStampResponse tsr) throws IOException, TSPException {
        try {
            // Check that the timestamp response was not failed by the TSA
            PKIFailureInfo failure = tsr.getFailInfo();
            int value = (failure == null) ? 0 : failure.intValue();
            if (value != 0) {
                throw new IOException("Invalid TSA '" + tsaUrl + "' response, code " + value + " (" + tsr.getStatusString() + ")");
            }

            validateCertpath(tsr.getTimeStampToken());
        } catch (CMSException ex) {
            throw new TSPException("Illegal Message Format", ex);
        } catch (CertificateException | OperatorCreationException | KeyStoreException | InvalidAlgorithmParameterException | NoSuchAlgorithmException ex) {
            throw new IOException("Failed to create verifier", ex);
        }
    }

    protected void validateCertpath(TimeStampToken timeStampToken) throws StoreException, KeyStoreException, NoSuchAlgorithmException, CMSException, OperatorCreationException, TSPException, InvalidAlgorithmParameterException, CertificateException {
        // Extract the sigining certificate from the Token and validate,
        // that the certificate was really used to sign it.

        // https://stackoverflow.com/questions/42114742/
        Collection<X509CertificateHolder> tstMatches
                = timeStampToken.getCertificates().getMatches(timeStampToken.getSID());
        X509CertificateHolder holder = tstMatches.iterator().next();
        X509Certificate tstCert = new JcaX509CertificateConverter().getCertificate(holder);
        SignerInformationVerifier siv = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(tstCert);
        timeStampToken.validate(siv);

        // Verify the returned certificate against the DFN cert store
        PKIXParameters params = new PKIXParameters(BUILT_IN_DFN_ANCHORS);
        params.setRevocationEnabled(false);
        params.setDate(Date.from(getSigningTime(timeStampToken).toInstant()));

        CertPath cp = CertificateFactory.getInstance("X.509").generateCertPath(Collections.singletonList(tstCert));

        try {
            CertPathValidator.getInstance(CertPathValidator.getDefaultType()).validate(cp, params);
        } catch (CertPathValidatorException ex) {
            throw new TSPException("CertPath could not be validated", ex);
        }
    }

    /**
     * Extract the signing time from the TimeStampToken. The time is read from
     * the signed attribute table.
     *
     * @param tst token the timestamp is to be extracted from
     * @return timestamp of signing time or {@code null} if no timestamp is
     * present
     * @throws CMSException if multiple timestamps are present
     */
    protected Date getSigningTime(TimeStampToken tst) throws CMSException {
        ASN1EncodableVector v = tst.getSignedAttributes().getAll(CMSAttributes.signingTime);
        switch (v.size()) {
            case 0:
                return null;
            case 1: {
                Attribute t = (Attribute) v.get(0);
                ASN1Set attrValues = t.getAttrValues();
                if (attrValues.size() != 1) {
                    throw new CMSException("A signingTime attribute MUST have a single attribute value");
                }

                Date date = Time.getInstance(attrValues.getObjectAt(0).toASN1Primitive()).getDate();
                return date;
            }
            default:
                throw new CMSException(
                        "The SignedAttributes in a signerInfo MUST NOT include multiple instances of the signingTime attribute");
        }
    }

    /**
     * Transfer the TimeStampRequest to the TSA and retrieve the response.
     *
     * @param requestBytes encoded form of the request
     * @return encoded form of the response
     * @throws IOException
     */
    protected byte[] getTSAResponse(byte[] requestBytes) throws IOException {
        URLConnection tsaConnection = tsaUrl.openConnection();
        tsaConnection.setConnectTimeout(5000);
        tsaConnection.setDoInput(true);
        tsaConnection.setDoOutput(true);
        tsaConnection.setUseCaches(false);
        tsaConnection.setRequestProperty("Content-Type", "application/timestamp-query");
        tsaConnection.setRequestProperty("Content-Transfer-Encoding", "binary");

        try (OutputStream out = tsaConnection.getOutputStream()) {
            out.write(requestBytes);
        }

        byte[] respBytes;
        try (InputStream input = tsaConnection.getInputStream()) {
            ByteArrayOutputStream bais = new ByteArrayOutputStream(10 * 1024);
            int read;
            byte[] buffer = new byte[10 * 1024];
            while ((read = input.read(buffer)) >= 0) {
                bais.write(buffer, 0, read);
            }
            respBytes = bais.toByteArray();
        }

        String encoding = tsaConnection.getContentEncoding();
        if (encoding != null && encoding.equalsIgnoreCase("base64")) {
            respBytes = Base64.getDecoder().decode(respBytes);
        }
        return respBytes;
    }

    protected MessageDigest getMessageDigest(AlgorithmIdentifier digestId) throws NoSuchAlgorithmException {
        if(SHA256_OID.equals(digestId)) {
            return MessageDigest.getInstance("SHA-256");
        } else {
            throw new NoSuchAlgorithmException("Unknown AlgorithmIdentifier: " + digestId);
        }
    }
}
