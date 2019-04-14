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
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1StreamParser;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
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


public class DFNTimestampService {

    private static final URL tsaUrl;
    private static final KeyStore dfnServiceAnchors;
    private static final AlgorithmIdentifier sha256oid;

    static {
        Security.addProvider(new BouncyCastleProvider());

	DigestAlgorithmIdentifierFinder algorithmFinder = new DefaultDigestAlgorithmIdentifierFinder();
	sha256oid = algorithmFinder.find("SHA-256");
	try {
            tsaUrl = new URL("http://zeitstempel.dfn.de/");
	} catch (MalformedURLException ex) {
	    throw new RuntimeException(ex);
	}
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

            dfnServiceAnchors = anchors;
        }   catch (CertificateException | IOException | KeyStoreException | NoSuchAlgorithmException ex) {
            throw new RuntimeException(ex);
        }
    }

    private SecureRandom random = new SecureRandom();

    public TimeStampToken timestamp(InputStream is) throws IOException {
        byte[] hash = hashStream(is);

	MessageImprint imprint = new MessageImprint(sha256oid, hash);

	TimeStampReq request = new TimeStampReq(
		imprint,
		null,
		new ASN1Integer(random.nextLong()),
		ASN1Boolean.TRUE,
		null);

	byte[] body = request.getEncoded();
	try {
	    byte[] responseBytes = getTSAResponse(body);

	    ASN1StreamParser asn1Sp = new ASN1StreamParser(responseBytes);
	    TimeStampResp tspResp = TimeStampResp.getInstance(asn1Sp.readObject());
	    TimeStampResponse tsr = new TimeStampResponse(tspResp);

	    checkForErrors(tsr);

	    // validate communication level attributes (RFC 3161 PKIStatus)
	    tsr.validate(new TimeStampRequest(request));

	    return tsr.getTimeStampToken();
	} catch (TSPException e) {
	    throw new IOException(e);
	}
    }

    private byte[] hashStream(InputStream is) throws IOException {
        byte[] hash;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[100 * 1024];
            int read = 0;
            while((read = is.read(buffer)) > 0) {
                md.update(buffer, 0, read);
            }
            hash = md.digest();
        } catch (NoSuchAlgorithmException ex) {
            throw new IOException(ex);
        }
        return hash;
    }

    public ZonedDateTime validate(InputStream data, byte[] tstBytes) throws TSPException, IOException {
        try {
            TimeStampToken tst = new TimeStampToken(new CMSSignedData(tstBytes));
            tst.getSignedAttributes().get(CMSAttributes.messageDigest).toASN1Primitive();
            System.out.println(tst.getTimeStampInfo().getHashAlgorithm().getAlgorithm());
            if(! tst.getTimeStampInfo().getHashAlgorithm().equals(sha256oid)) {
                throw new IOException("Unsupported hash: " + tst.getTimeStampInfo().getHashAlgorithm());
            }
            System.out.println(Arrays.equals(tst.getTimeStampInfo().getMessageImprintDigest(), hashStream(data)));
            return getSigningTime(tst.getSignedAttributes());
        } catch (CMSException ex) {
            throw new IOException(ex);
        }
    }

    private void checkForErrors(TimeStampResponse tsr) throws IOException, TSPException {
        try {
            PKIFailureInfo failure = tsr.getFailInfo();
            int value = (failure == null) ? 0 : failure.intValue();
            if (value != 0) {
                throw new IOException("Invalid TSA '" + tsaUrl + "' response, code " + value + " (" + tsr.getStatusString() + ")");
            }
            TimeStampToken timeStampToken = tsr.getTimeStampToken();
            // https://stackoverflow.com/questions/42114742/
            Collection<X509CertificateHolder> tstMatches
                = timeStampToken.getCertificates().getMatches(timeStampToken.getSID());
            X509CertificateHolder holder = tstMatches.iterator().next();
            X509Certificate tstCert = new JcaX509CertificateConverter().getCertificate(holder);
            SignerInformationVerifier siv = new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(tstCert);
            timeStampToken.validate(siv);

            PKIXParameters params = new PKIXParameters(dfnServiceAnchors);
            params.setRevocationEnabled(false);

            CertPath cp = CertificateFactory.getInstance("X.509").generateCertPath(Collections.singletonList(tstCert));

            try {
                CertPathValidator.getInstance(CertPathValidator.getDefaultType()).validate(cp, params);
            } catch (CertPathValidatorException ex) {
                throw new IOException("CertPath could not be validated", ex);
            }
        } catch (CertificateException | OperatorCreationException | KeyStoreException | InvalidAlgorithmParameterException | NoSuchAlgorithmException ex) {
            throw new IOException("Failed to create verifier", ex);
        }
    }

    private ZonedDateTime getSigningTime(AttributeTable signedAttrTable) throws CMSException {
	ASN1EncodableVector v = signedAttrTable.getAll(CMSAttributes.signingTime);
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
		ZonedDateTime ldt = ZonedDateTime.ofInstant(date.toInstant(), ZoneId.of("UTC"));
		return ldt;
	    }
	    default:
		throw new CMSException(
			"The SignedAttributes in a signerInfo MUST NOT include multiple instances of the signingTime attribute");
	}
    }

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
	    while((read = input.read(buffer)) >= 0) {
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
}
