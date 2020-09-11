import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

public class TimestampVerify {

	public static void main(String[] args) {

		try {
			File file = new File("/Users/oguzhan/changes-2020-09-08.tsr");
			File csv = new File("/Users/oguzhan/changes-2020-09-08.csv");

			TimeStampResponse response = new TimeStampResponse(readContentIntoByteArray(file));
			TimeStampToken token = response.getTimeStampToken();
			AttributeTable signedAttributes = token.getSignedAttributes();

			JcaContentVerifierProviderBuilder jcaCVPB = new JcaContentVerifierProviderBuilder();
			JcaDigestCalculatorProviderBuilder digestCalcPB = new JcaDigestCalculatorProviderBuilder();
			DigestCalculatorProvider digestCalc = digestCalcPB.build();
			ContentVerifierProvider contentVP = jcaCVPB.build(getCert()); // getCert() returns an X509Certificate object
			SignerInformationVerifier signerInfo = new SignerInformationVerifier(
					new DefaultCMSSignatureAlgorithmNameGenerator(), new DefaultSignatureAlgorithmIdentifierFinder(),
					contentVP, digestCalc);
			token.validate(signerInfo);
			org.bouncycastle.tsp.TimeStampTokenInfo tsTokenInfo = token.getTimeStampInfo();
			System.out.println(tsTokenInfo.getMessageImprintAlgOID().getId());
			MessageDigest md = MessageDigest.getInstance(tsTokenInfo.getMessageImprintAlgOID().getId());

			if (!Arrays.equals(md.digest(readContentIntoByteArray(csv)), tsTokenInfo.getMessageImprintDigest())) {
				System.err.println("fail while hash comparision");
			} else {
				System.out.println("success for digest: " + new String(tsTokenInfo.getMessageImprintDigest()));
				System.out.println("token gen time: "+tsTokenInfo.getGenTime());
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private static X509CertificateHolder getCert() {
		try {

			InputStream in;
			in = new FileInputStream("/Users/oguzhan/free.pem");
			CertificateFactory factory = CertificateFactory.getInstance("X.509");

			X509Certificate cert = (X509Certificate) factory.generateCertificate(in);

			// RSA Signature processing with BC
			return new X509CertificateHolder(cert.getEncoded());
		} catch (Exception e) {
			// TODO: handle exception
		}
		return null;
	}

	private static byte[] readContentIntoByteArray(File file) {
		FileInputStream fileInputStream = null;
		byte[] bFile = new byte[(int) file.length()];
		try {
			fileInputStream = new FileInputStream(file);
			fileInputStream.read(bFile);
			fileInputStream.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return bFile;
	}

}
