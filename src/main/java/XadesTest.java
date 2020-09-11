import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;

import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;

import xades4j.providers.impl.DefaultMessageDigestProvider;
import xades4j.providers.impl.DefaultTimeStampVerificationProvider;
import xades4j.providers.impl.PKIXCertificateValidationProvider;

public class XadesTest  {
	
	private static KeyStore createAndLoadJKSKeyStore(String path, String pwd) throws Exception
    {
        FileInputStream fis = new FileInputStream(path);
        KeyStore ks = KeyStore.getInstance("jks");
        ks.load(fis, pwd.toCharArray());
        fis.close();
        return ks;
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

	public static void main(String[] args) {
		try {
			
		File file = new File("/Users/oguzhan/changes-2020-09-08.tsr");
		File csv = new File("/Users/oguzhan/changes-2020-09-08.csv");
		KeyStore ks = createAndLoadJKSKeyStore("/Users/oguzhan/trustAnchorRoot", "changeit");
        PKIXCertificateValidationProvider certificateValidationProvider = new PKIXCertificateValidationProvider(ks, false);

        DefaultTimeStampVerificationProvider timeStampVerificationProvider = new DefaultTimeStampVerificationProvider(
                certificateValidationProvider,
                new DefaultMessageDigestProvider());
        TimeStampResponse response = new TimeStampResponse(readContentIntoByteArray(file));
		TimeStampToken token = response.getTimeStampToken();

        System.out.println(timeStampVerificationProvider.verifyToken(token.getEncoded(), readContentIntoByteArray(csv)));
		} catch (Exception e) {
			// TODO: handle exception
			e.printStackTrace();
		}

	}

}
