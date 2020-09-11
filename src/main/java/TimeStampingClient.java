import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.URL;
import java.net.URLConnection;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.encoders.Base64;
 
public class TimeStampingClient {
 
    private TimeStampingClient() {
    }
 
    
    public static void main(String[] args) {
    	System.setProperty("sun.net.http.allowRestrictedHeaders", "true");
    	TimeStampingClient t = new TimeStampingClient();
    	try {
    		byte[] timeStampToken = t.getTimeStampToken("http://172.16.20.20:8091", "oguzhan".getBytes());
    		System.out.println(new String(timeStampToken));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    
    /**
     * Get RFC 3161 timeStampToken.
     *
     * @param tsaUrl Location of TSA
     * @param data The data to be time-stamped
     * @param hashAlg The algorithm used for generating a hash value of the data to be time-stamped
     * @return encoded, TSA signed data of the timeStampToken
     * @throws IOException
     */
    public static byte[] getTimeStampToken(String tsaUrl, byte[] data) throws IOException {
 
        TimeStampResponse response = null;
        try {
 
            // calculate hash value
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashValue = digest.digest(data);
 
            // Setup the time stamp request
            TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
            tsqGenerator.setCertReq(true);
            BigInteger nonce = new BigInteger(128, new SecureRandom());
            
            TimeStampRequest request = tsqGenerator.generate(NISTObjectIdentifiers.id_sha256, hashValue,nonce);
            		
            byte[] requestBytes = request.getEncoded();
 
            // send http request
            byte[] respBytes = queryServer(tsaUrl, requestBytes,"username","password");
 
            // process response
            response = new TimeStampResponse(respBytes);
 
            // validate communication level attributes (RFC 3161 PKIStatus)
            response.validate(request);
            PKIFailureInfo failure = response.getFailInfo();
            int value = failure == null ? 0 : failure.intValue();
            if (value != 0) {
                throw new IOException("Server returned error code: " + value);
            }
        } catch (NoSuchAlgorithmException | TSPException e) {
            throw new IOException(e);
        }
 
        // extract the time stamp token
        TimeStampToken tsToken = response.getTimeStampToken();
        if (tsToken == null) {
            throw new IOException("TSA returned no time stamp token: " + response.getStatusString());
        }
 
        return tsToken.getEncoded();
    }
 
    /**
     * Get timestamp token (HTTP communication)
     *
     * @return TSA response, raw bytes (RFC 3161 encoded)
     * @throws IOException
     */
    private static byte[] queryServer(String tsaUrl, byte[] requestBytes,String username, String password) throws IOException {
    	URLConnection con = null;
    	try {
            URL url = new URL(tsaUrl);
            con =  url.openConnection();
            con.setDoInput(true);
            con.setDoOutput(true);
            con.setUseCaches(false);
            con.setRequestProperty("Content-Type", "application/timestamp-query");
            String basicAuth = username + ":" + password;
            basicAuth = "Basic " + new String(Base64.encode(basicAuth.getBytes()));
            con.setRequestProperty("Authorization",basicAuth);
            con.setRequestProperty("Accept", "*/*");
 
            OutputStream out = con.getOutputStream();
            out.write(requestBytes);
            out.close();
 
            InputStream is = con.getInputStream();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int bytesRead = 0;
            while ((bytesRead = is.read(buffer, 0, buffer.length)) >= 0) {
                baos.write(buffer, 0, bytesRead);
            }
            byte[] respBytes = baos.toByteArray();
            is.close();
 
            String encoding = con.getContentEncoding();
            if (encoding != null && encoding.equalsIgnoreCase("base64")) {
                respBytes = Base64.decode(new String(respBytes));
            }
            return respBytes;
 
        } catch (Exception e) {
			e.printStackTrace();
			throw e;
		} 
    }
}