package app;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jwt.JWTClaimsSet;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class JwtGenerator {


  private SecretKey key = new SecretKeySpec("secret".getBytes(), "DES");

  public String generateToken(Authentication authentication) {

    JWEObject jweObject = null;
    try {
      JWTClaimsSet claims = new JWTClaimsSet.Builder()
          .claim("email", "sanjay@example.com")
          .claim("name", "Sanjay Patel")
          .build();

      Payload payload = new Payload(claims.toJSONObject());
      JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);
      jweObject = new JWEObject(header, payload);
      String secret = "secret";
      byte[] secretKey = secret.getBytes();
      DirectEncrypter encrypter = new DirectEncrypter(secretKey);

      jweObject.encrypt(encrypter);
    } catch (JOSEException e) {

      e.printStackTrace();
    }

    return jweObject.serialize();
  }
}
