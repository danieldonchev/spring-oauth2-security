package app.jwt;

import app.UserPrincipal;
import app.exceptions.OAuth2AuthenticationProcessingException;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jwt.JWTClaimsSet;
import com.sun.org.apache.xml.internal.security.utils.Base64;
import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Optional;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;

@Component
public class JwtGenerator {

  public String generateToken(UserPrincipal principal) {

    JWEObject jweObject = null;
    try {

      Payload payload = new Payload(getClaims(principal).toJSONObject());
      JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);
      jweObject = new JWEObject(header, payload);

      SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
      KeySpec spec = new PBEKeySpec("very-secret-password".toCharArray(), "salt".getBytes(), 500,
          256);
      SecretKey tmp = factory.generateSecret(spec);
      SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

      DirectEncrypter encrypter = new DirectEncrypter(secret);

      jweObject.encrypt(encrypter);
    } catch (JOSEException | NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new OAuth2AuthenticationProcessingException(
          "Something went wrong when creating the access token", e);
    }

    return Optional.ofNullable(jweObject).orElseThrow(
        () -> new OAuth2AuthenticationProcessingException("Cannot create access token."))
        .serialize();
  }

  private JWTClaimsSet getClaims(UserPrincipal principal) {
    return new JWTClaimsSet.Builder()
        .claim("email", principal.getEmail())
        .claim("name", principal.getName())
        .claim("authorities", principal.getAuthorities())
        .build();
  }
}
