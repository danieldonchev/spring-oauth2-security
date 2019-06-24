package app;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTProcessor;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class JwtAuthenticationConverter implements ServerAuthenticationConverter {

  private SecretKey key = new SecretKeySpec("secret".getBytes(), "DES");

    private Mono<String> resolveToken(ServerWebExchange exchange) {

      return Mono
          .justOrEmpty(exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION))
          .filter(t -> t.startsWith("Bearer "))
          .map(t -> t.substring(7));
    }

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {

      return resolveToken(exchange)
          .map(this::getAuthentication);
    }

    public Authentication getAuthentication(String token) {

      JWTClaimsSet claimsSet = null;
      try {
        claimsSet = getJwtProcessor().process(token, null);
      } catch (ParseException e) {
        e.printStackTrace();
      } catch (BadJOSEException e) {
        e.printStackTrace();
      } catch (JOSEException e) {
        e.printStackTrace();
      }

      Collection<? extends GrantedAuthority> authorities =
          Arrays.stream(claimsSet.getClaim("auth").toString().split(","))
              .map(SimpleGrantedAuthority::new)
              .collect(Collectors.toList());

      User principal = new User(claimsSet.getSubject(), "", authorities);

      return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    private JWTProcessor<SimpleSecurityContext> getJwtProcessor() {
      ConfigurableJWTProcessor<SimpleSecurityContext> jwtProcessor = new DefaultJWTProcessor<SimpleSecurityContext>();
      JWKSource<SimpleSecurityContext> jweKeySource = new ImmutableSecret<SimpleSecurityContext>(
          key);
      JWEKeySelector<SimpleSecurityContext> jweKeySelector =
          new JWEDecryptionKeySelector<SimpleSecurityContext>(JWEAlgorithm.DIR,
              EncryptionMethod.A128CBC_HS256, jweKeySource);

      jwtProcessor.setJWEKeySelector(jweKeySelector);

      return jwtProcessor;
    }
  }
