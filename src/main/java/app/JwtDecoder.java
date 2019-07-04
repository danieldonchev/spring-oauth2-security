package app;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.core.publisher.Mono;

public class JwtDecoder implements ReactiveJwtDecoder {


  @Override
  public Mono<Jwt> decode(String token) throws JwtException {
    return null;
  }
}
