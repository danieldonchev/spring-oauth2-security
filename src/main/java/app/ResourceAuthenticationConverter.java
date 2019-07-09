//package app;
//
//import org.springframework.http.server.reactive.ServerHttpRequest;
//import org.springframework.security.core.Authentication;
//import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
//import org.springframework.security.oauth2.core.user.OAuth2User;
//import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
//import org.springframework.stereotype.Component;
//import org.springframework.util.StringUtils;
//import org.springframework.web.server.ServerWebExchange;
//import reactor.core.publisher.Mono;
//
//@Component
//public class ResourceAuthenticationConverter implements ServerAuthenticationConverter {
//
//  @Override
//  public Mono<Authentication> convert(ServerWebExchange exchange) {
//
//    return Mono.fromCallable(() -> {
//      String bearerToken = getBearerTokenFromRequest(exchange.getRequest());
//
//      OAuth2User user = new User("name", bearerToken);
//
//      Authentication authentication = new OAuth2AuthenticationToken(user, null, "facebook");
//      return authentication;
//    });
//  }
//
//  private String getBearerTokenFromRequest(ServerHttpRequest request) {
//    String bearerToken = request.getHeaders().getFirst("Authorization");
//    if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
//      return bearerToken.substring(7, bearerToken.length());
//    }
//    return null;
//  }
//}
