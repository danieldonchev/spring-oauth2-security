package app.oauth2authorization;

import app.User;
import app.UserPrincipal;
import app.jwt.JwtGenerator;
import java.util.Collection;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.endpoint.WebClientReactiveAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.userinfo.DefaultReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class Oauth2LoginAuthenticationManager implements ReactiveAuthenticationManager {

  private final ReactiveAuthenticationManager authorizationCodeManager;
  private final ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> userService;
  private final AuthRepository authRepository;
  private final JwtGenerator jwtGenerator;
  private GrantedAuthoritiesMapper authoritiesMapper = (authorities -> authorities);

  @Autowired
  public Oauth2LoginAuthenticationManager(AuthRepository authRepository, JwtGenerator jwtGenerator) {

    this.authRepository = authRepository;
    this.jwtGenerator = jwtGenerator;
    WebClientReactiveAuthorizationCodeTokenResponseClient client = new WebClientReactiveAuthorizationCodeTokenResponseClient();
    this.authorizationCodeManager = new OAuth2AuthorizationCodeReactiveAuthenticationManager(
        client);
    this.userService = new DefaultReactiveOAuth2UserService();
  }

  @Override
  public Mono<Authentication> authenticate(Authentication authentication) {
    return Mono.defer(() -> {
      OAuth2AuthorizationCodeAuthenticationToken token = (OAuth2AuthorizationCodeAuthenticationToken) authentication;

      return authorizationCodeManager.authenticate(token)
          .onErrorMap(OAuth2AuthorizationException.class,
              e -> new OAuth2AuthenticationException(e.getError(), e.getError().toString()))
          .cast(OAuth2AuthorizationCodeAuthenticationToken.class)
          .flatMap(this::onSuccess);
    });
  }

  private Mono<OAuth2LoginAuthenticationToken> onSuccess(
      OAuth2AuthorizationCodeAuthenticationToken authentication) {

    OAuth2AccessToken accessToken = authentication.getAccessToken();
    Map<String, Object> additionalParameters = authentication.getAdditionalParameters();
    OAuth2UserRequest userRequest = new OAuth2UserRequest(authentication.getClientRegistration(),
        accessToken, additionalParameters);

    return userService.loadUser(userRequest)
        .map(oauth2User -> {
          Collection<? extends GrantedAuthority> mappedAuthorities =
              this.authoritiesMapper.mapAuthorities(oauth2User.getAuthorities());

          UserPrincipal userPrincipal = new UserPrincipal();
          userPrincipal.setId("test-id");
          userPrincipal.setEmail("test-email");
          userPrincipal.setName("name");

          String generatedAccessToken = jwtGenerator.generateToken(userPrincipal);
          userPrincipal.setAccessToken(generatedAccessToken);

          OAuth2LoginAuthenticationToken authenticationResult = new OAuth2LoginAuthenticationToken(
              authentication.getClientRegistration(),
              authentication.getAuthorizationExchange(),
              userPrincipal,
              mappedAuthorities,
              accessToken,
              authentication.getRefreshToken());

          User user = new User("test-id", "test-name", "test-email");
          authRepository.findByEmail("test").subscribe(test -> {
            System.out.println(test);
          });
          authRepository.save(user).subscribe(test -> {
            System.out.println(test);
          });

          return authenticationResult;
        });
  }

}
