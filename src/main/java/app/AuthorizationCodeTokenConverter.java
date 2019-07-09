package app;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionOAuth2ServerAuthorizationRequestRepository;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.util.Assert;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

public class AuthorizationCodeTokenConverter
		implements ServerAuthenticationConverter {

	static final String AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE = "authorization_request_not_found";

	static final String CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE = "client_registration_not_found";

	private ServerAuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository =
			new AuthorizationRequestRepository();

	private final ReactiveClientRegistrationRepository clientRegistrationRepository;

	public AuthorizationCodeTokenConverter(
			ReactiveClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	@Override
	public Mono<Authentication> convert(ServerWebExchange serverWebExchange) {
		return this.authorizationRequestRepository.removeAuthorizationRequest(serverWebExchange)
				.switchIfEmpty(oauth2AuthorizationException(AUTHORIZATION_REQUEST_NOT_FOUND_ERROR_CODE))
				.flatMap(
						authorizationRequest -> authenticationRequest(serverWebExchange, authorizationRequest));
	}

	private <T> Mono<T> oauth2AuthorizationException(String errorCode) {
		return Mono.defer(() -> {
			OAuth2Error oauth2Error = new OAuth2Error(errorCode);
			return Mono.error(new OAuth2AuthorizationException(oauth2Error));
		});
	}

	private Mono<OAuth2AuthorizationCodeAuthenticationToken> authenticationRequest(
			ServerWebExchange exchange, OAuth2AuthorizationRequest authorizationRequest) {
		return Mono.just(authorizationRequest)
				.map(OAuth2AuthorizationRequest::getAttributes)
				.flatMap(additionalParams -> {
					String id = (String) additionalParams.get(OAuth2ParameterNames.REGISTRATION_ID);
					if (id == null) {
						return oauth2AuthorizationException(CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE);
					}
					return this.clientRegistrationRepository.findByRegistrationId(id);
				})
				.switchIfEmpty(oauth2AuthorizationException(CLIENT_REGISTRATION_NOT_FOUND_ERROR_CODE))
				.map(clientRegistration -> {
					OAuth2AuthorizationResponse authorizationResponse = convertResponse(exchange);
					OAuth2AuthorizationCodeAuthenticationToken authenticationRequest = new OAuth2AuthorizationCodeAuthenticationToken(
							clientRegistration,
							new OAuth2AuthorizationExchange(authorizationRequest, authorizationResponse));
					return authenticationRequest;
				});
	}

	private static OAuth2AuthorizationResponse convertResponse(ServerWebExchange exchange) {
		MultiValueMap<String, String> queryParams = exchange.getRequest()
				.getQueryParams();
		String redirectUri = UriComponentsBuilder.fromUri(exchange.getRequest().getURI())
				.query(null)
				.build()
				.toUriString();

		return convert(queryParams, redirectUri);
	}

	static OAuth2AuthorizationResponse convert(MultiValueMap<String, String> request, String redirectUri) {
		String code = request.getFirst(OAuth2ParameterNames.CODE);
		String errorCode = request.getFirst(OAuth2ParameterNames.ERROR);
		String state = request.getFirst(OAuth2ParameterNames.STATE);

		if (StringUtils.hasText(code)) {
			return OAuth2AuthorizationResponse.success(code)
					.redirectUri(redirectUri)
					.state(state)
					.build();
		} else {
			String errorDescription = request.getFirst(OAuth2ParameterNames.ERROR_DESCRIPTION);
			String errorUri = request.getFirst(OAuth2ParameterNames.ERROR_URI);
			return OAuth2AuthorizationResponse.error(errorCode)
					.redirectUri(redirectUri)
					.errorDescription(errorDescription)
					.errorUri(errorUri)
					.state(state)
					.build();
		}
	}
}
