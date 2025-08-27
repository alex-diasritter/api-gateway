package com.alex.api_gateway.config; // Altere para o seu pacote
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Value("${keycloak.resource-id}")
    private String resourceId;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        http
                .authorizeExchange(exchanges -> exchanges
                        .anyExchange().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwtAuthenticationConverter(keycloakJwtTokenConverter())
                        )
                )
                .csrf(ServerHttpSecurity.CsrfSpec::disable);

        return http.build();
    }

    @Bean
    public Converter<Jwt, Mono<AbstractAuthenticationToken>> keycloakJwtTokenConverter() {
        return new KeycloakJwtTokenConverter(this.resourceId);
    }

    static class KeycloakJwtTokenConverter implements Converter<Jwt, Mono<AbstractAuthenticationToken>> {

        private final String resourceId;
        private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter;

        private static final String KEYCLOAK_RESOURCE_ACCESS = "resource_access";
        private static final String KEYCLOAK_REALM_ACCESS = "realm_access";
        private static final String KEYCLOAK_ROLES = "roles";
        private static final String KEYCLOAK_ROLE_PREFIX = "ROLE_";
        private static final String PRINCIPAL_ATTR = "preferred_username";

        public KeycloakJwtTokenConverter(String resourceId) {
            this.resourceId = resourceId;
            this.jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
        }

        @Override
        @NonNull
        public Mono<AbstractAuthenticationToken> convert(@NonNull Jwt jwt) {
            Map<String, Object> resourceAccess = jwt.getClaimAsMap(KEYCLOAK_RESOURCE_ACCESS);
            Collection<String> resourceAccessRoles = Collections.emptyList();
            if (resourceAccess != null && resourceAccess.get(resourceId) instanceof Map) {
                Map<String, Object> clientAccess = (Map<String, Object>) resourceAccess.get(resourceId);
                if (clientAccess.get(KEYCLOAK_ROLES) instanceof Collection) {
                    resourceAccessRoles = (Collection<String>) clientAccess.get(KEYCLOAK_ROLES);
                }
            }

            Map<String, Object> realmAccess = jwt.getClaimAsMap(KEYCLOAK_REALM_ACCESS);
            Collection<String> realmAccessRoles = Collections.emptyList();
            if (realmAccess != null && realmAccess.get(KEYCLOAK_ROLES) instanceof Collection) {
                realmAccessRoles = (Collection<String>) realmAccess.get(KEYCLOAK_ROLES);
            }

            Stream<GrantedAuthority> resourceRolesStream = resourceAccessRoles.stream()
                    .map(role -> new SimpleGrantedAuthority(KEYCLOAK_ROLE_PREFIX + role));

            Stream<GrantedAuthority> realmRolesStream = realmAccessRoles.stream()
                    .map(role -> new SimpleGrantedAuthority(KEYCLOAK_ROLE_PREFIX + role));

            Collection<GrantedAuthority> scopeAuthorities = jwtGrantedAuthoritiesConverter.convert(jwt);

            Set<GrantedAuthority> authorities = Stream.concat(
                    scopeAuthorities.stream(),
                    Stream.concat(resourceRolesStream, realmRolesStream)
            ).collect(Collectors.toSet());

            String principalClaimName = jwt.getClaimAsString(PRINCIPAL_ATTR);
            if (principalClaimName == null) {
                principalClaimName = jwt.getSubject();
            }

            return Mono.just(new JwtAuthenticationToken(jwt, authorities, principalClaimName));
        }
    }
}
