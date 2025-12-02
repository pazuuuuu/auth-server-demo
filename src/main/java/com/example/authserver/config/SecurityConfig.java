package com.example.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
        http
            // Redirect to the login page when not authenticated from the
            // authorization endpoint
            .exceptionHandling((exceptions) -> exceptions
                .defaultAuthenticationEntryPointFor(
                    new LoginUrlAuthenticationEntryPoint(SecurityConstants.LOGIN_URL),
                    new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                )
            )
            // Accept access tokens for User Info and/or Client Registration
            .oauth2ResourceServer((resourceServer) -> resourceServer
                .jwt(Customizer.withDefaults()));

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
            .authorizeHttpRequests((authorize) -> authorize
                .requestMatchers(
                    SecurityConstants.LOGIN_URL, 
                    SecurityConstants.CSS_Resources, 
                    SecurityConstants.IMAGES_Resources, 
                    SecurityConstants.ERROR_URL, 
                    SecurityConstants.FORGOT_PASSWORD_PREFIX, 
                    SecurityConstants.RESET_PASSWORD_PREFIX, 
                    SecurityConstants.WEBAUTHN_PREFIX, 
                    SecurityConstants.LOGIN_WEBAUTHN_PREFIX
                ).permitAll()
                .anyRequest().authenticated()
            )
            .csrf(csrf -> csrf.ignoringRequestMatchers(
                SecurityConstants.FORGOT_PASSWORD_PREFIX, 
                SecurityConstants.RESET_PASSWORD_PREFIX
            ))
            // Form login handles the redirect to the login page from the
            // authorization server filter chain
            .formLogin(form -> form
                .loginPage(SecurityConstants.LOGIN_URL)
                .permitAll()
            )
            .webAuthn(webAuthn -> webAuthn
                .rpName(SecurityConstants.RP_NAME)
                .rpId(SecurityConstants.RP_ID)
                .allowedOrigins(SecurityConstants.ALLOWED_ORIGIN)
            ); // Enable WebAuthn with explicit RP settings

        return http.build();
    }

    @Bean
    public org.springframework.security.web.webauthn.management.UserCredentialRepository userCredentialRepository() {
        return new org.springframework.security.web.webauthn.management.MapUserCredentialRepository();
    }

}
