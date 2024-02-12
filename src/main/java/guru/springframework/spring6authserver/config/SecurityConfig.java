package guru.springframework.spring6authserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

// V229
// https://docs.spring.io/spring-authorization-server/reference/getting-started.html
@Configuration
public class SecurityConfig {
    @Bean
    @Order(1)   // Spring Security va a tener una * Chain of filters * y esto indica que deber ser el primero en ser configurado
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {

        // Setting UP the Authorization Server with Default Security
        // OAuth server va a exponer una serie de end points para obtener los tokens JWT, the public Key y la validación del token
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
        http
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                // Accept access tokens for User Info and/or Client Registration
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults()));

        return http.build();
    }

    // 230
    @Bean
    @Order(3)
    // Este segundo filtro es mas un * CATCH * de todo en el que se securiza todo lo demas
    // Requiere que all * Otras cosas * sean seguras salvo el * form de login *
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")).permitAll()
                )
                .headers(headers -> headers.frameOptions().disable())
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers(AntPathRequestMatcher.antMatcher("/h2-console/**")));
        return http.build();
    }

    // 231
    // Si nos redirecciona al Form Login, este es el * ÚNICO * usuario con acceso a dicho form
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }

    // V232
    // Creamos un repositorio de * Clientes Registrados * En este caso en * Memoria * SOLO PARA PRUEBAS
    // Creamos un Cliente Resgistrado con su clientID y su Client Secret * NO ENCRIPTADO * SOLO PARA PRUEBAS
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("oidc-client")
                // TRAZAS
                // 2024-02-07T16:21:38.529+01:00  WARN 25420 --- [main] o.s.security.core.userdetails.User: User.withDefaultPasswordEncoder() is considered unsafe for production and is only intended for sample applications.
                // https://docs.spring.io/spring-security/reference/features/authentication/password-storage.html#authentication-password-storage-dpe-encoding
                // https://www.baeldung.com/spring-security-5-default-password-encoder#2-nooppasswordencoder
                // he default PasswordEncoder is built as a DelegatingPasswordEncoder.
                // When you store the users in memory, you are providing the passwords in plain text and when trying to retrieve the encoder
                // from the DelegatingPasswordEncoder to validate the password it can't find one that matches the way in which these passwords were stored.
                // Use this way to create users instead.
                // User.withDefaultPasswordEncoder().username("user").password("user").roles("USER").build();

                // You can also simply prefix {noop} to your passwords in order for the DelegatingPasswordEncoder use the NoOpPasswordEncoder to validate these passwords. Notice that NoOpPasswordEncoder is deprecated though, as it is not a good practice to store passwords in plain text.
                // User.withUsername("user").password("{noop}user").roles("USER").build();
                //For more information, check this post.
                //https://spring.io/blog/2017/11/01/spring-security-5-0-0-rc1-released#password-encoding
                .clientSecret("{noop}secret")
                //.clientSecret(passwordEncoder().encode("secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:9000/login/oauth2/code/oidc-client")
                .redirectUri("http://127.0.0.1:9000/autorized")
                .postLogoutRedirectUri("http://127.0.0.1:9000/") // version 1.2.1
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("message.read")
                .scope("message.write")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        // En vez de crearlo en memoria, Spring Authorization Server se puede usar con una JDBC Database para almacenar los clientes registrados
        return new InMemoryRegisteredClientRepository(oidcClient);
    }

    // V233
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    // V235
    // https://docs.spring.io/spring-authorization-server/reference/configuration-model.html#configuring-authorization-server-settings
    // return new Builder()
    //			.authorizationEndpoint("/oauth2/authorize")
    //			.deviceAuthorizationEndpoint("/oauth2/device_authorization")
    //			.deviceVerificationEndpoint("/oauth2/device_verification")
    //			.tokenEndpoint("/oauth2/token")
    //			.tokenIntrospectionEndpoint("/oauth2/introspect")
    //			.tokenRevocationEndpoint("/oauth2/revoke")
    //			.jwkSetEndpoint("/oauth2/jwks")
    //			.oidcLogoutEndpoint("/connect/logout")
    //			.oidcUserInfoEndpoint("/userinfo")
    //			.oidcClientRegistrationEndpoint("/connect/register");
    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
