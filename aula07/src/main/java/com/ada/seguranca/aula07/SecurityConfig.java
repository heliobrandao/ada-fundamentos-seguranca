package com.ada.seguranca.aula07;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * Configuração 100% Nativa do Spring Security 6 (Live Coding da Aula 07).
 *
 * Por que esta abordagem é muito mais limpa?
 * 1. NÃO precisamos escrever filtro manual (OncePerRequestFilter / JwtAuthenticationFilter)!
 *    O próprio ".oauth2ResourceServer(oauth2 -> oauth2.jwt(...))" ativa o BearerTokenAuthenticationFilter
 *    nativo do Spring, que lê "Authorization: Bearer <token>", valida assinatura/expiração e devolve 401!
 * 2. NÃO precisamos criar uma classe separada "UsuarioDetailsService": como UserDetailsService tem
 *    apenas 1 método (loadUserByUsername), declaramos como um @Bean lambda de 5 linhas!
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception         {
        return http
                // API Stateless com token em cabeçalho (sem cookie de sessão) -> seguro desabilitar CSRF
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.GET, "/publico").permitAll()
                        .requestMatchers(HttpMethod.POST, "/user", "/authenticate").permitAll()
                        .anyRequest().authenticated()
                )
                // ETAPA 1 DO LIVE CODING: Autenticação Básica (HTTP Basic) nativa
                .httpBasic(Customizer.withDefaults())
                // ETAPA 2 DO LIVE CODING: Validação de JWT nativa do Spring Security 6
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                .build();
    }

    // Ensina o Spring Security a buscar o usuário no nosso banco H2 via JPA:
    @Bean
    UserDetailsService userDetailsService(UsuarioRepository repo) {
        return username -> repo.findByUsername(username)
                .map(u -> User.withUsername(u.getUsername())
                        .password(u.getPassword())
                        .roles("USER")
                        .build())
                .orElseThrow(() -> new UsernameNotFoundException("Usuário não encontrado"));
    }

    // Hash de senha com sal aleatório embutido (BCrypt)
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Orquestrador do Spring que une o UserDetailsService + PasswordEncoder na hora do login
    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    // Decodificador nativo do Spring Security: valida assinatura HMAC-SHA256 (HS256) e expiração (exp)
    @Bean
    JwtDecoder jwtDecoder() {
        SecretKeySpec secretKey = new SecretKeySpec(jwtSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        return NimbusJwtDecoder.withSecretKey(secretKey)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();
    }

    // Codificador nativo do Spring Security: assina os tokens gerados no /authenticate
    @Bean
    JwtEncoder jwtEncoder() {
        SecretKeySpec secretKey = new SecretKeySpec(jwtSecret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        return new NimbusJwtEncoder(new ImmutableSecret<>(secretKey));
    }
}
