package com.ada.seguranca.aula07;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Map;

@RestController
public class AuthController {

    public record LoginRequest(String username, String password) {}
    public record UsuarioCriadoResponse(Long id, String username) {}
    public record TokenResponse(String token) {}

    private final UsuarioRepository repo;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authManager;
    private final JwtEncoder jwtEncoder;

    public AuthController(
            UsuarioRepository repo,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authManager,
            JwtEncoder jwtEncoder) {
        this.repo = repo;
        this.passwordEncoder = passwordEncoder;
        this.authManager = authManager;
        this.jwtEncoder = jwtEncoder;
    }

    // 1. Rota pública (permitAll no SecurityConfig)
    @GetMapping("/publico")
    public Map<String, String> publico() {
        return Map.of("mensagem", "Rota pública: qualquer pessoa acessa sem precisar de login!");
    }

    // 2. Cadastro de usuário (UC1 do Projeto Final): grava o HASH BCrypt e nunca devolve a senha!
    @PostMapping("/user")
    public ResponseEntity<UsuarioCriadoResponse> cadastrar(@RequestBody LoginRequest req) {
        if (repo.findByUsername(req.username()).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Nome de usuário já está em uso.");
        }
        String hashBcrypt = passwordEncoder.encode(req.password());
        Usuario salvo = repo.save(new Usuario(req.username(), hashBcrypt));
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new UsuarioCriadoResponse(salvo.getId(), salvo.getUsername()));
    }

    // 3. Autenticação e emissão do JWT (UC2 do Projeto Final)
    @PostMapping("/authenticate")
    public TokenResponse autenticar(@RequestBody LoginRequest req) {
        // O AuthenticationManager chama nosso UserDetailsService + PasswordEncoder.matches() automaticamente!
        Authentication auth = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(req.username(), req.password())
        );

        Instant agora = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("ada-aula07")
                .subject(auth.getName())
                .issuedAt(agora)
                .expiresAt(agora.plusSeconds(3600)) // 1 hora de validade
                .build();

        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        String token = jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();

        return new TokenResponse(token);
    }

    // 4. Rota protegida: funciona tanto com Basic Auth (Etapa 1) quanto com Bearer JWT (Etapa 2)!
    @GetMapping("/perfil")
    public Map<String, String> perfil(Authentication auth) {
        return Map.of(
                "usuarioAutenticado", auth.getName(),
                "mensagem", "Acesso autorizado pelo Spring Security!"
        );
    }

    // Mesma mensagem para "usuário não existe" e "senha errada" (evita enumeração de usuários!)
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<Map<String, Object>> credenciaisInvalidas() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of(
                        "status", 401,
                        "erro", "Unauthorized",
                        "mensagem", "Usuário ou senha inválidos."
                ));
    }
}
