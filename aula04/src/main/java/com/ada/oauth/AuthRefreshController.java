package com.ada.oauth;

import com.ada.jwt.UsuariosDemo;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Aula 04 (Tópico 6): Endpoints de demonstração do fluxo Access Token + Refresh Token.
 *
 * Fluxo completo para demonstrar em sala (http/aula04.http):
 *   1. POST /auth/login    -> devolve { accessToken (15m), refreshToken (7d) }
 *   2. GET  /auth/me       -> 200 OK com o accessToken (se mandar o refreshToken aqui, dá 401!)
 *   3. POST /auth/refresh  -> invalida o refreshToken enviado e devolve um PAR NOVO
 *   4. POST /auth/refresh  -> (com o refreshToken ANTIGO já usado) -> 401 + revoga TODOS os tokens da usuária!
 *   5. POST /auth/logout   -> 204 No Content (revoga o refreshToken; não dá mais para renovar)
 */
@RestController
@RequestMapping("/auth")
public class AuthRefreshController {

    public record LoginRequest(String username, String password) {
    }

    public record RefreshRequest(String refreshToken) {
    }

    private final UsuariosDemo usuarios;
    private final TokenParService tokenParService;

    public AuthRefreshController(UsuariosDemo usuarios, TokenParService tokenParService) {
        this.usuarios = usuarios;
        this.tokenParService = tokenParService;
    }

    @PostMapping("/login")
    public TokenParService.ParDeTokens login(@RequestBody LoginRequest request) {
        UsuariosDemo.Usuario usuario = usuarios.autenticar(request.username(), request.password())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Usuário ou senha inválidos."));
        return tokenParService.emitirPar(usuario.username(), usuario.perfil());
    }

    @GetMapping("/me")
    public Map<String, Object> me(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestHeader(name = "access_token", required = false) String accessToken) {
        String token = extrairToken(authorization, accessToken);
        DecodedJWT jwt = tokenParService.validarAccessToken(token == null ? "" : token);

        Map<String, Object> resposta = new LinkedHashMap<>();
        resposta.put("usuario", jwt.getSubject());
        resposta.put("perfil", jwt.getClaim("role").asString());
        resposta.put("token_use", jwt.getClaim(TokenParService.CLAIM_TIPO).asString());
        resposta.put("expiraEm", jwt.getExpiresAtAsInstant().getEpochSecond());
        return resposta;
    }

    @GetMapping("/admin/painel")
    public Map<String, String> painelAdmin(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestHeader(name = "access_token", required = false) String accessToken) {
        String token = extrairToken(authorization, accessToken);
        DecodedJWT jwt = tokenParService.validarAccessToken(token == null ? "" : token);

        if (!"ADMIN".equals(jwt.getClaim("role").asString())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Acesso negado: exige perfil ADMIN.");
        }
        return Map.of("mensagem", "Painel administrativo acessado por " + jwt.getSubject());
    }

    @PostMapping("/refresh")
    public TokenParService.ParDeTokens refresh(@RequestBody RefreshRequest request) {
        return tokenParService.renovar(request == null ? null : request.refreshToken());
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody RefreshRequest request) {
        tokenParService.revogarNoLogout(request == null ? null : request.refreshToken());
        return ResponseEntity.noContent().build();
    }

    static String extrairToken(String authorization, String accessToken) {
        if (authorization != null && authorization.startsWith("Bearer ")) {
            return authorization.substring(7);
        }
        return accessToken;
    }
}
