package com.ada.oauth;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Aula 04 (Tópicos 4 e 5): Playground do OAuth 2.0 (Papéis, Grant Types, PKCE e Escopos).
 *
 * Cenário da aula (o aplicativo de impressão de fotos "app-impressao"):
 *   1. POST /oauth/autorizar
 *      -> A Ana (Resource Owner) se autentica no Servidor de Autorização e consente que o
 *         "app-impressao" (Client) receba o escopo "fotos:leitura".
 *      -> Devolve um "code" de uso único (60s) e o mesmo "state" (anti-CSRF).
 *   2. POST /oauth/token (grantType = "authorization_code")
 *      -> O "app-impressao" troca o "code" (+ codeVerifier do PKCE) por um Access Token.
 *   3. GET  /oauth/recursos/fotos
 *      -> O Servidor de Recursos (API de fotos) confere o Access Token e o escopo "fotos:leitura" -> 200 OK.
 *   4. DELETE /oauth/recursos/fotos
 *      -> O "app-impressao" tenta apagar as fotos da Ana -> 403 Forbidden! O token só tem "fotos:leitura".
 *   5. POST /oauth/token (grantType = "client_credentials")
 *      -> O "servico-relatorios" (sem usuário!) se autentica com client_id e client_secret e
 *         acessa GET /oauth/recursos/relatorios.
 */
@RestController
@RequestMapping("/oauth")
public class OAuthPlaygroundController {

    public record AutorizarRequest(
            String username,
            String password,
            String clientId,
            String scope,
            String state,
            String codeChallenge
    ) {
    }

    public record TokenRequest(
            String grantType,
            String code,
            String clientId,
            String clientSecret,
            String codeVerifier,
            String scope
    ) {
    }

    private final OAuthSimuladorService oauthService;

    public OAuthPlaygroundController(OAuthSimuladorService oauthService) {
        this.oauthService = oauthService;
    }

    @PostMapping("/autorizar")
    public OAuthSimuladorService.AutorizacaoResponse autorizar(@RequestBody AutorizarRequest request) {
        if (request == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Corpo da requisição ausente.");
        }
        return oauthService.emitirCodigoDeAutorizacao(
                request.username(),
                request.password(),
                request.clientId(),
                request.scope(),
                request.state(),
                request.codeChallenge()
        );
    }

    @PostMapping("/token")
    public OAuthSimuladorService.OAuthTokenResponse token(@RequestBody TokenRequest request) {
        if (request == null || request.grantType() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Informe o grantType ('authorization_code' ou 'client_credentials').");
        }
        return switch (request.grantType()) {
            case "authorization_code" -> oauthService.trocarCodigoPorToken(
                    request.code(), request.clientId(), request.codeVerifier()
            );
            case "client_credentials" -> oauthService.emitirTokenClientCredentials(
                    request.clientId(), request.clientSecret(), request.scope()
            );
            default -> throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "grant_type não suportado ou legado: " + request.grantType()
            );
        };
    }

    @GetMapping("/recursos/fotos")
    public Map<String, Object> listarFotos(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestHeader(name = "access_token", required = false) String accessToken) {
        String token = AuthRefreshController.extrairToken(authorization, accessToken);
        DecodedJWT jwt = oauthService.exigirTokenComEscopo(token, "fotos:leitura");

        Map<String, Object> resposta = new LinkedHashMap<>();
        resposta.put("proprietarioDosDados", jwt.getSubject());
        resposta.put("clienteAutorizado", jwt.getClaim("client_id").asString());
        resposta.put("escoposDoToken", jwt.getClaim("scope").asString());
        resposta.put("fotos", List.of("viagem-porto.jpg", "formatura-ada.jpg", "cafe-da-manha.jpg"));
        return resposta;
    }

    @DeleteMapping("/recursos/fotos")
    public Map<String, String> apagarFotos(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestHeader(name = "access_token", required = false) String accessToken) {
        String token = AuthRefreshController.extrairToken(authorization, accessToken);
        // Exige o escopo "fotos:apagar": um token que só tem "fotos:leitura" é barrado com 403!
        DecodedJWT jwt = oauthService.exigirTokenComEscopo(token, "fotos:apagar");
        return Map.of("mensagem", "Fotos de " + jwt.getSubject() + " apagadas pelo cliente " + jwt.getClaim("client_id").asString());
    }

    @GetMapping("/recursos/relatorios")
    public Map<String, Object> gerarRelatorioSistema(
            @RequestHeader(name = "Authorization", required = false) String authorization,
            @RequestHeader(name = "access_token", required = false) String accessToken) {
        String token = AuthRefreshController.extrairToken(authorization, accessToken);
        DecodedJWT jwt = oauthService.exigirTokenComEscopo(token, "relatorios:leitura");

        return Map.of(
                "sistemaCliente", jwt.getClaim("client_id").asString(),
                "escopo", jwt.getClaim("scope").asString(),
                "relatorio", "Total de alunos ativos: 42"
        );
    }
}
