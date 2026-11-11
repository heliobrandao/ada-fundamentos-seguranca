package com.ada.oauth;

import com.ada.criptografia.cripto.FuncaoHash;
import com.ada.jwt.JwtManual;
import com.ada.jwt.UsuariosDemo;
import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Aula 04 (Tópicos 4 e 5): Simulador didático dos fluxos do OAuth 2.0:
 *   1. Authorization Code (+ PKCE e state): quando HÁ um usuário (Resource Owner) autorizando um app (Client).
 *   2. Client Credentials: quando NÃO há usuário (sistema falando com sistema, M2M).
 *   3. Validação de Escopo (Scope) no Resource Server: o token abre só a porta permitida ("fotos:leitura"),
 *      e recebe 403 se tentar algo fora do escopo ("fotos:apagar").
 */
@Service
public class OAuthSimuladorService {

    public static final String CLAIM_USO_OAUTH = "oauth_access";
    private static final long VALIDADE_CODIGO_SEGUNDOS = 300;
    private static final long VALIDADE_TOKEN_OAUTH_SEGUNDOS = 15 * 60;

    /** Clientes cadastrados no Servidor de Autorização. */
    private static final Set<String> CLIENTES_PUBLICOS_OU_WEB = Set.of("app-impressao", "portal-parceiro");
    private static final Map<String, String> CLIENTES_M2M_SEGREDOS = Map.of(
            "servico-relatorios", "segredo-relatorios-123"
    );

    /** Código de autorização temporário e de USO ÚNICO. */
    public record CodigoAutorizacao(
            String code,
            String username,
            String clientId,
            String scope,
            String codeChallenge,
            Instant expiraEm,
            boolean usado
    ) {
        public CodigoAutorizacao marcarComoUsado() {
            return new CodigoAutorizacao(code, username, clientId, scope, codeChallenge, expiraEm, true);
        }
    }

    public record AutorizacaoResponse(String code, String state, String clientId, String scope, long expiraEmSegundos) {
    }

    public record OAuthTokenResponse(String accessToken, String tokenType, long expiresIn, String scope, String grantType) {
    }

    private final UsuariosDemo usuarios;
    private final FuncaoHash funcaoHash;
    private final Algorithm algoritmo;
    private final Map<String, CodigoAutorizacao> codigosEmitidos = new ConcurrentHashMap<>();

    public OAuthSimuladorService(UsuariosDemo usuarios, FuncaoHash funcaoHash, JwtManual manual) {
        this.usuarios = usuarios;
        this.funcaoHash = funcaoHash;
        this.algoritmo = Algorithm.HMAC256(manual.chavePadrao());
    }

    /**
     * Passo 1 do Authorization Code: o Proprietário do Recurso (usuário) se autentica no
     * Servidor de Autorização (NUNCA no app cliente!) e aprova o escopo pedido pelo cliente.
     * Devolve um "code" de uso único (60s) e devolve o mesmo "state" (proteção contra CSRF).
     */
    public AutorizacaoResponse emitirCodigoDeAutorizacao(
            String username,
            String password,
            String clientId,
            String scope,
            String state,
            String codeChallenge) {

        if (clientId == null || !CLIENTES_PUBLICOS_OU_WEB.contains(clientId)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "client_id desconhecido: " + clientId);
        }
        if (scope == null || scope.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Informe o escopo (scope) solicitado.");
        }
        if (state == null || state.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "O parâmetro 'state' é obrigatório para prevenir CSRF no fluxo OAuth.");
        }

        UsuariosDemo.Usuario usuario = usuarios.autenticar(username, password)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Credenciais do proprietário do recurso inválidas."));

        String code = "code_" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
        Instant expiraEm = Instant.now().plusSeconds(VALIDADE_CODIGO_SEGUNDOS);

        codigosEmitidos.put(code, new CodigoAutorizacao(
                code, usuario.username(), clientId, scope.trim(),
                (codeChallenge == null || codeChallenge.isBlank()) ? null : codeChallenge.trim(),
                expiraEm, false
        ));

        return new AutorizacaoResponse(code, state, clientId, scope.trim(), VALIDADE_CODIGO_SEGUNDOS);
    }

    /**
     * Passo 2 do Authorization Code: o Cliente troca o "code" pelo Access Token no endpoint /oauth/token.
     * Se o código foi emitido com PKCE (codeChallenge), exige o codeVerifier original!
     */
    public OAuthTokenResponse trocarCodigoPorToken(String code, String clientId, String codeVerifier) {
        if (code == null || code.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Informe o código de autorização (code).");
        }
        CodigoAutorizacao registro = codigosEmitidos.get(code.trim());
        if (registro == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Código de autorização inválido.");
        }
        if (registro.usado()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Código de autorização já foi utilizado (é de uso único).");
        }
        if (Instant.now().isAfter(registro.expiraEm())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Código de autorização expirado.");
        }
        if (!registro.clientId().equals(clientId)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "O código pertence a outro client_id.");
        }

        // Validação do PKCE: sha256(codeVerifier) precisa bater com o codeChallenge enviado no início!
        if (registro.codeChallenge() != null) {
            if (codeVerifier == null || codeVerifier.isBlank()) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "PKCE obrigatório: informe o code_verifier.");
            }
            String hashCalculado = funcaoHash.sha256(codeVerifier.trim());
            if (!registro.codeChallenge().equalsIgnoreCase(hashCalculado)) {
                throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "PKCE inválido: o SHA-256 do code_verifier não bate com o code_challenge.");
            }
        }

        // Código vale UMA única vez
        codigosEmitidos.put(registro.code(), registro.marcarComoUsado());

        String token = gerarTokenOAuth(registro.username(), registro.clientId(), registro.scope());
        return new OAuthTokenResponse(token, "Bearer", VALIDADE_TOKEN_OAUTH_SEGUNDOS, registro.scope(), "authorization_code");
    }

    /**
     * Grant Type: Client Credentials (sistema a sistema, SEM usuário final).
     */
    public OAuthTokenResponse emitirTokenClientCredentials(String clientId, String clientSecret, String scope) {
        String segredoEsperado = clientId == null ? null : CLIENTES_M2M_SEGREDOS.get(clientId);
        if (segredoEsperado == null || !segredoEsperado.equals(clientSecret)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "client_id ou client_secret inválidos.");
        }
        String escopoFinal = (scope == null || scope.isBlank()) ? "relatorios:leitura" : scope.trim();
        // Não há usuário final: o próprio serviço cliente é o "sub"
        String token = gerarTokenOAuth(clientId, clientId, escopoFinal);
        return new OAuthTokenResponse(token, "Bearer", VALIDADE_TOKEN_OAUTH_SEGUNDOS, escopoFinal, "client_credentials");
    }

    /**
     * Valida o Access Token no Servidor de Recursos (Resource Server) e confere se o escopo
     * exigido pela rota está presente dentro da claim "scope" do token!
     */
    public DecodedJWT exigirTokenComEscopo(String token, String escopoExigido) {
        if (token == null || token.isBlank()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token de acesso ausente.");
        }
        DecodedJWT jwt;
        try {
            jwt = JWT.require(algoritmo)
                    .withIssuer(JwtManual.EMISSOR)
                    .withClaim(TokenParService.CLAIM_TIPO, CLAIM_USO_OAUTH)
                    .build()
                    .verify(token.trim());
        } catch (JWTVerificationException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token de acesso inválido ou expirado.");
        }

        String escoposNoToken = jwt.getClaim("scope").asString();
        List<String> listaEscopos = escoposNoToken == null
                ? List.of()
                : Arrays.asList(escoposNoToken.split("[\\s,]+"));

        if (!listaEscopos.contains(escopoExigido)) {
            throw new ResponseStatusException(
                    HttpStatus.FORBIDDEN,
                    "Escopo insuficiente: o token possui [" + escoposNoToken + "], mas esta ação exige '" + escopoExigido + "'."
            );
        }
        return jwt;
    }

    private String gerarTokenOAuth(String subject, String clientId, String scope) {
        Instant agora = Instant.now();
        return JWT.create()
                .withIssuer(JwtManual.EMISSOR)
                .withSubject(subject)
                .withClaim("client_id", clientId)
                .withClaim("scope", scope)
                .withClaim(TokenParService.CLAIM_TIPO, CLAIM_USO_OAUTH)
                .withIssuedAt(agora)
                .withExpiresAt(agora.plusSeconds(VALIDADE_TOKEN_OAUTH_SEGUNDOS))
                .sign(algoritmo);
    }
}
