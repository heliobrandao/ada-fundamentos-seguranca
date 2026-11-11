package com.ada.oauth;

import com.ada.jwt.JwtManual;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Aula 04 (Tópico 6): Par ACCESS TOKEN + REFRESH TOKEN com ROTAÇÃO e DETECÇÃO DE REUSO.
 *
 * Por que ter DOIS tokens em vez de um só?
 *   - Access Token: vai em TODA requisição. É stateless (não consulta banco), mas dura pouco
 *     (15 minutos) para limitar o estrago caso seja roubado.
 *   - Refresh Token: só vai ao endpoint /auth/refresh (e /auth/logout). Dura mais (7 dias) e
 *     tem seu identificador ("jti") guardado no servidor, podendo ser REVOGADO a qualquer momento.
 *
 * ROTEIRO PARA EXPLICAR À TURMA:
 *   1. Claim "token_use": impede que alguém use um Refresh Token como se fosse Access Token
 *      para chamar endpoints da API (ou vice-versa).
 *   2. Rotação (uso único): cada vez que o cliente renova em /auth/refresh, o Refresh Token
 *      usado é marcado como revogado e nasce um PAR NOVO.
 *   3. Detecção de reuso (alarme de roubo): se alguém apresentar um Refresh Token que JÁ FOI
 *      USADO, sabemos que houve cópia/roubo -> revogamos TODOS os tokens daquele usuário!
 */
@Service
public class TokenParService {

    private static final Logger log = LoggerFactory.getLogger(TokenParService.class);

    public static final String CLAIM_TIPO = "token_use";
    public static final String TIPO_ACCESS = "access";
    public static final String TIPO_REFRESH = "refresh";

    // Access token vive 15 minutos (900 s); Refresh token vive 7 dias (604.800 s).
    public static final long VALIDADE_ACCESS_SEGUNDOS = 15 * 60;
    public static final long VALIDADE_REFRESH_SEGUNDOS = 7 * 24 * 60 * 60;

    /** Par devolvido no login e na renovação. */
    public record ParDeTokens(String accessToken, String refreshToken, long accessExpiraEmSegundos) {
    }

    /** Estado do Refresh Token guardado no servidor (em produção, seria uma tabela no banco). */
    public record RegistroRefresh(String jti, String username, String perfil, Instant expiraEm, boolean revogado) {
        public RegistroRefresh revogar() {
            return new RegistroRefresh(jti, username, perfil, expiraEm, true);
        }
    }

    private final Algorithm algoritmo;
    // jti -> RegistroRefresh (simula a tabela refresh_tokens do banco de dados)
    private final Map<String, RegistroRefresh> bancoRefresh = new ConcurrentHashMap<>();

    public TokenParService(JwtManual manual) {
        this.algoritmo = Algorithm.HMAC256(manual.chavePadrao());
    }

    /** Emite um novo par (Access Token + Refresh Token) e registra o jti do Refresh no servidor. */
    public ParDeTokens emitirPar(String username, String perfil) {
        Instant agora = Instant.now();

        String accessToken = JWT.create()
                .withIssuer(JwtManual.EMISSOR)
                .withSubject(username)
                .withClaim("role", perfil)
                .withClaim(CLAIM_TIPO, TIPO_ACCESS)
                .withIssuedAt(agora)
                .withExpiresAt(agora.plusSeconds(VALIDADE_ACCESS_SEGUNDOS))
                .sign(algoritmo);

        String jti = UUID.randomUUID().toString();
        Instant expiraRefresh = agora.plusSeconds(VALIDADE_REFRESH_SEGUNDOS);

        String refreshToken = JWT.create()
                .withIssuer(JwtManual.EMISSOR)
                .withSubject(username)
                .withJWTId(jti)
                .withClaim(CLAIM_TIPO, TIPO_REFRESH)
                .withIssuedAt(agora)
                .withExpiresAt(expiraRefresh)
                .sign(algoritmo);

        bancoRefresh.put(jti, new RegistroRefresh(jti, username, perfil, expiraRefresh, false));
        return new ParDeTokens(accessToken, refreshToken, VALIDADE_ACCESS_SEGUNDOS);
    }

    /** Valida um Access Token (exige token_use = "access"). */
    public DecodedJWT validarAccessToken(String token) {
        try {
            return verificador(TIPO_ACCESS).verify(token);
        } catch (JWTVerificationException e) {
            log.info("Access token recusado: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Não autenticado.");
        }
    }

    /**
     * Usa um Refresh Token para emitir um par novo (ROTAÇÃO).
     * Se o Refresh Token já tiver sido usado antes, dispara o alarme de REUSO e revoga tudo do usuário.
     */
    public ParDeTokens renovar(String refreshToken) {
        DecodedJWT jwt = validarFormatoRefresh(refreshToken);
        String jti = jwt.getId();
        RegistroRefresh registro = jti == null ? null : bancoRefresh.get(jti);

        if (registro == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token desconhecido.");
        }

        // DETECÇÃO DE REUSO: o token tem assinatura válida e não expirou, mas JÁ FOI USADO/REVOGADO!
        if (registro.revogado()) {
            int totalRevogados = revogarTodosDoUsuario(registro.username());
            log.warn("ALERTA DE SEGURANÇA: Reuso de refresh token detectado para o usuário '{}'. {} token(s) ativo(s) foram revogados!",
                    registro.username(), totalRevogados);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token já utilizado ou revogado.");
        }

        // ROTAÇÃO: marca o refresh token atual como usado/revogado e emite um par novinho
        bancoRefresh.put(jti, registro.revogar());
        return emitirPar(registro.username(), registro.perfil());
    }

    /** Revoga um Refresh Token no logout. */
    public void revogarNoLogout(String refreshToken) {
        DecodedJWT jwt = validarFormatoRefresh(refreshToken);
        String jti = jwt.getId();
        if (jti != null) {
            bancoRefresh.computeIfPresent(jti, (k, atual) -> atual.revogar());
        }
    }

    private DecodedJWT validarFormatoRefresh(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Informe o refreshToken.");
        }
        try {
            return verificador(TIPO_REFRESH).verify(refreshToken.trim());
        } catch (JWTVerificationException e) {
            log.info("Refresh token inválido: {}", e.getMessage());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token inválido ou expirado.");
        }
    }

    private int revogarTodosDoUsuario(String username) {
        int cont = 0;
        for (Map.Entry<String, RegistroRefresh> entry : bancoRefresh.entrySet()) {
            RegistroRefresh reg = entry.getValue();
            if (username.equals(reg.username()) && !reg.revogado()) {
                entry.setValue(reg.revogar());
                cont++;
            }
        }
        return cont;
    }

    private JWTVerifier verificador(String tipoEsperado) {
        // Algoritmo fixado no servidor (HS256), bloqueando "alg: none".
        // Além do "iss" e do "exp", exige o "token_use" correto ("access" OU "refresh").
        return JWT.require(algoritmo)
                .withIssuer(JwtManual.EMISSOR)
                .withClaim(CLAIM_TIPO, tipoEsperado)
                .build();
    }
}
