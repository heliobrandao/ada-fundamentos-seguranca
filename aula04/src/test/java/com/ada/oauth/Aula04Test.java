package com.ada.oauth;

import com.ada.criptografia.cripto.FuncaoHash;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.nio.charset.StandardCharsets;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = Main.class)
@AutoConfigureMockMvc
class Aula04Test {

    @Autowired
    private MockMvc mvc;
    @Autowired
    private ObjectMapper json;
    @Autowired
    private FuncaoHash funcaoHash;

    private ResultActions postJson(String caminho, Object corpo) throws Exception {
        return mvc.perform(post(caminho).contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(corpo)));
    }

    private JsonNode corpoDe(ResultActions acao) throws Exception {
        return json.readTree(acao.andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    // ------------------------------------ OAuth 2.0: Authorization Code + PKCE e Escopos

    @Test
    void fluxoAuthorizationCodeComPkceEEscopoLimitadoFuncionaEBloqueiaAcaoForaDoEscopo() throws Exception {
        String codeVerifier = "meu-segredo-pkce-123";
        String codeChallenge = funcaoHash.sha256(codeVerifier);

        // 1) Autorizar no Authorization Server
        JsonNode autorizacao = corpoDe(postJson("/oauth/autorizar", Map.of(
                "username", "ana",
                "password", "senha123",
                "clientId", "app-impressao",
                "scope", "fotos:leitura",
                "state", "xyz-123",
                "codeChallenge", codeChallenge
        )).andExpect(status().isOk()));

        String code = autorizacao.get("code").asText();
        assertThat(autorizacao.get("state").asText()).isEqualTo("xyz-123");

        // 2) Tentativa de troca com codeVerifier errado falha (PKCE protege o código!)
        postJson("/oauth/token", Map.of(
                "grantType", "authorization_code",
                "code", code,
                "clientId", "app-impressao",
                "codeVerifier", "verifier-errado"
        )).andExpect(status().isUnauthorized());

        // 3) Troca com o codeVerifier correto devolve o Access Token
        JsonNode tokenResp = corpoDe(postJson("/oauth/token", Map.of(
                "grantType", "authorization_code",
                "code", code,
                "clientId", "app-impressao",
                "codeVerifier", codeVerifier
        )).andExpect(status().isOk()));

        String oauthToken = tokenResp.get("accessToken").asText();

        // 4) O mesmo código não pode ser usado uma segunda vez
        postJson("/oauth/token", Map.of(
                "grantType", "authorization_code",
                "code", code,
                "clientId", "app-impressao",
                "codeVerifier", codeVerifier
        )).andExpect(status().isUnauthorized());

        // 5) Ler fotos (escopo fotos:leitura) -> 200 OK
        mvc.perform(get("/oauth/recursos/fotos").header("Authorization", "Bearer " + oauthToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.proprietarioDosDados").value("ana"))
                .andExpect(jsonPath("$.clienteAutorizado").value("app-impressao"));

        // 6) Apagar fotos (exige fotos:apagar) -> 403 Forbidden (Escopo insuficiente!)
        mvc.perform(delete("/oauth/recursos/fotos").header("Authorization", "Bearer " + oauthToken))
                .andExpect(status().isForbidden());
    }

    @Test
    void fluxoClientCredentialsAutenticaSistemaSemUsuario() throws Exception {
        JsonNode tokenResp = corpoDe(postJson("/oauth/token", Map.of(
                "grantType", "client_credentials",
                "clientId", "servico-relatorios",
                "clientSecret", "segredo-relatorios-123",
                "scope", "relatorios:leitura"
        )).andExpect(status().isOk()));

        String tokenM2M = tokenResp.get("accessToken").asText();

        mvc.perform(get("/oauth/recursos/relatorios").header("Authorization", "Bearer " + tokenM2M))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.sistemaCliente").value("servico-relatorios"));
    }

    // ----------------------------- Access Token + Refresh Token, Rotação e Reuso

    @Test
    void accessTokenAbreRotaProtegidaERefreshTokenNaoSePassaPorAccessToken() throws Exception {
        JsonNode login = corpoDe(postJson("/auth/login", Map.of("username", "ana", "password", "senha123"))
                .andExpect(status().isOk()));

        String accessToken = login.get("accessToken").asText();
        String refreshToken = login.get("refreshToken").asText();

        mvc.perform(get("/auth/me").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.usuario").value("ana"))
                .andExpect(jsonPath("$.token_use").value("access"));

        // Refresh token enviado como se fosse access token -> 401
        mvc.perform(get("/auth/me").header("Authorization", "Bearer " + refreshToken))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void rotacaoDeRefreshTokenInvalidaOAntigoEDetectaReusoRevogandoTodosOsTokensDoUsuario() throws Exception {
        JsonNode login = corpoDe(postJson("/auth/login", Map.of("username", "ana", "password", "senha123"))
                .andExpect(status().isOk()));
        String refresh1 = login.get("refreshToken").asText();

        // 1ª renovação: funciona e devolve um par novo (refresh1 agora está revogado)
        JsonNode renovado = corpoDe(postJson("/auth/refresh", Map.of("refreshToken", refresh1))
                .andExpect(status().isOk()));
        String refresh2 = renovado.get("refreshToken").asText();

        // Reuso do refresh1 (já gasto!): dispara o alarme de segurança (401) e revoga também o refresh2!
        postJson("/auth/refresh", Map.of("refreshToken", refresh1))
                .andExpect(status().isUnauthorized());

        // Até o refresh2 (que era novo) foi revogado por segurança
        postJson("/auth/refresh", Map.of("refreshToken", refresh2))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void logoutRevogaORefreshToken() throws Exception {
        JsonNode login = corpoDe(postJson("/auth/login", Map.of("username", "ana", "password", "senha123"))
                .andExpect(status().isOk()));
        String refresh = login.get("refreshToken").asText();

        postJson("/auth/logout", Map.of("refreshToken", refresh))
                .andExpect(status().isNoContent());

        postJson("/auth/refresh", Map.of("refreshToken", refresh))
                .andExpect(status().isUnauthorized());
    }
}
