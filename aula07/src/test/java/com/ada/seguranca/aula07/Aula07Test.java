package com.ada.seguranca.aula07;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class Aula07Test {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @BeforeEach
    void limparBanco() {
        usuarioRepository.deleteAll();
    }

    @Test
    @DisplayName("1. Rota pública (/publico) responde 200 sem exigir autenticação")
    void rotaPublicaFuncionaSemCredenciais() throws Exception {
        mockMvc.perform(get("/publico"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mensagem").exists());
    }

    @Test
    @DisplayName("2. Rota protegida (/perfil) sem credenciais devolve 401 Unauthorized")
    void rotaProtegidaSemCredenciaisDevolve401() throws Exception {
        mockMvc.perform(get("/perfil"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("3. Cadastro (POST /user) grava a senha como hash BCrypt ($2a$) e não expõe a senha na resposta")
    void cadastroGravaSenhaComoHashBCrypt() throws Exception {
        mockMvc.perform(post("/user")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"ana","password":"senha123"}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value("ana"))
                .andExpect(jsonPath("$.password").doesNotExist());

        Usuario salva = usuarioRepository.findByUsername("ana").orElseThrow();
        assertThat(salva.getPassword())
                .isNotEqualTo("senha123")
                .startsWith("$2");
    }

    @Test
    @DisplayName("4. Etapa 1 do Live Coding: Autenticação Básica (HTTP Basic) funciona nativamente com o usuário cadastrado")
    void etapa1BasicAuthFuncionaAposCadastro() throws Exception {
        cadastrarUsuario("ana", "senha123");

        mockMvc.perform(get("/perfil").with(httpBasic("ana", "senha123")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.usuarioAutenticado").value("ana"));
    }

    @Test
    @DisplayName("5. Etapa 2 do Live Coding: Fluxo JWT completo (POST /authenticate + Authorization: Bearer <token>)")
    void etapa2JwtFluxoCompleto() throws Exception {
        cadastrarUsuario("ana", "senha123");
        String token = autenticarEObterToken("ana", "senha123");

        mockMvc.perform(get("/perfil")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.usuarioAutenticado").value("ana"));
    }

    @Test
    @DisplayName("6. Anti-enumeração: senha errada e usuário inexistente devolvem 401 com a MESMA mensagem")
    void senhaErradaEUsuarioInexistenteDevolvem401ComAMesmaMensagem() throws Exception {
        cadastrarUsuario("ana", "senha123");

        mockMvc.perform(post("/authenticate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"ana","password":"errada"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.mensagem").value("Usuário ou senha inválidos."));

        mockMvc.perform(post("/authenticate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"fantasma","password":"qualquer"}
                                """))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.mensagem").value("Usuário ou senha inválidos."));
    }

    @Test
    @DisplayName("7. Token adulterado na assinatura é rejeitado automaticamente pelo JwtDecoder nativo com 401")
    void tokenAdulteradoDevolve401() throws Exception {
        cadastrarUsuario("ana", "senha123");
        String tokenValido = autenticarEObterToken("ana", "senha123");
        String tokenAdulterado = tokenValido.substring(0, tokenValido.length() - 2) + "XX";

        mockMvc.perform(get("/perfil")
                        .header("Authorization", "Bearer " + tokenAdulterado))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("8. Regra de propriedade (Broken Access Control): tentar ler chamado de outro usuário devolve 404")
    void regraDePropriedadeUsuarioNaoEnxergaChamadoDeOutraPessoa() throws Exception {
        cadastrarUsuario("ana", "senha123");
        cadastrarUsuario("carlos", "senha123");

        String tokenAna = autenticarEObterToken("ana", "senha123");
        String tokenCarlos = autenticarEObterToken("carlos", "senha123");

        // Ana abre um chamado (dono = "ana" extraído do token dela)
        MvcResult criacao = mockMvc.perform(post("/chamados")
                        .header("Authorization", "Bearer " + tokenAna)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"titulo":"Impressora parada","descricao":"Não imprime no 3º andar"}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.dono").value("ana"))
                .andReturn();

        JsonNode chamadoCriado = objectMapper.readTree(criacao.getResponse().getContentAsString());
        long idChamadoDaAna = chamadoCriado.get("id").asLong();

        // Ana consegue consultar o próprio chamado (200 OK)
        mockMvc.perform(get("/chamados/" + idChamadoDaAna)
                        .header("Authorization", "Bearer " + tokenAna))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.titulo").value("Impressora parada"));

        // Carlos (autenticado com token válido!) tenta acessar o chamado da Ana -> recebe 404 Not Found!
        mockMvc.perform(get("/chamados/" + idChamadoDaAna)
                        .header("Authorization", "Bearer " + tokenCarlos))
                .andExpect(status().isNotFound());
    }

    private void cadastrarUsuario(String username, String password) throws Exception {
        mockMvc.perform(post("/user")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","password":"%s"}
                                """.formatted(username, password)))
                .andExpect(status().isCreated());
    }

    private String autenticarEObterToken(String username, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/authenticate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username":"%s","password":"%s"}
                                """.formatted(username, password)))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode json = objectMapper.readTree(result.getResponse().getContentAsString());
        return json.get("token").asText();
    }
}
