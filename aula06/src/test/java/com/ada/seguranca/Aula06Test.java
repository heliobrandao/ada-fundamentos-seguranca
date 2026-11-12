package com.ada.seguranca;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class Aula06Test {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("SQL Injection: pesquisa vulnerável concatenando String devolve todos os 4 alunos com x' OR '1'='1")
    void pesquisaVulneravelEnganadaPeloSqlInjectionDevolveTodosOsAlunos() throws Exception {
        mockMvc.perform(get("/alunos/pesquisa/vulneravel")
                        .param("nome", "x' OR '1'='1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(4)));
    }

    @Test
    @DisplayName("PreparedStatement: pesquisa parametrizada trata x' OR '1'='1 como um nome comum e devolve lista vazia")
    void pesquisaComInstrucaoPreparadaTrataOAtaqueComoUmNome() throws Exception {
        mockMvc.perform(get("/alunos/pesquisa")
                        .param("nome", "x' OR '1'='1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(0)));
    }

    @Test
    @DisplayName("Busca por ID inexistente lança AlunoNaoEncontradoException e devolve 404 padronizado")
    void alunoInexistenteDevolve404NoFormatoPadronizado() throws Exception {
        mockMvc.perform(get("/alunos/999"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.erro").value("Not Found"))
                .andExpect(jsonPath("$.mensagem").value("Aluno 999 não encontrado"))
                .andExpect(jsonPath("$.timestamp").exists());
    }

    @Test
    @DisplayName("Rede de segurança: erro inesperado devolve 500 genérico sem vazar URL JDBC nem nome de classe")
    void erroInesperadoDevolveMensagemGenericaSemVazarDetalhes() throws Exception {
        mockMvc.perform(get("/erro-teste"))
                .andExpect(status().isInternalServerError())
                .andExpect(jsonPath("$.status").value(500))
                .andExpect(jsonPath("$.erro").value("Internal Server Error"))
                .andExpect(jsonPath("$.mensagem").value("Erro interno. Tente novamente mais tarde."))
                .andExpect(jsonPath("$.mensagem", not(containsString("jdbc"))))
                .andExpect(jsonPath("$.mensagem", not(containsString("IllegalStateException"))));
    }

    @Test
    @DisplayName("Armadilha do handler genérico: erro do Spring MVC mantém o status 400 em vez de virar 500")
    void erroDoSpringMvcMantemOStatus400EmVezDeVirar500() throws Exception {
        mockMvc.perform(get("/boas-vindas/estrito"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.erro").value("Bad Request"))
                .andExpect(jsonPath("$.mensagem").value("Requisição inválida."));
    }

    @Test
    @DisplayName("Validação com @Valid: devolve 400 informando quais campos falharam sem vazar stack trace")
    void validacaoDeEntradaDevolve400ComOsCamposInvalidos() throws Exception {
        String jsonInvalido = """
                {
                  "nome": "Oi",
                  "email": "email-invalido"
                }
                """;
        mockMvc.perform(post("/alunos")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(jsonInvalido))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.mensagem", containsString("Campos inválidos:")))
                .andExpect(jsonPath("$.mensagem", containsString("nome")))
                .andExpect(jsonPath("$.mensagem", containsString("email")));
    }

    @Test
    @DirtiesContext
    @DisplayName("Rate Limiter: segunda chamada a GET /alunos em menos de 10s devolve 429 Too Many Requests")
    void segundaChamadaAoRateLimiterDevolve429Padronizado() throws Exception {
        mockMvc.perform(get("/alunos"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$", hasSize(4)));

        mockMvc.perform(get("/alunos"))
                .andExpect(status().isTooManyRequests())
                .andExpect(jsonPath("$.status").value(429))
                .andExpect(jsonPath("$.erro").value("Too Many Requests"))
                .andExpect(jsonPath("$.mensagem").value("Muitas requisições. Tente novamente em instantes."));
    }
}
