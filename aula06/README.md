# Aula 06 — SQL Injection, Dependências Vulneráveis e Tratamento Seguro de Exceções

API de Alunos com banco H2 em memória (`jdbc:h2:mem:testdb`) usada nas demonstrações e práticas da **Aula 06** do módulo `[BE-JV-013] Fundamentos de segurança para aplicações`.

---

## Como executar

Na raiz do repositório ou dentro da pasta `aula06`:

```bash
# Subir a aplicação na porta 8080
mvn -pl aula06 spring-boot:run

# Rodar a suíte de testes automatizados da Aula 06
mvn -pl aula06 test
```

---

## Roteiro rápido de chamadas (`curl` / Postman)

### Parte 1 — SQL Injection vs. PreparedStatement

```bash
# 1. Uso normal
curl -G --data-urlencode "nome=Batman" http://localhost:8080/alunos/pesquisa/vulneravel

# 2. Ataque SQL Injection no endpoint vulnerável (devolve TODOS os 4 alunos!)
curl -G --data-urlencode "nome=x' OR '1'='1" http://localhost:8080/alunos/pesquisa/vulneravel

# 3. Mesmo ataque no endpoint corrigido com PreparedStatement (?) (devolve lista vazia [])
curl -G --data-urlencode "nome=x' OR '1'='1" http://localhost:8080/alunos/pesquisa

# 4. Busca parcial segura com LIKE (os '%' vão no valor do parâmetro, nunca concatenados no SQL)
curl -G --data-urlencode "termo=man" http://localhost:8080/alunos/pesquisa/like
```

### Parte 2 — Dependências Vulneráveis e OWASP Top 10

```bash
# Inspecionar a árvore de dependências do módulo
mvn -pl aula06 dependency:tree
```

Veja também o arquivo [`dependabot.yml.exemplo`](./dependabot.yml.exemplo) para configuração de alertas semanais no GitHub (`.github/dependabot.yml`).

### Parte 3 e 4 — Tratamento Seguro e Global de Exceções (`@RestControllerAdvice`)

| Chamada | Status HTTP | `mensagem` no `ErroResponse` | O que demonstra |
|---|---|---|---|
| `GET /alunos/999` | `404 Not Found` | `Aluno 999 não encontrado` | Exceção de domínio (`AlunoNaoEncontradoException`) tratada com status semântico |
| `GET /erro-teste` | `500 Internal Server Error` | `Erro interno. Tente novamente mais tarde.` | **Rede de segurança:** esconde `jdbc:h2:mem:testdb` e *stack trace* do cliente, gravando tudo no log do servidor |
| `GET /boas-vindas/estrito` (sem cookie) | `400 Bad Request` | `Requisição inválida.` | **Armadilha do handler genérico:** estender `ResponseEntityExceptionHandler` evita transformar erros 400 do Spring MVC em 500 |
| `POST /alunos` (JSON inválido) | `400 Bad Request` | `Campos inválidos: ...` | **Bean Validation (`@Valid`):** informa os campos inválidos sem expor classes internas (ponte para a API de Chamados) |
| 2ª chamada a `GET /alunos` em < 10s | `429 Too Many Requests` | `Muitas requisições. Tente novamente em instantes.` | Tratamento da exceção `RequestNotPermitted` do Resilience4j Rate Limiter |
