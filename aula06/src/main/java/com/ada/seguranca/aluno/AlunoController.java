package com.ada.seguranca.aluno;

import io.github.resilience4j.ratelimiter.annotation.RateLimiter;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/alunos")
public class AlunoController {

    private final AlunoService service;

    public AlunoController(AlunoService service) {
        this.service = service;
    }

    // Demonstração de Rate Limiter (429 Too Many Requests):
    // A instância "alunoService" (application.yml) aceita 1 chamada a cada 10 segundos.
    // A segunda chamada seguida lança RequestNotPermitted, tratada pelo GlobalExceptionHandler.
    @GetMapping
    @RateLimiter(name = "alunoService")
    public List<Aluno> consultaTodos() {
        return service.consultaTodos();
    }

    @GetMapping("/{id}")
    public Aluno buscaPorId(@PathVariable Long id) {
        return service.buscaPorId(id);
    }

    // Endpoint VULNERÁVEL a SQL Injection (concatenação direta de texto no SQL)
    // Teste normal: /alunos/pesquisa/vulneravel?nome=Batman
    // Ataque: /alunos/pesquisa/vulneravel?nome=x' OR '1'='1
    @GetMapping("/pesquisa/vulneravel")
    public List<Aluno> pesquisaVulneravel(@RequestParam String nome) {
        return service.pesquisaVulneravel(nome);
    }

    // Endpoint CORRIGIDO com PreparedStatement (?)
    // Ataque neutralizado: /alunos/pesquisa?nome=x' OR '1'='1 -> devolve []
    @GetMapping("/pesquisa")
    public List<Aluno> pesquisa(@RequestParam String nome) {
        return service.pesquisa(nome);
    }

    // Exemplo extra: busca parcial (‘LIKE’) parametrizada
    @GetMapping("/pesquisa/like")
    public List<Aluno> pesquisaPorParteDoNome(@RequestParam String termo) {
        return service.pesquisaPorParteDoNome(termo);
    }

    // Exemplo de validação de entrada com @Valid (ponte para a seção 5 do projeto final)
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Aluno cadastrar(@Valid @RequestBody NovoAlunoRequest request) {
        return service.cadastrar(request);
    }

    // DICA DE LIVE CODING (Passo 1 do tratamento no Controller):
    // Descomente este bloco se quiser demonstrar o @ExceptionHandler local antes do @RestControllerAdvice:
    //
    // @ExceptionHandler(AlunoNaoEncontradoException.class)
    // public ResponseEntity<‘String’> naoEncontrado(AlunoNaoEncontradoException ex) {
    //     return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ex.getMessage());
    // }
}
