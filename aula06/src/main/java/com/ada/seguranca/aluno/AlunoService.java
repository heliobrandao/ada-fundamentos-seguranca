package com.ada.seguranca.aluno;

import com.ada.seguranca.exception.AlunoNaoEncontradoException;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class AlunoService {

    private final AlunoRepository repository;

    public AlunoService(AlunoRepository repository) {
        this.repository = repository;
    }

    public List<Aluno> consultaTodos() {
        return repository.findAll();
    }

    // DICA DE LIVE CODING:
    // Se fizéssemos repository.findById(id).get(), um ID inexistente lançaria NoSuchElementException (500).
    // Ao lançar AlunoNaoEncontradoException, damos um nome de domínio claro ao erro (404).
    public Aluno buscaPorId(Long id) {
        return repository.findById(id)
                .orElseThrow(() -> new AlunoNaoEncontradoException(id));
    }

    public List<Aluno> pesquisaVulneravel(String nome) {
        return repository.pesquisaVulneravel(nome);
    }

    public List<Aluno> pesquisa(String nome) {
        return repository.pesquisa(nome);
    }

    public List<Aluno> pesquisaPorParteDoNome(String termo) {
        return repository.pesquisaPorParteDoNome(termo);
    }

    public Aluno cadastrar(NovoAlunoRequest request) {
        return repository.save(request.nome(), request.email());
    }
}
