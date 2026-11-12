package com.ada.seguranca.aluno;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.stereotype.Repository;

import java.sql.PreparedStatement;
import java.util.List;
import java.util.Optional;

@Repository
public class AlunoRepository {

    private static final RowMapper<Aluno> MAPPER = (rs, rowNum) -> new Aluno(
            rs.getLong("id"),
            rs.getString("nome"),
            rs.getString("email")
    );

    private final JdbcTemplate jdbc;

    public AlunoRepository(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public List<Aluno> findAll() {
        return jdbc.query("SELECT id, nome, email FROM alunos ORDER BY id", MAPPER);
    }

    public Optional<Aluno> findById(Long id) {
        List<Aluno> encontrados = jdbc.query(
                "SELECT id, nome, email FROM alunos WHERE id = ?",
                MAPPER,
                id
        );
        return encontrados.stream().findFirst();
    }

    // VULNERÁVEL a SQL Injection: o texto recebido é concatenado diretamente na consulta.
    // Ataque: nome = x' OR '1'='1   (devolve todos os 4 alunos da tabela!)
    public List<Aluno> pesquisaVulneravel(String nome) {
        String sql = "SELECT * FROM alunos WHERE nome = '" + nome + "'";
        return jdbc.query(sql, MAPPER);
    }

    // CORRIGIDO: instrução preparada (PreparedStatement). O SQL e o dado seguem por caminhos separados.
    // Com "x' OR '1'='1", o banco procura alguém literalmente chamado "x' OR '1'='1" e devolve [].
    public List<Aluno> pesquisa(String nome) {
        return jdbc.query("SELECT * FROM alunos WHERE nome = ?", MAPPER, nome);
    }

    // Busca parcial (LIKE) segura: os curingas '%' são concatenados ao VALOR do parâmetro,
    // NUNCA ao texto da consulta SQL.
    public List<Aluno> pesquisaPorParteDoNome(String termo) {
        return jdbc.query(
                "SELECT * FROM alunos WHERE LOWER(nome) LIKE LOWER(?)",
                MAPPER,
                "%" + termo + "%"
        );
    }

    public Aluno save(String nome, String email) {
        KeyHolder keyHolder = new GeneratedKeyHolder();
        jdbc.update(connection -> {
            PreparedStatement ps = connection.prepareStatement(
                    "INSERT INTO alunos (nome, email) VALUES (?, ?)",
                    new String[]{"id"}
            );
            ps.setString(1, nome);
            ps.setString(2, email);
            return ps;
        }, keyHolder);
        Long id = keyHolder.getKey() != null ? keyHolder.getKey().longValue() : null;
        return new Aluno(id, nome, email);
    }
}
