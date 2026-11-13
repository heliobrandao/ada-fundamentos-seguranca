package com.ada.seguranca.aula07;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Demonstração enxuta da Regra de Propriedade do Projeto Final (Seção 7 da Aula 07):
 * - O dono do chamado vem SEMPRE do token (Authentication.getName()), NUNCA do JSON enviado pelo cliente!
 * - Um usuário NUNCA vê o chamado de outra pessoa: tentar acessar devolve 404 Not Found
 *   (para não revelar nem sequer que aquele ID existe!).
 */
@RestController
@RequestMapping("/chamados")
public class ChamadoController {

    public record NovoChamadoRequest(String titulo, String descricao) {}
    public record Chamado(Long id, String titulo, String descricao, String dono) {}

    private final List<Chamado> chamados = new CopyOnWriteArrayList<>();
    private final AtomicLong sequenciaId = new AtomicLong(1);

    @PostMapping
    public ResponseEntity<Chamado> abrirChamado(
            @RequestBody NovoChamadoRequest req,
            Authentication auth) {
        // Regra de ouro: quem é o dono vem do SecurityContext (token/Basic), nunca do body!
        Chamado novo = new Chamado(
                sequenciaId.getAndIncrement(),
                req.titulo(),
                req.descricao(),
                auth.getName()
        );
        chamados.add(novo);
        return ResponseEntity.status(HttpStatus.CREATED).body(novo);
    }

    @GetMapping
    public List<Chamado> listarMeusChamados(Authentication auth) {
        return chamados.stream()
                .filter(c -> c.dono().equals(auth.getName()))
                .toList();
    }

    @GetMapping("/{id}")
    public Chamado buscarPorId(@PathVariable Long id, Authentication auth) {
        // Filtra pelo ID **E** pelo dono autenticado.
        // Se não existir OU pertencer a outra pessoa -> 404 Not Found!
        return chamados.stream()
                .filter(c -> c.id().equals(id) && c.dono().equals(auth.getName()))
                .findFirst()
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND,
                        "Chamado " + id + " não encontrado."
                ));
    }
}
