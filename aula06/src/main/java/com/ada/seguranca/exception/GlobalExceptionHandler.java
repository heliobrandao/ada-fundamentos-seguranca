package com.ada.seguranca.exception;

import io.github.resilience4j.ratelimiter.RequestNotPermitted;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.time.Instant;
import java.util.stream.Collectors;

/**
 * Tratamento global e padronizado de exceções da API.
 *
 * DICA DE LIVE CODING (A Armadilha do Handler Genérico):
 * 1. Se esta classe NÃO estender ResponseEntityExceptionHandler, o método @ExceptionHandler(Exception.class)
 *    captura inclusive as exceções internas do Spring MVC (como MissingRequestCookieException em
 *    GET /boas-vindas/estrito), transformando um erro 400 do cliente em 500 Internal Server Error!
 * 2. Ao estender ResponseEntityExceptionHandler e sobrescrever handleExceptionInternal, as exceções
 *    do próprio Spring MVC mantêm seus status originais (400, 404, 405, 415) e saem no formato ErroResponse.
 */
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AlunoNaoEncontradoException.class)
    public ResponseEntity<ErroResponse> naoEncontrado(AlunoNaoEncontradoException ex) {
        return resposta(HttpStatus.NOT_FOUND, ex.getMessage());
    }

    @ExceptionHandler(RequestNotPermitted.class)
    public ResponseEntity<ErroResponse> muitasRequisicoes(RequestNotPermitted ex) {
        return resposta(HttpStatus.TOO_MANY_REQUESTS,
                "Muitas requisições. Tente novamente em instantes.");
    }

    // Rede de segurança: o detalhe técnico vai SÓ para o log do servidor;
    // quem chamou a API recebe apenas uma mensagem genérica (sem stack trace, sem SQL, sem URL de banco).
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErroResponse> inesperado(Exception ex) {
        log.error("Erro inesperado", ex);
        return resposta(HttpStatus.INTERNAL_SERVER_ERROR,
                "Erro interno. Tente novamente mais tarde.");
    }

    // Ponte para o projeto final (Seção 5 do material): quando a validação @Valid falha,
    // informa quais campos estão inválidos sem expor detalhes internos da aplicação.
    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex,
            HttpHeaders headers,
            HttpStatusCode status,
            WebRequest request) {
        String camposInvalidos = ex.getBindingResult().getFieldErrors().stream()
                .map( GlobalExceptionHandler::formatarErroDeCampo )
                .collect(Collectors.joining("; "));
        String mensagem = camposInvalidos.isEmpty()
                ? "Requisição inválida."
                : "Campos inválidos: " + camposInvalidos;
        ErroResponse corpo = new ErroResponse(
                HttpStatus.BAD_REQUEST.value(),
                HttpStatus.BAD_REQUEST.getReasonPhrase(),
                mensagem,
                Instant.now()
        );
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).headers(headers).body(corpo);
    }

    // Formato único também para os erros do Spring MVC tratados pela classe-base (ResponseEntityExceptionHandler).
    @Override
    protected ResponseEntity<Object> handleExceptionInternal(
            Exception ex,
            Object body,
            HttpHeaders headers,
            HttpStatusCode statusCode,
            WebRequest request) {
        HttpStatus status = HttpStatus.resolve(statusCode.value());
        String erro = status != null ? status.getReasonPhrase() : "Erro";
        ErroResponse corpo = new ErroResponse(
                statusCode.value(),
                erro,
                mensagemGenerica(statusCode),
                Instant.now()
        );
        return ResponseEntity.status(statusCode).headers(headers).body(corpo);
    }

    private ResponseEntity<ErroResponse> resposta(HttpStatus status, String mensagem) {
        ErroResponse corpo = new ErroResponse(
                status.value(),
                status.getReasonPhrase(),
                mensagem,
                Instant.now()
        );
        return ResponseEntity.status(status).body(corpo);
    }

    private String mensagemGenerica(HttpStatusCode statusCode) {
        return switch (statusCode.value()) {
            case 400 -> "Requisição inválida.";
            case 404 -> "Recurso não encontrado.";
            case 405 -> "Método HTTP não permitido.";
            case 415 -> "Formato de mídia não suportado.";
            default -> "Não foi possível processar a requisição.";
        };
    }

    private static String formatarErroDeCampo(FieldError fieldError) {
        return fieldError.getField() + " (" + fieldError.getDefaultMessage() + ")";
    }
}
