# Aula 07 — Spring Security 6 Nativo: Basic Auth, BCrypt, JWT e Regra de Propriedade

Projeto enxuto de **Live Coding** da **Aula 07** (`[BE-JV-013] Fundamentos de segurança para aplicações`), usando os recursos **100% nativos do Spring Security 6** (`spring-boot-starter-security` + `spring-boot-starter-oauth2-resource-server`):

- **Zero filtro manual (`OncePerRequestFilter`)**: o próprio `.oauth2ResourceServer(oauth2 -> oauth2.jwt(...))` do Spring Security valida o cabeçalho `Authorization: Bearer <token>`, a assinatura HMAC-SHA256 e a expiração!
- **Zero biblioteca externa de JWT**: usa `JwtEncoder` e `JwtDecoder` (`NimbusJwtEncoder` / `NimbusJwtDecoder`) já embutidos no Spring Security.
- **Apenas 4 arquivos de código de negócio/configuração**:
  1. [`Usuario.java`](./src/main/java/com/ada/seguranca/aula07/Usuario.java) + [`UsuarioRepository.java`](./src/main/java/com/ada/seguranca/aula07/UsuarioRepository.java)
  2. [`SecurityConfig.java`](./src/main/java/com/ada/seguranca/aula07/SecurityConfig.java)
  3. [`AuthController.java`](./src/main/java/com/ada/seguranca/aula07/AuthController.java) (`GET /publico`, `POST /user`, `POST /authenticate`, `GET /perfil`)
  4. [`ChamadoController.java`](./src/main/java/com/ada/seguranca/aula07/ChamadoController.java) (`POST /chamados`, `GET /chamados`, `GET /chamados/{id}` demonstrando a **Regra de Propriedade** com `404` para chamados de outros usuários).

---

## Como executar

```powershell
# Opcional: definir a chave JWT_SECRET no terminal (precisa ter >= 32 bytes para o HS256)
$env:JWT_SECRET = "minha-chave-secreta-de-producao-com-mais-de-32-caracteres!"

# Subir a aplicação na porta 8080
mvn -pl aula07 spring-boot:run

# Rodar a suíte de testes automatizados (8 testes)
mvn -pl aula07 test
```
