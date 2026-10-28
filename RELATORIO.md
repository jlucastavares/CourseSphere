# Relatório Técnico: Segurança e Confiabilidade do CourseSphere

| | |
|---|---|
| **Aplicação** | CourseSphere: backend Flask (Python), frontend React + TypeScript, Firebase (Authentication e Realtime Database) |
| **Tipo de avaliação** | Teste de segurança *white-box* (com acesso ao código-fonte) e avaliação de confiabilidade |
| **Versão analisada** | Commit `0b60ef1` (código original) |
| **Versão corrigida** | Commit `1af5a59` e posteriores |
| **Autor** | Tavares |
| **Data** | Outubro de 2026 |

## Sumário

1. [Resumo executivo](#1-resumo-executivo)
2. [Escopo](#2-escopo)
3. [Metodologia](#3-metodologia)
4. [Classificação de severidade](#4-classificação-de-severidade)
5. [Vulnerabilidades encontradas](#5-vulnerabilidades-encontradas)
6. [Correções aplicadas](#6-correções-aplicadas)
7. [Hardening](#7-hardening)
8. [Verificação das correções](#8-verificação-das-correções)
9. [Confiabilidade (SRE)](#9-confiabilidade-sre)
10. [Recomendações priorizadas](#10-recomendações-priorizadas)
11. [Anexos](#11-anexos)

---

## 1. Resumo executivo

O CourseSphere é uma aplicação web em que estudantes criam um perfil acadêmico e conversam com um assistente sobre cursos. A avaliação buscou responder a três perguntas: **os dados dos usuários estão protegidos?**, **a aplicação está pronta para operar com segurança?** e **é possível saber se ela está funcionando bem?**

**Principais conclusões:**

- Foram identificadas **10 vulnerabilidades**: 1 crítica, 2 altas, 6 médias e 1 baixa. As mais graves eram **configurações inseguras**, e não falhas complexas: o servidor rodava em modo de depuração, que expõe o código e permite executar comandos, e credenciais de administrador ficavam em arquivos comuns dentro do projeto.
- O **controle de acesso entre usuários está correto**: nos testes, nenhum usuário conseguiu ler ou alterar dados de outro.
- **8 das 10 vulnerabilidades foram corrigidas**, 1 foi parcialmente mitigada e 1 foi documentada para correção futura, porque está num código que hoje não está ativo.
- Cada correção foi validada por **testes automatizados**. Na versão original, 22 dos testes de segurança falham. Na versão corrigida, todos os 42 testes passam.
- A aplicação passou a ter **logs, métricas e metas de qualidade de serviço** (SLOs), e foi preparada para rodar em **containers com balanceamento de carga**: duas instâncias do backend, com troca automática se uma falhar.
- As verificações de segurança passaram a rodar **automaticamente a cada alteração do código**.

**Risco residual e próximos passos:**

| Prioridade | Ação | Por quê |
|---|---|---|
| 1 | Trocar as chaves do Firebase e da OpenAI e guardá-las em um cofre de segredos | Elas ficaram expostas em arquivos do projeto antes da correção |
| 2 | Atualizar o SDK do Firebase no frontend | Concentra as vulnerabilidades conhecidas de dependências que ainda restam |
| 3 | Corrigir o SQL Injection latente antes de ativar o módulo de cursos | Hoje é inofensivo; se ativado sem correção, expõe o banco de cursos |
| 4 | Eliminar os pontos únicos de falha da infraestrutura antes de ir para produção | O balanceador e o Redis são instâncias únicas |

A lista completa, com esforço estimado, está na [seção 10](#10-recomendações-priorizadas).

---

## 2. Escopo

| Item | Detalhe |
|---|---|
| **Backend** | `backend/`: API Flask com 8 rotas: `POST /users/create`, `GET` e `POST /users/info`, `POST /users/query`, `POST /hash`, `GET /chats`, `POST /chats/<id>/messages` e `DELETE /chats/<id>`. Inclui o módulo `blueprints/courses.py`, que não está ativo |
| **Frontend** | `frontend/`: SPA em React, com login e cadastro, dashboard de perfil e chat |
| **Autenticação** | Firebase Authentication. O login ocorre no navegador; o backend valida o *ID token* com o Admin SDK |
| **Dados** | Firebase Realtime Database: `users/{uid}/info` (perfil) e `users/{uid}/chats` (histórico) |
| **Fora do escopo** | Infraestrutura do Google/Firebase, API da OpenAI (desativada nesta versão), scripts de coleta de dados (`cornell-course-sphere-data/`) e configurações feitas no console do Firebase |

**Observação sobre o enunciado:** o desafio cita como exemplo de controle de acesso "um usuário editar o curso de outro criador". Esta versão do CourseSphere não tem cursos com dono. Os recursos que pertencem a cada usuário são o **perfil** e os **chats**, e os testes de controle de acesso foram feitos sobre eles.

---

## 3. Metodologia

A análise seguiu o **OWASP Top 10 (2021)** como guia de categorias e partes do **OWASP ASVS**: autenticação (V2), sessão (V3), controle de acesso (V4), validação (V5), erros e logs (V7) e configuração (V14).

| Etapa | Como foi feita |
|---|---|
| **Revisão manual de código** | Leitura de cada rota do backend e das chamadas do frontend, observando de onde vem cada dado, como o usuário é identificado e o que é devolvido ao cliente |
| **Análise estática (SAST)** | **Bandit** no código Python |
| **Análise de dependências (SCA)** | **npm audit** no frontend e **pip-audit** no backend |
| **Testes dinâmicos** | Requisições `curl` contra a aplicação rodando localmente, para confirmar cada suspeita |
| **Testes automatizados** | 42 testes com `pytest`, que reproduzem cada ataque e confirmam a correção (ver [seção 8](#8-verificação-das-correções)) |

**Ambiente de teste:** aplicação local (backend em `127.0.0.1:5000`, frontend em `localhost:5173`) e, depois da containerização, `docker compose` em `localhost:8080`. Nenhum teste foi feito contra ambiente de produção.

**Obtenção de token para os testes autenticados:**

```bash
curl -s "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=<apiKey do firebaseConfig.ts>" \
  -H "Content-Type: application/json" \
  -d '{"email":"usuario-de-teste@exemplo.com","password":"<senha>","returnSecureToken":true}'
# o campo "idToken" da resposta é usado como: Authorization: Bearer <idToken>
```

---

## 4. Classificação de severidade

Cada vulnerabilidade recebeu uma nota **CVSS 3.1**, padrão do mercado que pontua de 0 a 10 considerando, entre outros fatores, como o ataque é feito e o que ele compromete. A severidade segue a escala oficial:

| Severidade | CVSS | Significado prático |
|---|---|---|
| **Crítica** | 9.0 – 10.0 | Comprometimento amplo e de fácil exploração. Correção imediata |
| **Alta** | 7.0 – 8.9 | Impacto sério em dados ou no sistema. Correção prioritária |
| **Média** | 4.0 – 6.9 | Impacto limitado ou que depende de condições. Correção planejada |
| **Baixa** | 0.1 – 3.9 | Impacto pequeno ou difícil de explorar |

Quando o contexto muda o risco real (por exemplo, um código vulnerável que não está ativo), isso é indicado junto da nota.

---

## 5. Vulnerabilidades encontradas

### 5.1 Visão geral

| ID | Vulnerabilidade | OWASP | CVSS | Severidade | Situação |
|---|---|---|---|---|---|
| VULN-01 | Credenciais em texto claro no projeto | A02 / A05 | 9.0 | **Crítica** | Parcialmente mitigada |
| VULN-02 | Servidor Flask em modo debug | A05 | 8.1 | **Alta** | Corrigida |
| VULN-03 | Mensagens de erro internas expostas e enumeração de usuários | A04 / A07 | 5.3 | Média | Corrigida |
| VULN-04 | Ausência de limite de requisições (rate limiting) | A04 / A07 | 6.5 | Média | Corrigida |
| VULN-05 | Token de sessão enviado na URL | A07 | 5.9 | Média | Corrigida |
| VULN-06 | Ausência de validação de entrada | A03 / A04 | 5.4 | Média | Corrigida |
| VULN-07 | CORS irrestrito e ausência de headers de segurança | A05 | 4.2 | Média | Corrigida |
| VULN-08 | Sessão não revogada no logout | A07 | 4.8 | Média | Corrigida |
| VULN-09 | Dependências com vulnerabilidades conhecidas | A06 | 4.2 | Média | Monitorada |
| VULN-10 | SQL Injection em módulo inativo | A03 | 7.5 se ativado | **Alta** (latente) / Baixa hoje | Documentada |

**Categorias pedidas no desafio:**

| Categoria | Vulnerabilidades |
|---|---|
| Injeção | VULN-10 |
| Exposição de dados sensíveis | VULN-01, 03, 05 |
| Autenticação e gestão de sessão | VULN-04, 05, 08 |
| Configuração incorreta de segurança | VULN-02, 07 |
| Dependências vulneráveis | VULN-09 |

### 5.2 Detalhamento

---

#### VULN-01: Credenciais em texto claro no projeto

**Severidade:** Crítica · CVSS 9.0 (`AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H`) · OWASP A02, A05

**Descrição.** Três arquivos com segredos ficam dentro da pasta do projeto:

| Arquivo | Conteúdo |
|---|---|
| `backend/credentials.json` | Chave privada de uma *service account* do Firebase |
| `backend/config.json` | Chave da API da OpenAI |
| `backend/cornell-course-sphere-data/reddit-data/reddit_key.json` | Segredo da API do Reddit |

A *service account* é a credencial de administrador do Firebase: **ignora todas as regras de segurança do banco** e permite criar, ler e apagar qualquer usuário ou dado. Os arquivos estavam no `.gitignore`, mas isso não impedia que vazassem por outros caminhos:

- a pasta circula como `.zip`;
- o `Dockerfile` original fazia `COPY . .` sem `.dockerignore`, então os segredos entrariam na imagem;
- a entrega exige um repositório público, onde um `git add -f` bastaria para publicá-los.

**Reprodução:**

```bash
python -c "import json; d=json.load(open('backend/credentials.json')); print(d['type'], 'private_key' in d)"
# service_account True
```

**Impacto técnico:** acesso administrativo total ao Firebase (Auth e banco) e uso da conta da OpenAI.

**Impacto no negócio:** vazamento dos dados pessoais de todos os usuários, com exposição à LGPD, e custo financeiro direto por uso indevido da API paga.

---

#### VULN-02: Servidor Flask em modo debug

**Severidade:** Alta · CVSS 8.1 (`AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`) · OWASP A05 · Bandit B201

**Descrição.** O servidor era iniciado com `app.run(debug=True)` (`backend/endpoints.py`). Esse modo ativa o *Werkzeug Debugger*: qualquer erro não tratado devolve uma página com o código-fonte e o *stack trace*, e um console Python interativo fica disponível em `/console`, protegido apenas por um PIN. Em duas rotas, a leitura do corpo da requisição ficava fora do `try`, o que permitia provocar o erro à vontade.

**Reprodução:**

```bash
curl -s -X POST http://127.0.0.1:5000/users/create -H "Content-Type: application/json" -d 'null'
# HTTP 500 com a página "Werkzeug Debugger":
# AttributeError: 'NoneType' object has no attribute 'get'

curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:5000/console
# 200: console do debugger disponível
```

**Impacto técnico:** exposição do código e da estrutura do servidor. Se exposto em rede, o PIN pode ser derivado, o que leva a **execução remota de código** e acesso às credenciais da VULN-01.

**Impacto no negócio:** comprometimento completo do servidor.

---

#### VULN-03: Mensagens de erro internas expostas e enumeração de usuários

**Severidade:** Média · CVSS 5.3 (`AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) · OWASP A04, A07

**Descrição.** Todas as rotas devolviam ao cliente a mensagem original da exceção (`str(e)`). No cadastro, a resposta diferenciava "e-mail já cadastrado" de outros erros, o que permite descobrir quais e-mails têm conta. Em outras rotas, as mensagens revelavam detalhes internos, como a validação do token.

**Reprodução:**

```bash
curl -s -X POST http://127.0.0.1:5000/users/create -H "Content-Type: application/json" \
  -d '{"email":"email-ja-cadastrado@exemplo.com","password":"Senha@123"}'
# {"error":"Error creating user: Error creating user: The user with the provided email already exists (EMAIL_EXISTS)."}

curl -s "http://127.0.0.1:5000/users/info?id_token=abc"
# {"error":"Error getting user info: Error verifying ID token: Wrong number of segments in token: b'abc'"}
```

**Impacto técnico:** reconhecimento facilitado para outros ataques.

**Impacto no negócio:** lista de usuários reais usada para phishing direcionado e para *credential stuffing*, que é testar senhas vazadas de outros sites.

---

#### VULN-04: Ausência de limite de requisições (rate limiting)

**Severidade:** Média · CVSS 6.5 (`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L`) · OWASP A04, A07

**Descrição.** Nenhuma rota limitava a quantidade de requisições. O cadastro (`POST /users/create`) não exige autenticação e cria contas com privilégio de administrador, contornando as proteções que o Firebase aplica no fluxo normal (bloqueio por IP, reCAPTCHA). A rota de consulta (`POST /users/query`) aceita usuários anônimos e foi projetada para chamar a API paga da OpenAI.

**Reprodução:**

```bash
for i in $(seq 1 50); do
  curl -s -o /dev/null -w "%{http_code} " -X POST http://127.0.0.1:5000/users/create \
    -H "Content-Type: application/json" -d "{\"email\":\"bot$i@exemplo.com\",\"password\":\"123456\"}"
done
# 50 × 200: 50 contas criadas em segundos, sem bloqueio
```

**Impacto técnico:** automação de ataques (criação de contas, força bruta) e negação de serviço.

**Impacto no negócio:** base poluída com contas falsas, esgotamento das cotas do Firebase e, com o assistente ativo, **custo sem limite** na OpenAI.

---

#### VULN-05: Token de sessão enviado na URL

**Severidade:** Média · CVSS 5.9 (`AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:L/A:N`) · OWASP A07

**Descrição.** O *ID token* do Firebase funciona como credencial: quem o apresenta é tratado como o usuário, por até 1 hora. O frontend o enviava na URL (`GET /users/info?id_token=...`), e o backend aceitava o token em três lugares diferentes (URL, corpo e header). URLs ficam gravadas em logs de servidor e de proxy, no histórico do navegador e em ferramentas de monitoramento.

**Reprodução:** com o backend rodando, fazer login e abrir o Dashboard. O log de acesso do Flask registra:

```
127.0.0.1 - - [...] "GET /users/info?id_token=eyJhbGciOiJSUzI1NiIs... HTTP/1.1" 200 -
```

O token copiado do log funciona em outras rotas:

```bash
curl -H "Authorization: Bearer <token copiado do log>" http://127.0.0.1:5000/chats
# 200: chats do usuário
```

**Impacto técnico:** sequestro de sessão por quem tem acesso a logs.

**Impacto no negócio:** leitura e alteração do perfil e do histórico de conversas de usuários.

---

#### VULN-06: Ausência de validação de entrada

**Severidade:** Média · CVSS 5.4 (`AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L`) · OWASP A03, A04

**Descrição.** O perfil e as mensagens de chat eram gravados no banco exatamente como chegavam, sem checar tipo, tamanho ou valores permitidos, e sem limite de tamanho da requisição. No chat, o cliente escolhia livremente o remetente (podia gravar mensagens como se fossem do "bot") e a quantidade de mensagens: cada item virava uma escrita no banco.

**Reprodução:**

```bash
python -c 'import json; print(json.dumps({"messages":[{"sender":"bot","content":"A"*1000}]*5000}))' > big.json
curl -s -X POST http://127.0.0.1:5000/chats/teste/messages \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" --data-binary @big.json
# 200: 5000 escritas (~5 MB) a partir de uma única requisição
```

**Impacto técnico:** dados inconsistentes, que podem quebrar o frontend, e amplificação de escrita: 1 requisição gera N escritas.

**Impacto no negócio:** custo e esgotamento da cota do banco, lentidão do serviço.

---

#### VULN-07: CORS irrestrito e ausência de headers de segurança

**Severidade:** Média · CVSS 4.2 (`AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N`) · OWASP A05

**Descrição.** O backend usava `CORS(app)` sem restrições, o que permite que qualquer site chame a API pelo navegador da vítima. As respostas não traziam `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Strict-Transport-Security` nem `Referrer-Policy`. Como a autenticação é por token no header e não por cookie, o risco imediato é limitado, mas qualquer falha futura de XSS se tornaria explorável.

**Reprodução:**

```bash
curl -s -D - -o /dev/null -X OPTIONS http://127.0.0.1:5000/chats \
  -H "Origin: https://atacante.example" -H "Access-Control-Request-Method: DELETE"
# Access-Control-Allow-Origin: *
```

**Impacto:** superfície maior para XSS e clickjacking.

---

#### VULN-08: Sessão não revogada no logout

**Severidade:** Média · CVSS 4.8 (`AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N`) · OWASP A07

**Descrição.** O logout só apagava a sessão no navegador, e o backend validava tokens sem verificar se tinham sido revogados. Um token copiado continuava aceito por até 1 hora após o logout.

**Reprodução:** guardar o token, clicar em Logout e repetir:

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:5000/chats
# 200
```

**Impacto:** em caso de vazamento (ver VULN-05), não havia como invalidar a sessão.

---

#### VULN-09: Dependências com vulnerabilidades conhecidas

**Severidade:** Média · CVSS 4.2 (agregado) · OWASP A06

**Descrição:**

- **Frontend:** o `npm audit --omit=dev` aponta **14 vulnerabilidades (5 altas e 9 moderadas)**. A maioria vem da cadeia do SDK `firebase` 10.x (`undici`, `@grpc/grpc-js`). Também aparecem `react-router-dom` 6.x (open redirect, GHSA-wrjc-x8rr-h8h6) e `uuid` < 11.1.1.
- **Backend:** o `requirements.txt` não fixa versões, então o build não é reprodutível. O `pip-audit` não encontrou CVEs nas versões atuais.

**Reprodução:** `cd frontend && npm audit --omit=dev`. Saída completa em `evidencias/npm_audit_versao_original.txt`.

**Impacto:** exposição a falhas públicas e risco de *supply chain*. Parte das falhas afeta só a execução em Node, e não o código que roda no navegador.

---

#### VULN-10: SQL Injection em módulo inativo

**Severidade:** Baixa no estado atual. **Alta (CVSS 7.5, `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`) se o módulo for ativado** · OWASP A03 · Bandit B608 (6 ocorrências)

**Descrição.** O arquivo `backend/blueprints/courses.py` monta consultas SQL colando o texto recebido na URL:

```python
execute_query(f"SELECT * FROM courses WHERE semester = '{semester}'")
```

O módulo não está registrado na aplicação (`#app.register_blueprint(courses_bp)`) e tem imports quebrados, então hoje suas rotas respondem 404.

**Reprodução (prova de conceito):** se ativado, a requisição `GET /courses/x' OR '1'='1` geraria `... WHERE semester = 'x' OR '1'='1'` e devolveria a tabela inteira.

**Impacto:** dívida técnica de alto risco. Basta "terminar o TODO" para expor o banco de cursos.

### 5.3 Testes negativos (controles que funcionam)

| Teste | Resultado |
|---|---|
| **Controle de acesso (IDOR):** ler, alterar ou apagar o perfil e os chats de outro usuário | **Não vulnerável.** Todas as rotas usam o `uid` do token verificado, nunca um identificador enviado pelo cliente |
| **XSS armazenado:** `<img src=x onerror=alert(1)>` no perfil ou no chat | **Não vulnerável.** O React escapa o conteúdo e não há `dangerouslySetInnerHTML` |
| **Injeção de caminho no banco** via `chat_id` (`../`, `.`, `#`) | **Não explorável.** O Flask não aceita `/` no parâmetro e o SDK rejeita caracteres especiais |
| **`apiKey` do Firebase no frontend** | **Falso positivo.** É um identificador público por design do Firebase |

### 5.4 Achados informativos

- **Prompt injection latente (OWASP LLM01).** A pergunta do usuário é concatenada diretamente no prompt do LLM (`main.make_prompt`). Hoje a integração com a OpenAI está desativada.
- **Gerador aleatório não criptográfico em `/hash`** (Bandit B311). O impacto é mitigado porque a função também usa `secrets.token_hex`.

---

## 6. Correções aplicadas

O código original foi registrado no primeiro commit (`0b60ef1`) e cada correção foi feita em um commit separado. Em todas, o objetivo foi tratar a **causa raiz**, e não só o sintoma. O critério usado foi: *se alguém criar uma rota nova amanhã, o problema volta?*

### 6.1 VULN-02: Modo debug desligado por padrão

**Commit:** `26ca9a8` · **Arquivo:** `backend/endpoints.py`

| | |
|---|---|
| **Causa raiz** | O modo inseguro era o **padrão**, escrito no código. Qualquer execução, em qualquer ambiente, ligava o debugger |
| **Correção** | O debug passou a ser controlado pela variável de ambiente `FLASK_DEBUG`, desligada por padrão. Host e porta seguem o mesmo modelo. No Docker, o servidor passou a ser o Gunicorn, que não tem debugger |
| **Por que resolve** | Apagar a linha e religá-la quando necessário dependeria de alguém lembrar de desligar antes de publicar. Agora o caminho padrão é o seguro (*secure by default*) e o modo inseguro exige um pedido explícito |

```python
debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
app.run(host=host, port=port, debug=debug_mode)
```

**Resultado:** o corpo `null` em `/users/create` retorna `400 {"error":"Invalid JSON body"}`, sem traceback, e `/console` retorna 404.

### 6.2 VULN-05: Token de sessão apenas no header `Authorization`

**Commit:** `8b34411` · **Arquivos:** `backend/endpoints.py`, `frontend/src/api.ts`

| | |
|---|---|
| **Causa raiz** | Não havia um ponto único de autenticação. Cada rota lia o token de um lugar (URL, corpo ou header) e repetia a verificação, e essa inconsistência levou o frontend a enviá-lo na URL |
| **Correção** | Criado o decorator `require_auth`, que aceita o token **somente** no header `Authorization: Bearer`, valida-o e disponibiliza o `uid` autenticado. Todas as rotas protegidas passaram a usá-lo, e o frontend passou a enviar o token só pelo header |
| **Por que resolve** | Remover o `?id_token=` de uma chamada corrigiria apenas aquele caso. Com a autenticação centralizada, o token só pode vir de um lugar, que não é registrado em logs, e toda rota nova com `@require_auth` herda o comportamento correto |

**Resultado:** token na URL ou no corpo retorna `401`, e o log de acesso não contém mais o token.

### 6.3 VULN-03: Erros genéricos e fim da enumeração de usuários

**Commit:** `2f9a3f8` · **Arquivo:** `backend/endpoints.py`

| | |
|---|---|
| **Causa raiz** | O código não separava a informação para o desenvolvedor (detalhe técnico do erro) da resposta para o usuário: cada rota devolvia `str(e)` |
| **Correção** | **1.** O detalhe do erro vai só para o log do servidor (`logger.exception`), e o cliente recebe uma mensagem fixa. **2.** O cadastro responde com a mesma mensagem para qualquer falha do Firebase; formato do e-mail e tamanho da senha são validados antes, para manter o retorno útil ao usuário. **3.** *Handlers* globais de erro como rede de segurança. **4.** Validação de que o corpo é um objeto JSON |
| **Por que resolve** | Trocar só a mensagem do cadastro deixaria as outras rotas vazando informação. A política "detalhe no log, mensagem genérica na resposta" vale para todas as rotas e é garantida pelo *handler* global, inclusive para rotas futuras |

| Teste | Antes | Depois |
|---|---|---|
| Cadastro com e-mail existente | `...already exists (EMAIL_EXISTS)` | `Could not create account. Check your data or try logging in.` |
| Corpo `null` | 500 com traceback | `400 Invalid JSON body` |
| Token inválido | `Error verifying ID token: Wrong number of segments...` | `401 Invalid or expired token` |

**Limitação:** o login ocorre diretamente entre o navegador e o Firebase. Para fechar a enumeração também nesse fluxo, é preciso ativar a *Email Enumeration Protection* no console do Firebase (ver [seção 10](#10-recomendações-priorizadas)).

### 6.4 VULN-01: Mitigação parcial

**Commits:** `40adb1e`, `69b0610`, `f83b497`

Não é possível "corrigir" um segredo que já ficou exposto sem trocá-lo, o que depende de acesso aos consoles do Firebase e da OpenAI. No código, foram tratadas as formas de vazamento:

- o caminho da credencial passou a vir de variável de ambiente (`FIREBASE_CREDENTIALS`);
- `.dockerignore` no backend e no frontend impede que segredos entrem nas imagens;
- no Docker, a credencial é montada como *secret*, somente leitura, em tempo de execução.

**Pendente:** rotação das chaves e uso de um cofre de segredos.

---

## 7. Hardening

Foram implementadas quatro melhorias de segurança além da especificação original. Elas corrigem as VULN-04, 06, 07 e 08 e reforçam as correções anteriores.

| Melhoria | Commit | Vulnerabilidade tratada |
|---|---|---|
| Rate limiting | `76537a3` | VULN-04 |
| Headers de segurança HTTP e CORS restrito | `8375e42` | VULN-07 |
| Validação de entrada e limite de tamanho | `83b9ed8` | VULN-06 |
| Logout no servidor com revogação de tokens | `aa8b012` | VULN-08 |

### 7.1 Rate limiting

Flask-Limiter, por endereço IP, com contadores em Redis compartilhado quando há várias instâncias:

| Rota | Limite |
|---|---|
| Todas | 200 por minuto |
| `POST /users/create` | 5 por minuto e 20 por hora |
| `POST /users/query` | 20 por minuto |

Acima do limite, a resposta é `429 Too Many Requests`, com o header `Retry-After`. Atrás do Nginx, o IP real do cliente é lido do `X-Forwarded-For` (`ProxyFix`). Sem isso, todos os usuários apareceriam com o IP do proxy.

### 7.2 Headers de segurança e CORS

| Header (API) | Função |
|---|---|
| `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` | A API só serve JSON: nenhum script, estilo ou frame |
| `X-Frame-Options: DENY` | Impede exibição em `<iframe>` (clickjacking) |
| `X-Content-Type-Options: nosniff` | Impede *MIME sniffing* |
| `Referrer-Policy: no-referrer` | Não envia a URL de origem a terceiros |
| `Strict-Transport-Security` | Força HTTPS quando houver TLS |
| `Cache-Control: no-store` | Dados do usuário não ficam em cache |

O CORS passou a aceitar apenas as origens do frontend (variável `CORS_ORIGINS`). No Docker, o Nginx adiciona ao site uma CSP específica, que libera apenas o próprio domínio e os serviços de autenticação do Firebase.

### 7.3 Validação de entrada

Novo módulo `backend/validation.py`, baseado em *allowlist*: só campos conhecidos são gravados, com tipo, tamanho e valores permitidos.

| Dado | Regra |
|---|---|
| `year` | freshman, sophomore, junior, senior ou graduate |
| `about` | até 2000 caracteres |
| `majors`, `minors`, `courses` | listas de textos curtos, com número máximo de itens |
| Mensagens de chat | até 50 por requisição; remetente `user` ou `bot` |
| `chat_id` | apenas `[A-Za-z0-9_-]` |
| Pergunta ao assistente | até 1000 caracteres |
| Qualquer requisição | corpo de até 256 KB (`413` acima disso) |

### 7.4 Logout com revogação

Nova rota `POST /auth/logout`, que revoga os tokens do usuário no Firebase. Toda validação de token passou a usar `check_revoked=True`, e o botão de logout do site chama essa rota antes de encerrar a sessão local.

**Efeitos colaterais aceitos:** o logout encerra a sessão em todos os dispositivos do usuário, e cada requisição autenticada faz uma consulta adicional ao Firebase.

---

## 8. Verificação das correções

### 8.1 Testes automatizados

Foram escritos **42 testes** com `pytest` (`backend/tests/`). O Firebase é substituído por um dublê em memória, com dois usuários fictícios, para que os testes rodem sem credenciais e sem criar contas reais.

| Grupo | O que comprova | Testes |
|---|---|---|
| Regressão | Perfil, chats, consulta e cadastro continuam funcionando | 4 |
| Controle de acesso | Um usuário não lê, lista nem apaga dados de outro | 3 |
| Modo debug (VULN-02) | Desligado por padrão; só liga com `FLASK_DEBUG=1` | 3 |
| Mensagens de erro (VULN-03) | Sem enumeração e sem detalhes internos | 5 |
| Token de sessão (VULN-05, 08) | Aceito só no header; revogado no logout | 5 |
| Rate limiting (VULN-04) | Bloqueio após o limite, com `Retry-After` | 3 |
| Headers e CORS (VULN-07) | Headers presentes; origens desconhecidas recusadas | 3 |
| Validação (VULN-06) | Valores inválidos, excesso e campos extras recusados | 7 |
| Observabilidade | `/health`, `/metrics`, `request_id` e logs sem dados sensíveis | 9 |

**Comparação entre versões:**

| Versão | Resultado | Evidência |
|---|---|---|
| Original (`0b60ef1`) | **22 de 33 testes de segurança falham** | `evidencias/pytest_versao_original.txt` |
| Corrigida | **42 de 42 testes passam** | `evidencias/pytest_versao_corrigida.txt` |

As falhas na versão original confirmam que os testes detectam as vulnerabilidades, e não apenas validam o código novo.

### 8.2 Ferramentas de análise

| Ferramenta | Versão original | Versão corrigida |
|---|---|---|
| Bandit: severidade alta | 1 (B201, modo debug) | **0** |
| Bandit: severidade média | 6 (B608, VULN-10) | 6 (VULN-10, documentada) |
| pip-audit | — | Nenhuma vulnerabilidade conhecida |
| npm audit | 14 (5 altas, 9 moderadas) | 14 (VULN-09, pendente) |

### 8.3 Pipeline de segurança (CI)

As verificações rodam automaticamente a cada push e *pull request* (`.github/workflows/security.yml`):

| Job | Ferramenta | Bloqueia o merge? |
|---|---|---|
| Testes automatizados | pytest | Sim |
| SAST | Bandit | Sim, para severidade alta |
| SCA backend | pip-audit | Sim |
| SCA frontend | npm audit | Não, enquanto a VULN-09 estiver pendente; o relatório é salvo como artefato |
| Build do frontend | TypeScript + Vite | Sim |

O workflow usa permissão mínima (`contents: read`). O **Dependabot** verifica semanalmente as dependências de pip, npm, imagens Docker e GitHub Actions.

Evidência da execução: `evidencias/github_actions_checks.png`.

---

## 9. Confiabilidade (SRE)

### 9.1 Observabilidade implementada

**Logs estruturados.** Cada evento é uma linha JSON (`backend/observability.py`):

```json
{"timestamp":"2026-10-27T21:56:17.44+00:00","level":"INFO","message":"request","instance":"backend-1",
 "request_id":"7d5a917f0fe8414ca0d25c1cea96fb79","method":"POST","path":"/users/info",
 "status":200,"duration_ms":0.27,"client_ip":"127.0.0.1","uid":"alice"}
```

| Evento | Conteúdo |
|---|---|
| `request` | Toda requisição: rota, status, duração, IP e usuário. Nível WARNING para 4xx e ERROR para 5xx |
| `auth.*` | Token ausente ou inválido, cadastro (sucesso ou falha), logout |
| Erros internos | Exceções com traceback completo, apenas no log |

- **Rastreabilidade:** cada requisição recebe um `request_id`, devolvido no header `X-Request-ID` e repassado pelo Nginx.
- **Privacidade:** tokens, senhas, e-mails, corpo das requisições e query strings nunca são registrados.

**Endpoints:**

| Endpoint | Função |
|---|---|
| `GET /health` | *Liveness*: `{"status":"ok","instance":...,"uptime_seconds":...}`. Usado pelo Docker e pelo balanceador |
| `GET /metrics` | Métricas Prometheus. No Docker, bloqueado no Nginx para acesso externo |

**Métricas:**

| Métrica | Tipo | Uso |
|---|---|---|
| `http_requests_total{method,endpoint,status}` | Contador | Volume e taxa de erros por rota |
| `http_request_duration_seconds{method,endpoint}` | Histograma | Latência (p50, p95, p99) |
| `auth_events_total{event,result}` | Contador | Eventos de autenticação e sinais de ataque |

As métricas usam o padrão da rota (`/chats/<chat_id>`), e não a URL real, para evitar alta cardinalidade.

### 9.2 SLIs e SLOs

| | SLI 1: Disponibilidade | SLI 2: Latência |
|---|---|---|
| **Definição** | Proporção de requisições a `/users/info` e `/chats*` que **não** retornam erro 5xx | Proporção de `GET /users/info` e `GET /chats` respondidas em **menos de 800 ms** |
| **Por que este indicador** | Perfil e histórico são a função principal da aplicação | É o carregamento do Dashboard e do chat, a primeira interação do usuário |
| **SLO** | **99,5%** em janela móvel de 30 dias | **95%** abaixo de 800 ms em 30 dias |
| **Orçamento de erro** | 0,5%, cerca de 3h36min por mês | 5% das requisições |

Erros 4xx (token inválido, validação, rate limit) **não** contam contra a disponibilidade, porque representam o sistema respondendo corretamente a uma requisição inválida. O limite de 800 ms considera que cada requisição autenticada faz pelo menos duas chamadas ao Firebase: validação do token com revogação e leitura dos dados.

```promql
# SLI 1: disponibilidade
sum(rate(http_requests_total{endpoint=~"/users/info|/chats.*", status!~"5.."}[30d]))
/ sum(rate(http_requests_total{endpoint=~"/users/info|/chats.*"}[30d]))

# SLI 2: latência
sum(rate(http_request_duration_seconds_bucket{method="GET", endpoint=~"/users/info|/chats", le="0.8"}[30d]))
/ sum(rate(http_request_duration_seconds_count{method="GET", endpoint=~"/users/info|/chats"}[30d]))
```

### 9.3 Dashboard proposto (Grafana + Prometheus)

| Linha | Público | Painéis |
|---|---|---|
| **1. Metas (SLO)** | Gestão | Disponibilidade nos últimos 30 dias (verde ≥ 99,5%); latência dentro do SLO (verde ≥ 95%); orçamento de erro restante, em *gauge* |
| **2. Saúde do serviço** | Operação | Requisições por segundo por rota; taxa de 5xx; latência p50, p95 e p99; instâncias no ar (`up`); requisições por instância, para mostrar o equilíbrio do balanceamento |
| **3. Segurança** | AppSec | Tokens inválidos por minuto; respostas `429` (rate limit) por minuto; cadastros com falha |

**Alertas sugeridos:**

| Alerta | Condição |
|---|---|
| Queima rápida do orçamento de erro | Taxa de 5xx acima de 7,2% (14,4× o permitido) por 5 min e por 1 h. Nesse ritmo, o orçamento mensal acaba em cerca de 2 dias |
| Latência | p95 acima de 800 ms por 10 min |
| Instância fora do ar | `up == 0` por 1 min |
| Possível ataque | Mais de 50 tokens inválidos ou mais de 100 respostas `429` por minuto |

### 9.4 Arquitetura e escalabilidade

```
Navegador ──► Nginx :8080 ─┬─► /         → frontend (arquivos estáticos)
                           └─► /api/...  → round-robin ─┬─► backend-1 (Gunicorn) ─┐
                                                        └─► backend-2 (Gunicorn) ─┴─► Redis (rate limit)
```

| Decisão | Motivo |
|---|---|
| Nginx como balanceador e servidor do site | Ponto único de entrada (só a porta 8080 exposta) e mesma origem para site e API, o que dispensa CORS no navegador |
| Round-robin com `max_fails` e `proxy_next_upstream` | Se uma instância falhar, é retirada do pool e a requisição vai para a outra |
| Health checks no `/health` | O Docker só considera um backend pronto quando ele responde, e o Nginx só sobe depois disso |
| Gunicorn, 1 processo e 4 threads por container | Servidor de produção; a escala é horizontal (mais containers), e um processo por container mantém as métricas consistentes |
| Redis compartilhado | O rate limit vale para o conjunto, e não para cada instância |
| Containers sem root, sistema de arquivos somente leitura, `no-new-privileges`, `cap_drop: ALL` | Reduz o impacto de uma eventual invasão do container |

**Demonstração** (`scripts/demo_balanceamento.ps1`, evidência em `evidencias/docker_balanceamento.png`): 10 requisições pelo Nginx, 5 atendidas por `backend-1` e 5 por `backend-2`, em alternância. Os quatro containers aparecem como `healthy`.

**Testes de resiliência:**

| Teste | Resultado |
|---|---|
| Uma instância derrubada durante as requisições | Nenhuma requisição falhou; a outra instância assumiu |
| 7 cadastros alternando entre as instâncias | 5 aceitos e 2 bloqueados: o limite foi compartilhado |
| `X-Forwarded-For` forjado pelo cliente | Ignorado; o Nginx sobrescreve o header |
| Corpo acima de 256 KB | Recusado no próprio Nginx (`413`) |

### 9.5 Riscos de disponibilidade

| Risco | Impacto | Probabilidade | Recomendação |
|---|---|---|---|
| **Dependência total do Firebase** (Auth e banco) | Alto: login, perfil e chats param | Baixa | *Timeouts* curtos, *circuit breaker* e mensagens claras de indisponibilidade |
| **Nginx como ponto único de falha** | Alto: o site sai do ar | Média | Balanceador gerenciado (ex.: AWS ALB) ou Nginx redundante |
| **Redis como ponto único de falha** | Médio: o rate limit para de funcionar | Média | Redis com réplica e política definida para quando ele falhar |
| **Execução em um único host** | Alto: falha da máquina derruba tudo | Média | Kubernetes com réplicas em zonas diferentes e escala automática |
| **Health check apenas de *liveness*** | Médio: uma instância sem acesso ao Firebase continua recebendo tráfego | Média | Endpoint `/ready` que verifique as dependências |
| **Validação de revogação a cada requisição** | Médio: aumenta a latência e a dependência do Firebase | Alta | Monitorar o SLI 2; se necessário, cache curto da verificação |
| **Ausência de HTTPS** | Alto em produção: tokens em texto claro na rede | — | TLS no balanceador. O header HSTS já está configurado |

---

## 10. Recomendações priorizadas

A ordem considera o risco ao negócio e o esforço necessário. Os itens 1 a 4 não dependem de código.

| # | Ação | Risco tratado | Esforço | Responsável |
|---|---|---|---|---|
| **1** | Trocar a chave da *service account* do Firebase e a chave da OpenAI | VULN-01 (Crítica) | Baixo | Dono da conta |
| **2** | Revisar as regras de segurança (*Security Rules*) do Realtime Database: como o frontend não acessa o banco diretamente, elas podem negar todo acesso direto | Acesso ao banco sem passar pela API | Baixo | Dono da conta |
| **3** | Ativar a *Email Enumeration Protection* no Firebase Authentication | VULN-03 (fluxo de login) | Baixo | Dono da conta |
| **4** | Guardar segredos em um cofre (Secrets Manager, Vault) e tirá-los da pasta do projeto | VULN-01 | Médio | Infra |
| **5** | Atualizar o SDK `firebase` e o `react-router-dom` no frontend, testar e tornar o npm audit bloqueante no CI | VULN-09 | Médio | Dev |
| **6** | Fixar as versões do `requirements.txt` (ex.: `pip-compile`) | VULN-09 | Baixo | Dev |
| **7** | Reescrever `blueprints/courses.py` com consultas parametrizadas antes de ativá-lo | VULN-10 | Baixo | Dev |
| **8** | HTTPS no balanceador | Interceptação de tokens | Baixo | Infra |
| **9** | Endpoint `/ready`, *timeouts* e *circuit breaker* nas chamadas ao Firebase | Disponibilidade | Médio | Dev |
| **10** | Implantar Prometheus, Grafana e os alertas da seção 9.3 | Detecção de falhas e ataques | Médio | Infra |
| **11** | Remover pontos únicos de falha (balanceador gerenciado, Redis com réplica, múltiplos hosts) | Disponibilidade | Alto | Infra |
| **12** | Ao reativar o assistente (OpenAI), separar instruções e entrada do usuário no prompt e limitar o custo por usuário | Prompt injection, custo | Médio | Dev |

---

## 11. Anexos

### 11.1 Evidências

| Arquivo | Conteúdo |
|---|---|
| `evidencias/bandit_versao_original.txt` | Bandit no código original |
| `evidencias/npm_audit_versao_original.txt` | npm audit no código original |
| `evidencias/pytest_versao_original.txt` | Testes de segurança contra o código original (22 falhas) |
| `evidencias/pytest_versao_corrigida.txt` | Testes contra o código corrigido (42 aprovados) |
| `evidencias/docker_balanceamento.png` | Demonstração do balanceamento e estado dos containers |
| `evidencias/github_actions_checks.png` | Execução do pipeline de segurança no GitHub Actions |

### 11.2 Histórico de commits

| Commit | Descrição |
|---|---|
| `0b60ef1` | Versão base analisada |
| `26ca9a8` | Correção VULN-02: modo debug desligado por padrão |
| `8b34411` | Correção VULN-05: token só no header `Authorization` |
| `2f9a3f8` | Correção VULN-03: erros genéricos, sem enumeração |
| `76537a3` | Hardening: rate limiting (VULN-04) |
| `8375e42` | Hardening: headers de segurança e CORS (VULN-07) |
| `83b9ed8` | Hardening: validação de entrada (VULN-06) |
| `aa8b012` | Hardening: logout com revogação (VULN-08) |
| `9e16951` | Testes automatizados de segurança |
| `41b93db` | Evidências das ferramentas e testes |
| `ba7a884` | Observabilidade: logs JSON, `/health`, `/metrics` |
| `a0637da` | Testes de observabilidade |
| `40adb1e` | Configuração por variáveis de ambiente |
| `69b0610` | Dockerfiles do backend e do frontend |
| `f83b497` | docker-compose com Nginx e 2 backends |
| `b958862` | Evidência do balanceamento |
| `a3bb3cb` | Pipeline de segurança (CI) e Dependabot |
| `84b1a0c` | Evidência do pipeline |
| `da9d551` | Correção: `tsconfig.json` versionado |
| `2c01afe` | CI: build do frontend |
| `39f6565` | Correção: `/hash` sem erro 500 |
| `1af5a59` | README |

### 11.3 Como reproduzir

As instruções para rodar a aplicação, executar as ferramentas e reproduzir cada achado estão no [README.md](README.md).
