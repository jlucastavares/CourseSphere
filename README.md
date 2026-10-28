# CourseSphere: Desafio Técnico AppSec & SRE

Este repositório é a minha entrega para o desafio técnico de Segurança de Aplicações e Confiabilidade. Peguei o CourseSphere, uma aplicação web em que estudantes montam um perfil e conversam com um chatbot sobre cursos, e trabalhei nele em quatro frentes:

- encontrar vulnerabilidades reais e corrigir as mais importantes;
- reforçar a segurança além do que a aplicação pedia;
- instrumentar logs e métricas;
- containerizar tudo com balanceamento de carga.

A stack não é a sugerida no enunciado (Rails). O backend é **Flask (Python)**, o frontend é **React + TypeScript**, e autenticação e banco de dados ficam no **Firebase** (Authentication e Realtime Database). O desafio permite outra stack desde que cubra autenticação, CRUD e consumo de API. Aqui o "CRUD" é o perfil do estudante e o histórico de chats de cada usuário.

O relatório completo, com as vulnerabilidades, as correções, os SLIs/SLOs e as recomendações, está em **[RELATORIO.md](RELATORIO.md)**. Este README explica como rodar o projeto e como conferir o que foi feito.

---

## O que mudou em relação ao código original

O primeiro commit (`0b60ef1`) é o código exatamente como recebi (apenas criei o config.json com uma nova chave da openAi e criei um firebase próprio para conseguir rodar a aplicação localmente). Cada mudança depois dele está em um commit separado, então dá para ver o antes e o depois de cada correção com `git show <commit>`.

Em resumo:

- **Análise:** 10 vulnerabilidades encontradas, de configuração insegura a SQL Injection latente.
- **Correções:** o modo debug do Flask ligado por padrão, o token de sessão trafegando na URL e mensagens de erro que permitiam descobrir quais e-mails tinham conta.
- **Hardening:**
  - rate limiting;
  - headers de segurança e CORS restrito;
  - validação de tudo o que o cliente envia;
  - logout que de fato invalida o token no servidor.
- **Observabilidade:** logs em JSON, `/health`, `/metrics` (Prometheus) e definição de SLIs/SLOs.
- **Infraestrutura:** Docker, com Nginx na frente de duas instâncias do backend e um Redis compartilhado.
- **Verificação contínua:** a cada push, o GitHub Actions roda testes, Bandit, pip-audit, npm audit e o build do frontend.

## Estrutura

```
backend/            API em Flask
  endpoints.py        rotas, autenticação e tratamento de erros
  validation.py       validação de entrada
  observability.py    logs JSON, /health e /metrics
  tests/              testes automatizados (pytest)
frontend/           React + TypeScript (Vite)
nginx/nginx.conf    balanceador de carga e servidor do frontend
docker-compose.yml  sobe nginx + 2 backends + redis
scripts/            script que demonstra o balanceamento
evidencias/         saídas das ferramentas e prints
.github/workflows/  pipeline de segurança
```

---

## Como rodar

### Pré-requisito: credencial do Firebase

O backend precisa de uma credencial de *service account* do Firebase em `backend/credentials.json`. Ela **não está no repositório**, de propósito. Para gerar uma: no console do Firebase, vá em *Configurações do projeto → Contas de serviço → Gerar nova chave privada* e salve o arquivo nesse caminho.

Sem a credencial, os **testes automatizados continuam funcionando**, porque usam um Firebase simulado. Ver a seção [Testes](#testes).

### Com Docker (recomendado)

Precisa do Docker Desktop aberto.

```bash
docker compose up --build
```

Quando os containers aparecerem como `healthy`, o site estará em **http://localhost:8080**. A API responde no mesmo endereço, em `/api/...`.

Para ver o balanceamento funcionando, num segundo terminal:

```powershell
# Windows
powershell -ExecutionPolicy Bypass -File scripts\demo_balanceamento.ps1
```
```bash
# Linux/Mac
sh scripts/demo_balanceamento.sh
```

Cada linha mostra qual instância (`backend-1` ou `backend-2`) respondeu. O resultado que obtive está em `evidencias/docker_balanceamento.png`. Para desligar tudo: `docker compose down`.

### Sem Docker (desenvolvimento)

Backend (Python 3.12 ou mais recente):

```bash
cd backend
python -m venv venv
venv\Scripts\activate          # Windows  (Linux/Mac: source venv/bin/activate)
pip install -r requirements-dev.txt
python endpoints.py
```

A API sobe em `http://127.0.0.1:5000`. A primeira linha do log é um JSON com `"server.start"`. O modo debug fica **desligado**, a menos que se defina `FLASK_DEBUG=1`.

Frontend (Node 20), em outro terminal:

```bash
cd frontend
npm install
npm run dev
```

O site abre em `http://localhost:5173`.

---

## Testes

```bash
cd backend
pip install -r requirements-dev.txt
python -m pytest -v
```

São 42 testes. A maioria reproduz um ataque encontrado na análise e confirma que ele está bloqueado, por exemplo:

- token enviado pela URL;
- um usuário tentando ler os dados de outro;
- cadastro com e-mail já existente;
- 7 cadastros seguidos;
- remetente de mensagem forjado.

Os outros garantem que o uso normal (perfil, chats, consulta, cadastro) continua funcionando.

Os testes não acessam o Firebase de verdade: ele é substituído por uma versão em memória (`tests/conftest.py`). Por isso rodam em qualquer máquina e no CI, sem credencial.

Rodei a mesma bateria na versão original do código: **22 testes falham** lá e **todos passam** na versão atual. As duas saídas estão em `evidencias/`.

## Ferramentas de segurança

| Ferramenta | Para quê | Como rodar |
|---|---|---|
| Bandit | Análise estática do Python (SAST) | `bandit -r backend -x backend/tests,backend/venv,backend/cornell-course-sphere-data` |
| pip-audit | Dependências Python com CVE (SCA) | `pip-audit -r backend/requirements.txt` |
| npm audit | Dependências do frontend com CVE (SCA) | `cd frontend && npm audit --omit=dev` |
| pytest | Testes de segurança e regressão | ver acima |

As quatro rodam automaticamente a cada push (`.github/workflows/security.yml`), junto com o build do frontend. O Dependabot está configurado para avisar sobre atualizações de dependências.

O npm audit ainda aponta vulnerabilidades no SDK do Firebase usado pelo frontend. Por isso ele gera o relatório mas não bloqueia o pipeline; o motivo está explicado no relatório.

---

## Como reproduzir os achados

O jeito mais simples é rodar os testes na versão original:

```bash
git checkout 0b60ef1 -- backend/endpoints.py   # volta só a API para a versão original
cd backend && python -m pytest -q tests/test_security.py   # 22 testes falham
cd .. && git checkout HEAD -- backend/endpoints.py   # restaura a versão corrigida
```

Para reproduzir manualmente, suba a versão original do backend (`git checkout 0b60ef1`) e use os comandos abaixo. Nas rotas autenticadas, é preciso um ID token do Firebase, que pode ser obtido pela API REST de login, usando a `apiKey` de `frontend/src/firebaseConfig.ts`:

```bash
curl -s "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=<apiKey>" \
  -H "Content-Type: application/json" \
  -d '{"email":"seu-usuario-de-teste@exemplo.com","password":"senha","returnSecureToken":true}'
# o campo "idToken" da resposta é o token
```

Alguns dos achados principais:

```bash
# Modo debug: um corpo "null" derruba a rota e devolve a página do Werkzeug Debugger
curl -X POST http://127.0.0.1:5000/users/create -H "Content-Type: application/json" -d 'null'

# Enumeração de usuários: a resposta diz que o e-mail já existe (EMAIL_EXISTS)
curl -X POST http://127.0.0.1:5000/users/create -H "Content-Type: application/json" \
  -d '{"email":"um-email-ja-cadastrado@exemplo.com","password":"Senha@123"}'

# Token na URL: aceito pelo backend e gravado no log de acesso do Flask
curl "http://127.0.0.1:5000/users/info?id_token=<token>"

# Sem rate limiting: 50 cadastros seguidos, nenhum bloqueado
for i in $(seq 1 50); do curl -s -o /dev/null -w "%{http_code} " -X POST \
  http://127.0.0.1:5000/users/create -H "Content-Type: application/json" \
  -d "{\"email\":\"teste$i@exemplo.com\",\"password\":\"123456\"}"; done
```

Na versão atual, os mesmos comandos retornam, respectivamente:

- `400 Invalid JSON body`;
- uma mensagem genérica de falha no cadastro;
- `401`, sem o token aparecer em nenhum log;
- `429 Too Many Requests` a partir da 6ª tentativa.

O passo a passo de cada vulnerabilidade, com severidade e impacto, está no [RELATORIO.md](RELATORIO.md).

## Observabilidade

| Endpoint | O que mostra |
|---|---|
| `GET /health` | Se a instância está no ar: `{"status":"ok","instance":...}` |
| `GET /metrics` | Métricas no formato Prometheus: requisições por rota e status, latência e eventos de autenticação |

No Docker, `/api/health` é público e `/api/metrics` é bloqueado no Nginx. As métricas ficam só para a rede interna.

Os logs saem em JSON, uma linha por evento, com `request_id`, instância, rota, status e duração. Tokens, senhas e e-mails nunca são registrados. Os SLIs/SLOs e a proposta de dashboard estão no relatório.

---