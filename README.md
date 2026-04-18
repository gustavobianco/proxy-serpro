# Proxy mTLS — SERPRO Integra Contador

Servidor Node.js mínimo que recebe requisições da Edge Function do Lovable Cloud e encaminha à SERPRO carregando o **certificado A1 (.pfx)** do escritório via **mTLS cliente**.

> **Por que isso existe:** o Edge Runtime do Deno (Supabase Functions) não suporta mTLS cliente nativo. A SERPRO exige cert A1 em toda chamada Integra Contador. Esse proxy resolve a limitação.

---

## Arquitetura

```
Frontend (Lovable)
   ↓
Edge Function `serpro-consultar-pgdas` (Supabase)
   ↓ POST /serpro/consultar  (header x-proxy-secret)
Proxy Node (este repositório, hospedado no Railway)
   ↓ POST integra-contador/v1/Consultar  (mTLS com cert A1 + Bearer OAuth)
SERPRO
```

A Edge Function só roteia via proxy quando os dois secrets estão definidos no Lovable Cloud:

- `SERPRO_PROXY_URL` — URL pública do proxy (ex: `https://serpro-proxy.up.railway.app`)
- `SERPRO_PROXY_SHARED_SECRET` — mesmo valor que está aqui como `PROXY_SHARED_SECRET`

Sem esses secrets, a edge function tenta direto e falha com `Resource forbidden` (sem mTLS).

---

## Pré-requisitos

- Conta no [Railway](https://railway.app) (ou Fly.io / Render / VPS — o `server.js` é portável)
- Certificado A1 do escritório no formato **`.pfx`** (ou `.p12`) com a senha
- Credenciais OAuth da loja SERPRO (`consumer_key` + `consumer_secret`) já cadastradas no Integra Contador

---

## Deploy no Railway — passo a passo

### 1. Subir o código

Opção A — via GitHub:
1. Crie um repositório novo contendo **apenas o conteúdo desta pasta** (`proxy-serpro/`)
2. Em Railway → **New Project → Deploy from GitHub Repo** → selecione o repositório
3. Railway detecta o `package.json` e o `railway.json` automaticamente

Opção B — via CLI:
```bash
cd proxy-serpro
npm install -g @railway/cli
railway login
railway init
railway up
```

### 2. Criar um Volume para o certificado

O `.pfx` **nunca** entra no Git. Use um Volume persistente do Railway:

1. No projeto Railway → **Settings → Volumes → New Volume**
2. Mount path: `/data`
3. Tamanho: 1 GB (mais que suficiente)

### 3. Subir o cert.pfx para o Volume

Use a Railway CLI para abrir um shell na instância e copiar o arquivo:

```bash
# A partir da máquina onde está o cert.pfx
railway link                        # selecione o projeto/serviço
railway run bash                    # abre shell na instância
# Em outro terminal local:
railway shell -- cat > /data/cert.pfx < ./cert.pfx
```

Alternativa simples: hospede o `.pfx` num bucket privado temporário (ex: S3 pré-assinado por 5min) e dentro do shell rode:
```bash
curl -o /data/cert.pfx "<URL-pré-assinada>"
chmod 600 /data/cert.pfx
```

Depois **remova a URL pré-assinada**.

### 4. Configurar variáveis de ambiente

No Railway → **Variables**, adicione (use `.env.example` como referência):

| Variável | Valor |
|---|---|
| `PROXY_SHARED_SECRET` | gere um UUID v4 (ex: `uuidgen` ou `crypto.randomUUID()`) |
| `SERPRO_AMBIENTE` | `trial`, `demonstracao` ou `producao` |
| `SERPRO_CONSUMER_KEY` | da loja SERPRO |
| `SERPRO_CONSUMER_SECRET` | da loja SERPRO |
| `SERPRO_CERT_PATH` | `/data/cert.pfx` |
| `SERPRO_CERT_PASSWORD` | senha do `.pfx` |
| `CONTRATANTE_CNPJ` | CNPJ do escritório (só dígitos) |
| `AUTOR_PEDIDO_CNPJ` | opcional, default = `CONTRATANTE_CNPJ` |

> `PORT` é injetado automaticamente pelo Railway — não precisa setar.

### 5. Validar deploy

Após o deploy, Railway expõe uma URL pública (ex: `https://serpro-proxy-production.up.railway.app`).

Teste o healthcheck:
```bash
curl https://<sua-url>.up.railway.app/healthz
# → {"ok":true,"ambiente":"trial","ts":"..."}
```

Teste uma consulta (substitua o secret e os valores):
```bash
curl -X POST https://<sua-url>.up.railway.app/serpro/consultar \
  -H "Content-Type: application/json" \
  -H "x-proxy-secret: <PROXY_SHARED_SECRET>" \
  -d '{"cliente_cnpj":"00000000000000","competencia":"202403"}'
```

Se o cert A1 estiver correto, a SERPRO responde com `http_status: 200` e o payload do PGDAS-D. Se ainda retornar 403, o problema está no certificado / autorização da empresa, não no proxy.

### 6. Conectar ao Lovable Cloud

No Lovable Cloud, adicione os dois secrets:
- `SERPRO_PROXY_URL` = a URL do Railway (sem barra final)
- `SERPRO_PROXY_SHARED_SECRET` = o mesmo valor de `PROXY_SHARED_SECRET`

A Edge Function `serpro-consultar-pgdas` passa a rotear automaticamente via proxy nas próximas execuções.

---

## Rodando localmente (debug)

```bash
cd proxy-serpro
cp .env.example .env
# preencha .env e coloque o cert.pfx em ./cert.pfx
# ajuste SERPRO_CERT_PATH=./cert.pfx
npm install
npm run dev
```

Em outro terminal:
```bash
curl -X POST http://localhost:3000/serpro/consultar \
  -H "Content-Type: application/json" \
  -H "x-proxy-secret: <seu-shared-secret>" \
  -d '{"cliente_cnpj":"00000000000000","competencia":"202403"}'
```

---

## Endpoints

### `GET /healthz`
Liveness probe. Retorna `{ ok: true, ambiente, ts }`.

### `POST /serpro/consultar`

**Headers:**
- `x-proxy-secret: <PROXY_SHARED_SECRET>` (obrigatório)
- `Content-Type: application/json`

**Body:**
```jsonc
{
  "cliente_cnpj": "00000000000000",       // 14 dígitos, com ou sem máscara
  "competencia": "202403",                // YYYYMM
  "jwt": "<jwt-procuração>",              // opcional (só plano com API de procurações)
  "id_sistema": "PGDASD",                 // opcional, default
  "id_servico": "CONSULTIMADECREC14",     // opcional, default
  "versao_sistema": "1.0",                // opcional
  "dados": { "periodoApuracao": 202403 }  // opcional, default = { periodoApuracao: <competencia> }
}
```

**Resposta (sucesso):**
```jsonc
{
  "ok": true,
  "http_status": 200,
  "ambiente": "trial",
  "duracao_ms": 842,
  "payload": { /* resposta crua da SERPRO */ }
}
```

**Resposta (erro):**
```jsonc
{
  "ok": false,
  "http_status": 403,
  "ambiente": "trial",
  "duracao_ms": 350,
  "payload": { "message": "..." }
}
```

---

## Segurança

- `PROXY_SHARED_SECRET` é a única defesa contra chamadas não autorizadas — **trate como senha**, gere com 32+ bytes aleatórios e troque se vazar
- O `.pfx` nunca entra no repositório; vive só no Volume do Railway com `chmod 600`
- O proxy não persiste nada — só repassa requests/responses
- Considere ativar **Private Networking** no Railway e expor o serviço só via referer/IP allowlist se possível

---

## Troubleshooting

| Sintoma | Causa provável | Ação |
|---|---|---|
| `boot: variável obrigatória ausente` | env var faltando no Railway | conferir Variables |
| `boot: falha ao ler certificado` | path errado ou Volume não montado | conferir `SERPRO_CERT_PATH` e mount path |
| `OAuth 401` | consumer_key/secret errados ou ambiente errado | conferir credenciais e `SERPRO_AMBIENTE` |
| `http_status: 403` em `/serpro/consultar` | cert A1 inválido, vencido, ou sem habilitação no Integra Contador | conferir validade do cert e contratação SERPRO |
| `http_status: 401` com `jwt_token` | JWT de procuração expirado | renovar (só aplicável no plano "com API de procurações") |
| Edge Function ainda dá `Resource forbidden` | secrets `SERPRO_PROXY_URL`/`SERPRO_PROXY_SHARED_SECRET` não setados no Lovable Cloud | adicionar secrets e reexecutar |
