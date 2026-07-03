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

### 2. Subir o certificado A1

O proxy aceita **dois métodos**. Use o que for mais prático.

#### Método A — Volume + arquivo `.pfx` binário (recomendado)

1. No projeto Railway → **Settings → Volumes → New Volume**
2. Mount path: `/data`, tamanho 1 GB
3. Suba o `.pfx` **binário** (NÃO converter para base64) pra `/data/cert.pfx`:

```bash
railway link
railway shell -- cat > /data/cert.pfx < ./cert.pfx
chmod 600 /data/cert.pfx
```

Ou via URL pré-assinada temporária (S3/Drive) dentro do shell:
```bash
curl -o /data/cert.pfx "<URL-pré-assinada>"
chmod 600 /data/cert.pfx
```
Depois **revogue a URL**. Configure `SERPRO_CERT_PATH=/data/cert.pfx`.

#### Método B — Variável de ambiente em base64

Quando não dá pra montar Volume, gere o base64 do `.pfx`:

```bash
base64 -w0 cert.pfx
# cole o resultado em SERPRO_CERT_BASE64 no Railway → Variables
```

Se `SERPRO_CERT_BASE64` estiver definida e não-vazia, ela tem prioridade sobre `SERPRO_CERT_PATH`.

> **Autodetect:** se você acidentalmente subir um `.pfx` em base64 (texto ASCII) pro Volume, o proxy detecta no boot e decodifica automaticamente — vai aparecer no log `base64 detectado, decodificado`.

> **Validação no boot:** o proxy tenta abrir o PKCS#12 com a senha logo no boot. Se a senha estiver errada ou o arquivo não for um `.pfx` válido, o container falha imediatamente com mensagem clara — você não precisa esperar a primeira chamada à SERPRO pra descobrir o problema.

### 3. Configurar variáveis de ambiente

No Railway → **Variables**, adicione (use `.env.example` como referência):

| Variável | Valor |
|---|---|
| `PROXY_SHARED_SECRET` | gere um UUID v4 (ex: `uuidgen` ou `crypto.randomUUID()`) |
| `SERPRO_AMBIENTE` | `trial`, `demonstracao` ou `producao` |
| `SERPRO_CONSUMER_KEY` | da loja SERPRO |
| `SERPRO_CONSUMER_SECRET` | da loja SERPRO |
| `SERPRO_CERT_PATH` | `/data/cert.pfx` (Método A) — opcional se usar Método B |
| `SERPRO_CERT_BASE64` | conteúdo do `.pfx` em base64 (Método B) — opcional se usar Método A |
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

### `POST /esocial/eventos/identificadores`

Consulta os identificadores (`id` + `nrRec`) dos eventos **não periódicos/não
trabalhistas** de um empregador (folha de pagamento, totalizadores etc — ex:
S-1200, S-1210, S-1299) em um período. É o primeiro passo antes de baixar o
XML de cada evento. Fala direto com o Web Service SOAP oficial do eSocial
(`webservices.download.esocial.gov.br`), **não** com o Integra Contador —
usa o mesmo certificado A1 do escritório (com a outorga de poderes/procuração
para o cliente) já cadastrado em `/configuracoes`.

**Headers:** iguais a `/serpro/*` (`x-proxy-secret` obrigatório).

**Body:**
```jsonc
{
  "escritorio_id": "uuid-do-escritorio",
  "cliente_cnpj": "00000000000000",  // CNPJ do cliente (usa só a raiz, 8 dígitos) ou CPF (11 dígitos)
  "tp_evt": "S-1200",                // tipo do evento, 6 caracteres
  "per_apur": "2026-06"              // "AAAA-MM" ou "AAAA"
}
```

**Resposta (sucesso):**
```jsonc
{
  "ok": true,
  "http_status": 200,
  "duracao_ms": 842,
  "cert": { "thumbprint": "...", "validade_em": "..." },
  "status": { "cd_resposta": "0", "desc_resposta": "Sucesso" },
  "qtde_tot_evts_consulta": 2,
  "dh_ultimo_evt_retornado": "2026-06-30T23:59:59",
  "eventos": [
    { "id": "ID1000000000000000000000001", "nrRec": "1.0/AAAAA" },
    { "id": "ID1000000000000000000000002", "nrRec": "1.0/BBBBB" }
  ]
}
```

### `POST /esocial/eventos/download`

Baixa o XML **original** (byte-a-byte, o mesmo que foi transmitido ao
eSocial) de cada evento a partir dos `id` retornados por
`/esocial/eventos/identificadores`. Faz chunking automático em lotes de 50
`id`s por chamada SOAP.

**Body:**
```jsonc
{
  "escritorio_id": "uuid-do-escritorio",
  "cliente_cnpj": "00000000000000",
  "ids": ["ID1000000000000000000000001", "ID1000000000000000000000002"]
}
```

**Resposta (sucesso):**
```jsonc
{
  "ok": true,
  "http_status": 200,
  "duracao_ms": 1204,
  "cert": { "thumbprint": "...", "validade_em": "..." },
  "status": { "cd_resposta": "0", "desc_resposta": "Sucesso" },  // do último lote
  "status_por_lote": [                          // status de CADA lote de até 50 ids
    { "http_status": 200, "cd_resposta": "0", "desc_resposta": "Sucesso" }
  ],
  "arquivos": [
    {
      "id": "ID1000000000000000000000001",
      "nr_rec": null,
      "cd_resposta": "0",
      "desc_resposta": "Sucesso",
      "xml_evento": "<eSocial xmlns=\"...\"><evtRemun Id=\"...\">...</evtRemun></eSocial>"
    }
  ]
}
```

> Se `ids` tiver mais de 50 itens, o proxy faz uma chamada SOAP por lote de
> 50. `status` reflete só o último lote — sempre confira `status_por_lote`
> para não perder uma falha num lote anterior. Se um lote falhar no meio do
> processo, os arquivos dos lotes já concluídos vêm em `arquivos_parciais`
> na resposta de erro (em vez de serem descartados).

> **Ambiente:** estas rotas só funcionam com `SERPRO_AMBIENTE=producao` —
> não há um "trial" oficial do eSocial equivalente ao da SERPRO, então o
> proxy recusa rodar (`501`) em qualquer outro ambiente para não arriscar
> bater no eSocial real de um cliente enquanto o resto do proxy está sendo
> testado em trial/demonstração.

> **Atenção:** estas duas rotas foram validadas offline (assinatura XML
> com round-trip criptográfico, parsing contra respostas SOAP sintéticas
> seguindo os XSDs oficiais do eSocial), mas ainda não foram testadas
> contra o Web Service real — valide a primeira chamada em produção
> consultando o CNPJ do próprio escritório antes de rodar para clientes.
> Veja `CHANGELOG.md` (2.1.0) para detalhes técnicos.

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
