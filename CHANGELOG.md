# Proxy SERPRO mTLS — Changelog

Toda release relevante deve subir a `version` em `package.json` e descrever
aqui o que mudou. O `/healthz` exibe `versao` (lida do package.json) e
`boot_em` (timestamp de boot), facilitando confirmar se o redeploy do
Railway pegou a versão certa.

Convenção: [SemVer](https://semver.org/lang/pt-BR/).
- **MAJOR** — quebra de compatibilidade com a Edge Function chamadora.
- **MINOR** — novas rotas/parâmetros sem quebrar contratos antigos.
- **PATCH** — bugfix, log, ajuste interno.

---

## 2.0.0 — multi-tenant

### Quebra de compatibilidade
- Toda rota `/serpro/*` agora **exige** `escritorio_id` (uuid) no body.
  Resposta: `400 escritorio_id obrigatório` se ausente/inválido.
- Variáveis de ambiente removidas: `SERPRO_CERT_PATH`, `SERPRO_CERT_BASE64`,
  `SERPRO_CERT_PASSWORD`. O `.pfx` global do boot deixou de existir.
- Variáveis novas obrigatórias: `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`,
  `CERT_ENCRYPTION_KEY` (mesmos valores usados pela edge `certificado-upload`).

### Adicionado
- Loader dinâmico por escritório (`lib/certificadoEscritorio.js`):
  busca o cert ativo em `certificados_escritorio`, baixa o `.pfx` do bucket
  `certificados`, descriptografa a senha (AES-GCM-256) e converte para PEM.
- Cache LRU em memória de `mtlsAgent` por `escritorio_id` (max 20, TTL 1h).
- Token cache (`access_token` + `jwt_token`) agora vive **por escritório**
  dentro da entrada do cache (cada `/authenticate` é mTLS com cert distinto).
- Dedup de cargas concorrentes via `inFlight Map<id, Promise>`.
- Nova rota `POST /serpro/cache/invalidate` com body `{ escritorio_id }`
  ou `{ all: true }` — útil quando o usuário troca o cert ativo.
- `/healthz` enriquecido: passa a expor `cache: { size, max, entries[] }`
  com thumbprint, validade e timestamps de cada entrada quente.
- Erros estruturados do loader: `404 certificado_nao_encontrado`,
  `410 certificado_vencido`, `502 erro_storage`, etc.
- Resposta inclui `cert: { thumbprint, validade_em }` para auditoria.

### Removido
- Toda lógica de boot que lia `.pfx` de Volume / env base64.
- `mtlsAgent` global e `tokenCache` global.

### Como verificar após redeploy
```bash
curl -fsS https://SEU-PROXY/healthz | jq
# Espera versao=2.0.0 e cache.size=0 logo após deploy.
```

---

## 1.1.0 — 2026-04-19

### Adicionado
- Rotas `/serpro/apoiar`, `/serpro/declarar`, `/serpro/emitir` (além da
  já existente `/serpro/consultar`), via factory genérica `montarHandler`.
- `/healthz` enriquecido: `versao`, `boot_em`, `ambiente`, `rotas[]`.

---

## 1.0.0 — versão inicial

- `/healthz` (liveness probe).
- `/serpro/consultar` (Integra Contador tipo Consultar) com mTLS via
  certificado A1 (.pfx) carregado no boot e Agent undici dedicado.
- Autenticação `x-proxy-secret` para isolar a Edge Function chamadora.
