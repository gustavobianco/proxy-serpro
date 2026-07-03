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

## 2.1.0 — download de eventos do eSocial

### Adicionado
- Novas rotas `POST /esocial/eventos/identificadores` e
  `POST /esocial/eventos/download`, que falam com os Web Services SOAP
  oficiais de Consulta/Download de Eventos do eSocial (produção,
  `webservices.download.esocial.gov.br`) — **não** é o Integra Contador
  SERPRO, é o serviço próprio do eSocial que usa o certificado A1 do
  escritório com a outorga de poderes (procuração) para baixar eventos já
  enviados de um cliente.
- Reaproveita o mesmo cert/agent mTLS por `escritorio_id` já usado em
  `/serpro/*` (`lib/certificadoEscritorio.js` agora também expõe
  `pemKey`/`pemCert` na entrada do cache, necessários para assinar XML).
- `lib/esocialSign.js`: assinatura XML enveloped (RSA-SHA256, digest
  SHA-256, canonicalização C14N, `KeyInfo` só com `X509Certificate`),
  exigida pelo eSocial em toda requisição desses Web Services.
- `lib/esocialClient.js`: construção do envelope SOAP, chamada dos dois
  serviços (`ConsultarIdentificadoresEventosEmpregador` e
  `SolicitarDownloadEventosPorId`, com chunking automático em lotes de 50
  ids) e parsing da resposta.
- `lib/esocialXml.js`: extração do XML de cada evento por substring (não
  por DOM) para preservar o arquivo original byte-a-byte, já que é esse
  XML que tem valor de auditoria/compliance.
- `lib/httpErros.js`: `extrairDetalhesErro`/`classificarErroMtls`
  extraídos de `server.js` para serem reaproveitados também nas rotas
  `/esocial/*`.
- Guard `SERPRO_AMBIENTE=producao` obrigatório para qualquer rota
  `/esocial/*` (501 caso contrário) — não existe "trial" oficial do
  eSocial equivalente ao da SERPRO para este Web Service, então testar o
  proxy em `trial`/`demonstracao` nunca deve acabar batendo no eSocial
  real de um cliente.
- `/esocial/eventos/download` re-resolve o cert do escritório
  (`obterContextoMtls`) a cada lote de 50 ids, em vez de reusar um
  `agent`/chave capturados uma única vez — evita usar um `undici.Agent`
  já fechado se o cache LRU evictar/revalidar a entrada no meio de um
  download grande com muitos lotes.
- `status_por_lote` na resposta de `/esocial/eventos/download`: antes só
  o status do último lote era devolvido, escondendo silenciosamente a
  falha de um lote anterior num download com mais de 50 ids.
- Se um lote falhar no meio do processo, os arquivos já baixados nos
  lotes anteriores voltam em `arquivos_parciais` na resposta de erro, em
  vez de serem descartados.
- `blocoBruto`/`blocosBrutos` (`lib/esocialXml.js`) agora também
  reconhecem elementos self-closing (`<tag/>`), evitando um 502 espúrio
  se o eSocial serializar um elemento complexo vazio dessa forma.
- Extração de fault SOAP 1.2 (`<Reason><Text>...</Text></Reason>`) além
  do 1.1 (`<faultstring>`) — antes a mensagem de erro vinha com as tags
  `<Text>` embutidas cruas.

### Observação importante
Este código foi validado offline (assinatura XML com round-trip
criptográfico, parsing contra respostas SOAP sintéticas seguindo os XSDs
oficiais), mas **não foi testado contra o Web Service real do eSocial**
— não há certificado real nem alcance de rede até `esocial.gov.br` no
ambiente onde foi escrito. Antes de rodar para CNPJ de clientes,
valide a primeira chamada consultando o próprio CNPJ do escritório.

### Como verificar após redeploy
```bash
curl -fsS https://SEU-PROXY/healthz | jq '.rotas'
# Espera ver /esocial/eventos/identificadores e /esocial/eventos/download
```

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
