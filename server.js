// proxy-serpro/server.js
// Proxy mTLS para SERPRO Integra Contador — multi-tenant (v2.x).
//
// Cada escritório tem seu próprio certificado A1 (.pfx) armazenado no bucket
// `certificados` do Supabase, com a senha cifrada (AES-GCM 256) em
// `certificados_escritorio`. O proxy carrega o cert sob demanda, mantém um
// cache LRU de mtlsAgent por escritorio_id e usa o agent certo em cada
// requisição. Veja lib/certificadoEscritorio.js.
//
// Endpoints:
//   GET  /healthz                     → liveness + snapshot do cache
//   POST /serpro/consultar            → Integra Contador /v1/Consultar
//   POST /serpro/apoiar               → /v1/Apoiar
//   POST /serpro/declarar             → /v1/Declarar
//   POST /serpro/emitir               → /v1/Emitir
//   POST /serpro/cache/invalidate     → invalida 1 escritório ou todos
//   POST /esocial/eventos/identificadores → lista eventos (id+nrRec) de um
//                                            empregador num período
//   POST /esocial/eventos/download        → baixa o XML original dos eventos
//                                            identificados acima
//
// Variáveis de ambiente obrigatórias:
//   PROXY_SHARED_SECRET, SERPRO_AMBIENTE, SERPRO_CONSUMER_KEY,
//   SERPRO_CONSUMER_SECRET, CONTRATANTE_CNPJ,
//   SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, CERT_ENCRYPTION_KEY
// Opcional: AUTOR_PEDIDO_CNPJ (default = CONTRATANTE_CNPJ), PORT (default 3000)
//
// Notas:
//   - Em todas as rotas /serpro/* e /esocial/*, body precisa incluir
//     `escritorio_id` (uuid) — mesmo cert A1 por escritório, mesmo cache.
//   - As rotas /esocial/* usam o Web Service SOAP oficial de
//     Consulta/Download de Eventos (produção), não o Integra Contador —
//     ver lib/esocialClient.js.
//   - Boot NÃO falha se nenhum cert existir; só requests de escritórios sem
//     cert ativo é que erram (404 certificado_nao_encontrado).

import "dotenv/config";
import express from "express";
import { readFileSync } from "node:fs";
import { fetch as undiciFetch } from "undici";
import {
  obterContextoMtls,
  invalidarCache,
  snapshotCache,
  CertificadoError,
} from "./lib/certificadoEscritorio.js";
import {
  consultarIdentificadoresEventosEmpregador,
  solicitarDownloadEventosPorId,
  ESocialValidationError,
  ESocialUpstreamError,
  ESocialNetworkError,
} from "./lib/esocialClient.js";
import {
  extrairDetalhesErro,
  classificarErroMtls,
  certificadoErrorParaResposta,
} from "./lib/httpErros.js";

const {
  PORT = "3000",
  PROXY_SHARED_SECRET,
  SERPRO_AMBIENTE = "producao",
  SERPRO_CONSUMER_KEY,
  SERPRO_CONSUMER_SECRET,
  CONTRATANTE_CNPJ,
  AUTOR_PEDIDO_CNPJ,
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  CERT_ENCRYPTION_KEY,
} = process.env;

const required = {
  PROXY_SHARED_SECRET,
  SERPRO_CONSUMER_KEY,
  SERPRO_CONSUMER_SECRET,
  CONTRATANTE_CNPJ,
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  CERT_ENCRYPTION_KEY,
};
for (const [k, v] of Object.entries(required)) {
  if (!v) {
    console.error(`[boot] variável obrigatória ausente: ${k}`);
    process.exit(1);
  }
}

// /authenticate do Integra Contador — exige mTLS com o cert A1 do escritório.
const SERPRO_TOKEN_URLS = {
  trial: "https://autenticacao.sapi.serpro.gov.br/authenticate",
  demonstracao: "https://autenticacao.sapi.serpro.gov.br/authenticate",
  producao: "https://autenticacao.sapi.serpro.gov.br/authenticate",
};
// Cada operação SERPRO tem um endpoint próprio. O gateway valida o tipo
// por endpoint e devolve 403 [AcessoNegado-ICGERENCIADOR-017] se não bater.
const SERPRO_BASE_URLS = {
  trial: "https://gateway.apiserpro.serpro.gov.br/integra-contador-trial/v1",
  demonstracao: "https://apigateway.serpro.gov.br/integra-contador-demonstracao/v1",
  producao: "https://gateway.apiserpro.serpro.gov.br/integra-contador/v1",
};
function urlServico(operacao) {
  const base = SERPRO_BASE_URLS[SERPRO_AMBIENTE];
  if (!base) return null;
  return `${base}/${operacao}`;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Valida body.escritorio_id; em caso de erro já escreve a resposta 400 e devolve null. */
function extrairEscritorioIdOuFalhar(req, res) {
  const escritorio_id = req.body?.escritorio_id;
  if (!escritorio_id || typeof escritorio_id !== "string" || !UUID_RE.test(escritorio_id)) {
    res.status(400).json({ ok: false, error: "escritorio_id obrigatório (uuid)" });
    return null;
  }
  return escritorio_id;
}

/** Resumo do certificado ativo do escritório, incluído nas respostas para auditoria. */
function certResumo(entry) {
  return { thumbprint: entry.thumbprint.slice(0, 16), validade_em: entry.validadeEm };
}

/**
 * Obtém access_token + jwt_token usando o agent mTLS do escritório.
 * O par {accessToken, jwtToken} vive em entry.tokenCache (per-escritório).
 */
async function obterAccessToken(entry) {
  const now = Date.now();
  const tc = entry.tokenCache;
  if (tc.accessToken && tc.jwtToken && tc.expiresAt - now > 60_000) {
    return { accessToken: tc.accessToken, jwtToken: tc.jwtToken };
  }
  const url = SERPRO_TOKEN_URLS[SERPRO_AMBIENTE];
  if (!url) throw new Error(`Ambiente inválido: ${SERPRO_AMBIENTE}`);

  const basic = Buffer.from(
    `${SERPRO_CONSUMER_KEY}:${SERPRO_CONSUMER_SECRET}`,
  ).toString("base64");

  const resp = await undiciFetch(url, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/x-www-form-urlencoded",
      // TERCEIROS = escritório de contabilidade atuando em nome do contribuinte
      "Role-Type": "TERCEIROS",
    },
    body: "grant_type=client_credentials",
    dispatcher: entry.agent,
  });
  const text = await resp.text();
  if (!resp.ok) {
    throw new Error(`OAuth ${resp.status}: ${text.slice(0, 200)}`);
  }
  const json = JSON.parse(text);
  const accessToken = json.access_token;
  const jwtToken = json.jwt_token;
  const expiresIn = json.expires_in ?? 3600;
  if (!accessToken) throw new Error("access_token vazio na resposta SERPRO");
  if (!jwtToken) {
    throw new Error(
      "jwt_token vazio na resposta SERPRO (Integra Contador exige Bearer + jwt_token)",
    );
  }
  entry.tokenCache = {
    accessToken,
    jwtToken,
    expiresAt: now + expiresIn * 1000,
  };
  return { accessToken, jwtToken };
}

const app = express();
app.use(express.json({ limit: "1mb" }));

// Auth shared-secret obrigatória nas rotas /serpro/* e /esocial/*
const exigirSharedSecret = (req, res, next) => {
  const sent = req.header("x-proxy-secret");
  if (!sent || sent !== PROXY_SHARED_SECRET) {
    return res.status(401).json({ ok: false, error: "shared secret inválido" });
  }
  next();
};
app.use("/serpro", exigirSharedSecret);
app.use("/esocial", exigirSharedSecret);

// Versão lida do package.json (útil para confirmar deploy).
let PKG_VERSION = "desconhecida";
const BUILD_TIME = new Date().toISOString();
try {
  const pkg = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8"));
  PKG_VERSION = pkg.version ?? "desconhecida";
} catch { /* noop */ }

function listarRotas() {
  const rotas = [];
  const stack = app._router?.stack ?? [];
  for (const layer of stack) {
    const path = layer.route?.path;
    if (path?.startsWith("/serpro/") || path?.startsWith("/esocial/")) {
      const metodos = Object.keys(layer.route.methods || {})
        .filter((m) => layer.route.methods[m])
        .map((m) => m.toUpperCase());
      rotas.push({ path, methods: metodos });
    }
  }
  return rotas.sort((a, b) => a.path.localeCompare(b.path));
}

app.get("/healthz", (_req, res) => {
  res.json({
    ok: true,
    ambiente: SERPRO_AMBIENTE,
    versao: PKG_VERSION,
    boot_em: BUILD_TIME,
    rotas: listarRotas(),
    cache: snapshotCache(),
    ts: new Date().toISOString(),
  });
});

/**
 * POST /serpro/cache/invalidate
 * Body: { escritorio_id?: string, all?: boolean }
 * Útil quando o usuário troca o cert ativo (UI deve disparar isso).
 */
app.post("/serpro/cache/invalidate", (req, res) => {
  const { escritorio_id, all } = req.body ?? {};
  const r = invalidarCache({ escritorioId: escritorio_id, all: !!all });
  res.json({ ok: true, ...r });
});

/**
 * Factory de handler genérico — recebe a operação SERPRO ("Consultar",
 * "Apoiar", "Declarar", "Emitir") e devolve um Express handler que
 * encaminha o pedido para o endpoint correspondente do Integra Contador,
 * usando o cert A1 do escritório informado em body.escritorio_id.
 */
function montarHandler(operacao) {
  const tag = `[/serpro/${operacao.toLowerCase()}]`;
  return async (req, res) => {
    const inicio = Date.now();
    try {
      const {
        cliente_cnpj,
        competencia,
        jwt,
        id_sistema = "PGDASD",
        id_servico = "CONSULTIMADECREC14",
        versao_sistema = "1.0",
        dados,
      } = req.body ?? {};

      const escritorio_id = extrairEscritorioIdOuFalhar(req, res);
      if (!escritorio_id) return;
      if (!cliente_cnpj || !competencia) {
        return res
          .status(400)
          .json({ ok: false, error: "cliente_cnpj e competencia são obrigatórios" });
      }
      const cnpjLimpo = String(cliente_cnpj).replace(/\D/g, "");
      if (cnpjLimpo.length !== 14) {
        return res.status(400).json({ ok: false, error: "cliente_cnpj inválido" });
      }
      const competenciaSerpro = String(competencia).replace(/\D/g, "");
      if (!/^\d{6}$/.test(competenciaSerpro)) {
        return res
          .status(400)
          .json({ ok: false, error: "competencia inválida (esperado YYYYMM)" });
      }

      // Carrega/usa o cert A1 do escritório (cache LRU)
      let entry;
      try {
        entry = await obterContextoMtls(escritorio_id);
      } catch (err) {
        if (err instanceof CertificadoError) {
          const { status, body } = certificadoErrorParaResposta(err);
          return res.status(status).json(body);
        }
        throw err;
      }

      const { accessToken, jwtToken } = await obterAccessToken(entry);
      const integraUrl = urlServico(operacao);
      if (!integraUrl) {
        return res
          .status(500)
          .json({ ok: false, error: `Ambiente inválido: ${SERPRO_AMBIENTE}` });
      }

      const contratanteCnpj = CONTRATANTE_CNPJ.replace(/\D/g, "");
      const autorCnpj = (AUTOR_PEDIDO_CNPJ ?? CONTRATANTE_CNPJ).replace(/\D/g, "");

      const dadosPayload =
        dados !== undefined
          ? typeof dados === "string"
            ? dados
            : JSON.stringify(dados)
          : JSON.stringify({ periodoApuracao: Number(competenciaSerpro) });

      const payload = {
        contratante: { numero: contratanteCnpj, tipo: 2 },
        autorPedidoDados: { numero: autorCnpj, tipo: 2 },
        contribuinte: { numero: cnpjLimpo, tipo: 2 },
        pedidoDados: {
          idSistema: id_sistema,
          idServico: id_servico,
          versaoSistema: versao_sistema,
          dados: dadosPayload,
        },
      };

      const headers = {
        Authorization: `Bearer ${accessToken}`,
        jwt_token: jwt || jwtToken,
        "Content-Type": "application/json",
        Accept: "application/json",
      };

      let integraResp;
      try {
        integraResp = await undiciFetch(integraUrl, {
          method: "POST",
          headers,
          body: JSON.stringify(payload),
          dispatcher: entry.agent,
        });
      } catch (fetchErr) {
        const detalhes = extrairDetalhesErro(fetchErr);
        console.error(`${tag} falha mTLS upstream:`, detalhes);
        return res.status(502).json({
          ok: false,
          http_status: null,
          ambiente: SERPRO_AMBIENTE,
          duracao_ms: Date.now() - inicio,
          stage: "mtls_upstream",
          error: detalhes.mensagem,
          error_name: detalhes.name,
          error_code: detalhes.code,
          error_cause: detalhes.cause,
          diagnostico: classificarErroMtls(detalhes),
          cert: certResumo(entry),
        });
      }
      const integraText = await integraResp.text();
      let integraJson = null;
      try {
        integraJson = JSON.parse(integraText);
      } catch {
        integraJson = null;
      }

      return res.json({
        ok: integraResp.ok,
        http_status: integraResp.status,
        ambiente: SERPRO_AMBIENTE,
        duracao_ms: Date.now() - inicio,
        stage: "ok",
        operacao,
        cert: certResumo(entry),
        payload: integraJson ?? { raw: integraText },
      });
    } catch (err) {
      const detalhes = extrairDetalhesErro(err);
      console.error(`${tag} erro:`, detalhes);
      return res.status(500).json({
        ok: false,
        http_status: null,
        ambiente: SERPRO_AMBIENTE,
        duracao_ms: Date.now() - inicio,
        stage: "internal",
        error: detalhes.mensagem,
        error_name: detalhes.name,
        error_code: detalhes.code,
        error_cause: detalhes.cause,
      });
    }
  };
}

app.post("/serpro/consultar", montarHandler("Consultar"));
app.post("/serpro/apoiar", montarHandler("Apoiar"));
app.post("/serpro/declarar", montarHandler("Declarar"));
app.post("/serpro/emitir", montarHandler("Emitir"));

/** Mapeia um item de `arquivos` do lib/esocialClient.js para o formato de resposta HTTP. */
function mapArquivo(a) {
  return {
    id: a.id,
    nr_rec: a.nrRec,
    cd_resposta: a.cdResposta,
    desc_resposta: a.descResposta,
    xml_evento: a.xml,
  };
}

/**
 * Mapeia erros das rotas /esocial/* para respostas HTTP estruturadas,
 * seguindo o mesmo formato (ok/http_status/stage/error) usado em /serpro/*.
 * Distingue fault SOAP (upstream respondeu, mas com erro) de falha de
 * rede/mTLS (upstream não respondeu) de bug interno (nem chegou a tentar
 * a chamada), do mesmo jeito que montarHandler já faz para /serpro/*.
 */
function respostaEsocialErro(res, err, inicio) {
  if (err instanceof ESocialValidationError) {
    return res.status(400).json({ ok: false, stage: "validacao", error: err.message });
  }
  if (err instanceof CertificadoError) {
    const { status, body } = certificadoErrorParaResposta(err);
    return res.status(status).json(body);
  }

  const parcial =
    err.arquivosParciais && err.arquivosParciais.length > 0
      ? {
          arquivos_parciais: err.arquivosParciais.map(mapArquivo),
          status_por_lote_parcial: err.statusPorLoteParcial,
        }
      : {};

  if (err instanceof ESocialUpstreamError) {
    return res.status(502).json({
      ok: false,
      http_status: err.httpStatus,
      duracao_ms: Date.now() - inicio,
      stage: "esocial_soap_fault",
      error: err.message,
      raw_response: err.rawResponse ? err.rawResponse.slice(0, 2000) : null,
      ...parcial,
    });
  }
  if (err instanceof ESocialNetworkError) {
    const detalhes = extrairDetalhesErro(err.cause ?? err);
    console.error("[/esocial] falha mTLS upstream:", detalhes);
    return res.status(502).json({
      ok: false,
      http_status: null,
      duracao_ms: Date.now() - inicio,
      stage: "mtls_upstream",
      error: detalhes.mensagem,
      error_name: detalhes.name,
      error_code: detalhes.code,
      error_cause: detalhes.cause,
      diagnostico: classificarErroMtls(detalhes),
      ...parcial,
    });
  }

  const detalhes = extrairDetalhesErro(err);
  console.error("[/esocial] erro interno:", detalhes);
  return res.status(500).json({
    ok: false,
    http_status: null,
    duracao_ms: Date.now() - inicio,
    stage: "internal",
    error: detalhes.mensagem,
    error_name: detalhes.name,
    error_code: detalhes.code,
    error_cause: detalhes.cause,
    ...parcial,
  });
}

/**
 * As rotas /esocial/* falam direto com o Web Service de PRODUÇÃO do
 * eSocial (não existe ambiente de testes equivalente ao trial da SERPRO
 * para esse serviço — ver lib/esocialClient.js). Recusamos rodar se o
 * proxy estiver configurado para um ambiente SERPRO não-produção, pra
 * evitar que um teste contra o trial da SERPRO acabe batendo, sem querer,
 * no eSocial real de um cliente.
 */
function exigirAmbienteProducao(_req, res, next) {
  if (SERPRO_AMBIENTE !== "producao") {
    return res.status(501).json({
      ok: false,
      error:
        "/esocial/* só opera contra o eSocial de produção real. Defina SERPRO_AMBIENTE=producao para habilitar (evita bater sem querer no eSocial de um cliente enquanto se testa o proxy em trial/demonstracao).",
    });
  }
  next();
}
app.use("/esocial", exigirAmbienteProducao);

/**
 * POST /esocial/eventos/identificadores
 * Body: { escritorio_id, cliente_cnpj, tp_evt, per_apur }
 * Lista os identificadores (id + nrRec) dos eventos do empregador
 * (cliente_cnpj) de um tipo (tp_evt, ex: "S-1200") num período
 * (per_apur, "AAAA-MM" ou "AAAA") — primeiro passo antes do download.
 */
app.post("/esocial/eventos/identificadores", async (req, res) => {
  const inicio = Date.now();
  try {
    const escritorio_id = extrairEscritorioIdOuFalhar(req, res);
    if (!escritorio_id) return;

    const { cliente_cnpj, tp_evt, per_apur } = req.body ?? {};
    if (!cliente_cnpj || !tp_evt || !per_apur) {
      return res
        .status(400)
        .json({ ok: false, error: "cliente_cnpj, tp_evt e per_apur são obrigatórios" });
    }

    const entry = await obterContextoMtls(escritorio_id);
    const resultado = await consultarIdentificadoresEventosEmpregador({
      agent: entry.agent,
      pemKey: entry.pemKey,
      pemCert: entry.pemCert,
      cnpjCliente: cliente_cnpj,
      tpEvt: tp_evt,
      perApur: per_apur,
    });

    return res.json({
      ok: resultado.httpStatus >= 200 && resultado.httpStatus < 300,
      http_status: resultado.httpStatus,
      duracao_ms: Date.now() - inicio,
      cert: certResumo(entry),
      status: { cd_resposta: resultado.cdResposta, desc_resposta: resultado.descResposta },
      qtde_tot_evts_consulta: resultado.qtdeTotEvtsConsulta,
      dh_ultimo_evt_retornado: resultado.dhUltimoEvtRetornado,
      eventos: resultado.eventos,
    });
  } catch (err) {
    return respostaEsocialErro(res, err, inicio);
  }
});

/**
 * POST /esocial/eventos/download
 * Body: { escritorio_id, cliente_cnpj, ids: string[] }
 * Baixa o XML original de cada evento (ids vêm de
 * /esocial/eventos/identificadores). Faz chunking automático em lotes de
 * 50 ids por chamada SOAP; `status_por_lote` traz o status de cada lote
 * (não só do último) para não esconder falha parcial em downloads grandes.
 */
app.post("/esocial/eventos/download", async (req, res) => {
  const inicio = Date.now();
  try {
    const escritorio_id = extrairEscritorioIdOuFalhar(req, res);
    if (!escritorio_id) return;

    const { cliente_cnpj, ids } = req.body ?? {};
    if (!cliente_cnpj) {
      return res.status(400).json({ ok: false, error: "cliente_cnpj é obrigatório" });
    }

    // Falha rápido se o cert não existir/expirou, e dá o resumo de cert pra
    // resposta — o download em si re-resolve o cert a cada lote (ver
    // solicitarDownloadEventosPorId) pra se autocurar se o cache evictar
    // a entrada no meio de um download grande.
    const entry = await obterContextoMtls(escritorio_id);
    const resultado = await solicitarDownloadEventosPorId({
      obterEntry: () => obterContextoMtls(escritorio_id),
      cnpjCliente: cliente_cnpj,
      ids,
    });

    const ultimoLote = resultado.statusPorLote.at(-1) ?? null;
    return res.json({
      ok: resultado.statusPorLote.every((l) => l.httpStatus >= 200 && l.httpStatus < 300),
      http_status: ultimoLote?.httpStatus ?? null,
      duracao_ms: Date.now() - inicio,
      cert: certResumo(entry),
      status: ultimoLote
        ? { cd_resposta: ultimoLote.cdResposta, desc_resposta: ultimoLote.descResposta }
        : null,
      status_por_lote: resultado.statusPorLote.map((l) => ({
        http_status: l.httpStatus,
        cd_resposta: l.cdResposta,
        desc_resposta: l.descResposta,
      })),
      arquivos: resultado.arquivos.map(mapArquivo),
    });
  } catch (err) {
    return respostaEsocialErro(res, err, inicio);
  }
});

app.listen(Number(PORT), () => {
  console.log(
    `[boot] proxy SERPRO mTLS multi-tenant escutando em :${PORT} ` +
      `(ambiente=${SERPRO_AMBIENTE}, versao=${PKG_VERSION})`,
  );
});
