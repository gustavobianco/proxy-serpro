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
//
// Variáveis de ambiente obrigatórias:
//   PROXY_SHARED_SECRET, SERPRO_AMBIENTE, SERPRO_CONSUMER_KEY,
//   SERPRO_CONSUMER_SECRET, CONTRATANTE_CNPJ,
//   SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, CERT_ENCRYPTION_KEY
// Opcional: AUTOR_PEDIDO_CNPJ (default = CONTRATANTE_CNPJ), PORT (default 3000)
//
// Notas:
//   - Em todas as rotas /serpro/*, body precisa incluir `escritorio_id` (uuid).
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

// Auth shared-secret obrigatória nas rotas /serpro/*
app.use("/serpro", (req, res, next) => {
  const sent = req.header("x-proxy-secret");
  if (!sent || sent !== PROXY_SHARED_SECRET) {
    return res.status(401).json({ ok: false, error: "shared secret inválido" });
  }
  next();
});

// Versão lida do package.json (útil para confirmar deploy).
let PKG_VERSION = "desconhecida";
const BUILD_TIME = new Date().toISOString();
try {
  const pkg = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf8"));
  PKG_VERSION = pkg.version ?? "desconhecida";
} catch { /* noop */ }

function listarRotasSerpro() {
  const rotas = [];
  const stack = app._router?.stack ?? [];
  for (const layer of stack) {
    if (layer.route?.path?.startsWith("/serpro/")) {
      const metodos = Object.keys(layer.route.methods || {})
        .filter((m) => layer.route.methods[m])
        .map((m) => m.toUpperCase());
      rotas.push({ path: layer.route.path, methods: metodos });
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
    rotas: listarRotasSerpro(),
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
        escritorio_id,
        cliente_cnpj,
        competencia,
        jwt,
        id_sistema = "PGDASD",
        id_servico = "CONSULTIMADECREC14",
        versao_sistema = "1.0",
        dados,
      } = req.body ?? {};

      if (!escritorio_id || typeof escritorio_id !== "string" || !UUID_RE.test(escritorio_id)) {
        return res.status(400).json({ ok: false, error: "escritorio_id obrigatório (uuid)" });
      }
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
          return res.status(err.status).json({
            ok: false,
            stage: "cert_load",
            error_code: err.code,
            error: err.message,
          });
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
          cert: { thumbprint: entry.thumbprint.slice(0, 16), validade_em: entry.validadeEm },
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
        cert: { thumbprint: entry.thumbprint.slice(0, 16), validade_em: entry.validadeEm },
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

function extrairDetalhesErro(err) {
  const out = { mensagem: "", name: null, code: null, cause: null };
  if (err instanceof Error) {
    out.mensagem = err.message || String(err);
    out.name = err.name ?? null;
    out.code = err.code ?? null;
    const cause = err.cause;
    if (cause) {
      if (cause instanceof Error) {
        out.cause = {
          message: cause.message,
          name: cause.name ?? null,
          code: cause.code ?? null,
          reason: cause.reason ?? null,
          library: cause.library ?? null,
          syscall: cause.syscall ?? null,
        };
      } else {
        out.cause = { message: String(cause) };
      }
    }
  } else {
    out.mensagem = String(err);
  }
  return out;
}

function classificarErroMtls(detalhes) {
  const blob = JSON.stringify(detalhes).toLowerCase();
  if (blob.includes("unsupported pkcs12") || blob.includes("err_crypto_unsupported_operation")) {
    return "OpenSSL 3 rejeitou o PKCS#12 (algoritmo legado). O proxy converte para PEM no boot — se está vendo isso, há um bug na conversão.";
  }
  if (blob.includes("mac verify") || blob.includes("bad decrypt") || blob.includes("wrong password")) {
    return "Senha do .pfx incorreta — verifique o cert ativo do escritório em /configuracoes.";
  }
  if (blob.includes("no start line") || blob.includes("asn1") || blob.includes("pkcs12")) {
    return "Arquivo .pfx inválido ou corrompido — reenvie o certificado A1 em /configuracoes.";
  }
  if (blob.includes("certificate has expired") || blob.includes("cert has expired")) {
    return "Certificado A1 vencido — emita um novo e suba em /configuracoes.";
  }
  if (blob.includes("unable to verify") || blob.includes("self signed") || blob.includes("unable to get")) {
    return "Cadeia de confiança incompleta — verifique se o .pfx contém a cadeia completa.";
  }
  if (blob.includes("econnreset") || blob.includes("socket hang up") || blob.includes("epipe")) {
    return "Handshake TLS interrompido pela SERPRO — certificado provavelmente não está habilitado para Integra Contador neste ambiente.";
  }
  if (blob.includes("enotfound") || blob.includes("eai_again") || blob.includes("etimedout")) {
    return "Não foi possível alcançar a SERPRO — checar conectividade do container Railway.";
  }
  if (blob.includes("alert") || blob.includes("handshake") || blob.includes("tls")) {
    return "Falha no handshake TLS com a SERPRO — checar validade, senha e habilitação do certificado.";
  }
  return null;
}

app.listen(Number(PORT), () => {
  console.log(
    `[boot] proxy SERPRO mTLS multi-tenant escutando em :${PORT} ` +
      `(ambiente=${SERPRO_AMBIENTE}, versao=${PKG_VERSION})`,
  );
});
