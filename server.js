// proxy-serpro/server.js
// Proxy mTLS para SERPRO Integra Contador.
// Recebe POST /serpro/consultar da Edge Function (Supabase) com auth via
// header x-proxy-secret e encaminha à SERPRO carregando o certificado A1
// (.pfx + senha) via undici Agent (mTLS cliente).
//
// Endpoints:
//   GET  /healthz                → liveness probe (Railway)
//   POST /serpro/consultar       → executa consulta Integra Contador
//
// Variáveis de ambiente obrigatórias:
//   PROXY_SHARED_SECRET, SERPRO_AMBIENTE, SERPRO_CONSUMER_KEY,
//   SERPRO_CONSUMER_SECRET, SERPRO_CERT_PATH, SERPRO_CERT_PASSWORD,
//   CONTRATANTE_CNPJ
// Opcional: AUTOR_PEDIDO_CNPJ (default = CONTRATANTE_CNPJ), PORT (default 3000)

import "dotenv/config";
import express from "express";
import { readFileSync } from "node:fs";
import { Agent, fetch as undiciFetch } from "undici";

const {
  PORT = "3000",
  PROXY_SHARED_SECRET,
  SERPRO_AMBIENTE = "trial",
  SERPRO_CONSUMER_KEY,
  SERPRO_CONSUMER_SECRET,
  SERPRO_CERT_PATH,
  SERPRO_CERT_PASSWORD,
  CONTRATANTE_CNPJ,
  AUTOR_PEDIDO_CNPJ,
} = process.env;

// Validação eager das variáveis críticas — falha rápido no boot
const required = {
  PROXY_SHARED_SECRET,
  SERPRO_CONSUMER_KEY,
  SERPRO_CONSUMER_SECRET,
  SERPRO_CERT_PATH,
  SERPRO_CERT_PASSWORD,
  CONTRATANTE_CNPJ,
};
for (const [k, v] of Object.entries(required)) {
  if (!v) {
    console.error(`[boot] variável obrigatória ausente: ${k}`);
    process.exit(1);
  }
}

const SERPRO_TOKEN_URLS = {
  trial: "https://gateway.apiserpro.serpro.gov.br/token",
  demonstracao: "https://apigateway.serpro.gov.br/token",
  producao: "https://gateway.apiserpro.serpro.gov.br/token",
};
const SERPRO_INTEGRA_URLS = {
  trial: "https://gateway.apiserpro.serpro.gov.br/integra-contador-trial/v1/Consultar",
  demonstracao: "https://apigateway.serpro.gov.br/integra-contador-demonstracao/v1/Consultar",
  producao: "https://gateway.apiserpro.serpro.gov.br/integra-contador/v1/Consultar",
};

// Carrega o .pfx uma única vez no boot
let pfxBuffer;
try {
  pfxBuffer = readFileSync(SERPRO_CERT_PATH);
  console.log(`[boot] certificado A1 carregado (${pfxBuffer.length} bytes)`);
} catch (err) {
  console.error(`[boot] falha ao ler certificado em ${SERPRO_CERT_PATH}:`, err.message);
  process.exit(1);
}

// Agent mTLS reutilizável — mantém keep-alive e handshake quente
const mtlsAgent = new Agent({
  connect: {
    pfx: pfxBuffer,
    passphrase: SERPRO_CERT_PASSWORD,
  },
});

// Cache simples de access_token em memória (proxy é single-instance)
let tokenCache = { value: null, expiresAt: 0 };

async function obterAccessToken() {
  const now = Date.now();
  if (tokenCache.value && tokenCache.expiresAt - now > 60_000) {
    return tokenCache.value;
  }
  const url = SERPRO_TOKEN_URLS[SERPRO_AMBIENTE];
  if (!url) throw new Error(`Ambiente inválido: ${SERPRO_AMBIENTE}`);

  const basic = Buffer.from(
    `${SERPRO_CONSUMER_KEY}:${SERPRO_CONSUMER_SECRET}`,
  ).toString("base64");

  // OAuth não exige mTLS — usa fetch normal
  const resp = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Basic ${basic}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  });
  const text = await resp.text();
  if (!resp.ok) {
    throw new Error(`OAuth ${resp.status}: ${text.slice(0, 200)}`);
  }
  const json = JSON.parse(text);
  const accessToken = json.access_token;
  const expiresIn = json.expires_in ?? 3600;
  if (!accessToken) throw new Error("access_token vazio na resposta SERPRO");
  tokenCache = {
    value: accessToken,
    expiresAt: now + expiresIn * 1000,
  };
  return accessToken;
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

app.get("/healthz", (_req, res) => {
  res.json({ ok: true, ambiente: SERPRO_AMBIENTE, ts: new Date().toISOString() });
});

/**
 * POST /serpro/consultar
 * Body: { cliente_cnpj: string, competencia: string (YYYYMM), jwt?: string,
 *         id_sistema?: string, id_servico?: string, dados?: object }
 *
 * Default = PGDASD/CONSULTIMADECREC14 (consulta declarações por período).
 */
app.post("/serpro/consultar", async (req, res) => {
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

    const accessToken = await obterAccessToken();
    const integraUrl = SERPRO_INTEGRA_URLS[SERPRO_AMBIENTE];
    if (!integraUrl) {
      return res.status(500).json({ ok: false, error: `Ambiente inválido: ${SERPRO_AMBIENTE}` });
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
      "Content-Type": "application/json",
      Accept: "application/json",
    };
    if (jwt) headers.jwt_token = jwt;

    // Chamada com mTLS via undici Agent
    const integraResp = await undiciFetch(integraUrl, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
      dispatcher: mtlsAgent,
    });
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
      payload: integraJson ?? { raw: integraText },
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("[/serpro/consultar] erro:", msg);
    return res.status(500).json({
      ok: false,
      http_status: null,
      ambiente: SERPRO_AMBIENTE,
      duracao_ms: Date.now() - inicio,
      error: msg,
    });
  }
});

app.listen(Number(PORT), () => {
  console.log(`[boot] proxy SERPRO mTLS escutando em :${PORT} (ambiente=${SERPRO_AMBIENTE})`);
});
