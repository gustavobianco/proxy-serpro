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
import { readFileSync, writeFileSync, mkdirSync, existsSync, chmodSync, statSync } from "node:fs";
import { dirname } from "node:path";
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
  CERT_PFX_BASE64,
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

// Se CERT_PFX_BASE64 estiver definida, grava o .pfx no disco antes de ler.
// Isso permite injetar o certificado via variável de ambiente sem depender
// de upload manual para o Volume.
if (CERT_PFX_BASE64) {
  const certDir = dirname(SERPRO_CERT_PATH);
  if (!existsSync(certDir)) {
    mkdirSync(certDir, { recursive: true });
  }
  writeFileSync(SERPRO_CERT_PATH, Buffer.from(CERT_PFX_BASE64, "base64"));
  chmodSync(SERPRO_CERT_PATH, 0o600);
  console.log(
    `[boot] cert.pfx gravado em ${SERPRO_CERT_PATH} (${statSync(SERPRO_CERT_PATH).size} bytes)`,
  );
}

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
    let integraResp;
        try {
          integraResp = await undiciFetch(integraUrl, {
            method: "POST",
            headers,
            body: JSON.stringify(payload),
            dispatcher: mtlsAgent,
          });
        } catch (fetchErr) {
          // Falha de transporte/handshake — extrai todos os detalhes possíveis
          const detalhes = extrairDetalhesErro(fetchErr);
          console.error("[/serpro/consultar] falha mTLS upstream:", detalhes);
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
      payload: integraJson ?? { raw: integraText },
    });
  } catch (err) {
    const detalhes = extrairDetalhesErro(err);
    console.error("[/serpro/consultar] erro:", detalhes);
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
});

/**
 * Achata um Error (incluindo err.cause de undici) em campos serializáveis.
 * undici costuma colocar o erro real (TLS/socket) em err.cause.
 */
function extrairDetalhesErro(err) {
  const out = {
    mensagem: "",
    name: null,
    code: null,
    cause: null,
  };
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
          // alguns erros TLS expõem .reason / .library / .syscall
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
/**
 * Classifica os erros mTLS mais comuns em uma dica acionável para o operador.
 */
function classificarErroMtls(detalhes) {
  const blob = JSON.stringify(detalhes).toLowerCase();
  if (blob.includes("mac verify") || blob.includes("bad decrypt") || blob.includes("wrong password")) {
    return "Senha do .pfx incorreta — confira SERPRO_CERT_PASSWORD no Railway.";
  }
  if (blob.includes("no start line") || blob.includes("asn1") || blob.includes("pkcs12")) {
    return "Arquivo .pfx inválido ou corrompido — reenvie o certificado A1 ao Volume do Railway.";
  }
  if (blob.includes("certificate has expired") || blob.includes("cert has expired")) {
    return "Certificado A1 vencido — emita um novo e atualize o Volume.";
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
  console.log(`[boot] proxy SERPRO mTLS escutando em :${PORT} (ambiente=${SERPRO_AMBIENTE})`);
});
