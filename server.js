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
import { createHash } from "node:crypto";
import { dirname } from "node:path";
import { Agent, fetch as undiciFetch } from "undici";
import forge from "node-forge";

const {
  PORT = "3000",
  PROXY_SHARED_SECRET,
  SERPRO_AMBIENTE = "trial",
  SERPRO_CONSUMER_KEY,
  SERPRO_CONSUMER_SECRET,
  SERPRO_CERT_PATH,
  SERPRO_CERT_BASE64,
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
  SERPRO_CERT_PASSWORD,
  CONTRATANTE_CNPJ,
};
for (const [k, v] of Object.entries(required)) {
  if (!v) {
    console.error(`[boot] variável obrigatória ausente: ${k}`);
    process.exit(1);
  }
}

if (!SERPRO_CERT_PATH && !SERPRO_CERT_BASE64) {
  console.error("[boot] defina SERPRO_CERT_PATH (arquivo) ou SERPRO_CERT_BASE64 (env)");
  process.exit(1);
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

// Carrega o .pfx (binário do arquivo, base64 em arquivo, ou base64 em env)
let pfxBuffer;
let pfxOrigem = "";
try {
  if (SERPRO_CERT_BASE64 && SERPRO_CERT_BASE64.trim().length > 0) {
    pfxBuffer = Buffer.from(SERPRO_CERT_BASE64.trim(), "base64");
    pfxOrigem = "env SERPRO_CERT_BASE64";
  } else {
    const raw = readFileSync(SERPRO_CERT_PATH);
    // autodetect: se o arquivo é texto ASCII base64, decodifica
    const asAscii = raw.toString("utf8").trim();
    const looksBase64 =
      asAscii.length > 100 && /^[A-Za-z0-9+/=\r\n\s]+$/.test(asAscii);
    if (looksBase64) {
      pfxBuffer = Buffer.from(asAscii.replace(/\s+/g, ""), "base64");
      pfxOrigem = `arquivo ${SERPRO_CERT_PATH} (base64 detectado, decodificado)`;
    } else {
      pfxBuffer = raw;
      pfxOrigem = `arquivo ${SERPRO_CERT_PATH} (binário)`;
    }
  }
  console.log(`[boot] certificado A1 carregado de ${pfxOrigem} (${pfxBuffer.length} bytes)`);
} catch (err) {
  console.error(`[boot] falha ao ler certificado:`, err.message);
  process.exit(1);
}

// Validação + extração de key/cert PEM via node-forge.
// Motivo: Node 18+/OpenSSL 3 rejeita PKCS#12 com algoritmos legados
// (RC2-40, 3DES-SHA1) usados em certificados A1 brasileiros, com erro
// "Unsupported PKCS12 PFX data". node-forge é puro JS e aceita esses
// algoritmos, então convertemos para PEM e passamos key+cert ao undici.
let pemKey = null;
let pemCert = null;
let pemCa = [];
try {
  const p12Der = pfxBuffer.toString("binary");
  const p12Asn1 = forge.asn1.fromDer(p12Der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, SERPRO_CERT_PASSWORD);
  // extrai chave privada (PKCS#8 shrouded ou keyBag)
  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  let keyObj = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0]?.key;
  if (!keyObj) {
    const plainKeyBags = p12.getBags({ bagType: forge.pki.oids.keyBag });
    keyObj = plainKeyBags[forge.pki.oids.keyBag]?.[0]?.key;
  }
  if (!keyObj) throw new Error("nenhuma chave privada encontrada no PKCS#12");
  // extrai certificados
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
  const certs = (certBags[forge.pki.oids.certBag] ?? []).map((b) => b.cert);
  if (certs.length === 0) throw new Error("nenhum certificado encontrado no PKCS#12");
  // heurística: o cert do titular tem a chave pública correspondente à privada;
  // o resto é cadeia (CA intermediária + raiz)
  const pubKeyPem = forge.pki.publicKeyToPem(forge.pki.setRsaPublicKey(keyObj.n, keyObj.e));
  const titular = certs.find(
    (c) => forge.pki.publicKeyToPem(c.publicKey) === pubKeyPem,
  ) ?? certs[0];
  const cadeia = certs.filter((c) => c !== titular);
  pemKey = forge.pki.privateKeyToPem(keyObj);
  pemCert = forge.pki.certificateToPem(titular);
  pemCa = cadeia.map((c) => forge.pki.certificateToPem(c));

  const thumb = createHash("sha256").update(pfxBuffer).digest("hex").slice(0, 16);
  const cn = titular.subject.getField("CN")?.value ?? "?";
  const validade = titular.validity.notAfter.toISOString().slice(0, 10);
  console.log(
    `[boot] PKCS#12 validado e convertido para PEM ` +
      `(sha256[0..16]=${thumb}, CN="${cn}", validade=${validade}, cadeia=${cadeia.length})`,
  );
} catch (err) {
  const msg = (err && (err.message || err.toString())) || String(err);
  const lower = msg.toLowerCase();
  let dica = "";
  if (
    lower.includes("pkcs12mac") ||
    lower.includes("mac could not be verified") ||
    lower.includes("invalid password") ||
    lower.includes("mac verify") ||
    lower.includes("bad decrypt")
  ) {
    dica = " → senha do .pfx incorreta (confira SERPRO_CERT_PASSWORD no Railway).";
  } else if (
    lower.includes("asn.1") ||
    lower.includes("asn1") ||
    lower.includes("too few bytes") ||
    lower.includes("invalid tag") ||
    lower.includes("der")
  ) {
    dica = " → arquivo não é um PKCS#12 válido (talvez ainda esteja em base64, truncado ou corrompido).";
  }
  console.error(`[boot] PKCS#12 inválido: ${msg}${dica}`);
  process.exit(1);
}


// Agent mTLS reutilizável — mantém keep-alive e handshake quente.
// Usamos key+cert PEM (não pfx) para contornar a restrição do OpenSSL 3
// que rejeita os algoritmos legados dos certificados A1 brasileiros
// (erro "Unsupported PKCS12 PFX data" / ERR_CRYPTO_UNSUPPORTED_OPERATION).
const mtlsAgent = new Agent({
  connect: {
    key: pemKey,
    cert: pemCert,
    ...(pemCa.length > 0 ? { ca: pemCa } : {}),  },
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
    if (jwt) {
      const jwtLimpo = String(jwt).trim().replace(/^Bearer\s+/i, "");

      const partes = jwtLimpo.split(".");
      if (partes.length !== 3) {
        return res.status(400).json({
          ok: false,
          error: "jwt inválido: esperado formato header.payload.signature (3 partes separadas por '.')",
        });
      }

      try {
        const payloadJwt = JSON.parse(Buffer.from(partes[1], "base64url").toString("utf8"));
        if (payloadJwt.exp && payloadJwt.exp * 1000 < Date.now()) {
          return res.status(400).json({
            ok: false,
            error: `jwt expirado em ${new Date(payloadJwt.exp * 1000).toISOString()}`,
          });
        }
      } catch {
        return res.status(400).json({ ok: false, error: "jwt com payload não decodificável" });
      }

      const preview = `${jwtLimpo.slice(0, 8)}…${jwtLimpo.slice(-8)}`;
      console.log(`[/serpro/consultar] jwt_token presente (len=${jwtLimpo.length}, preview=${preview})`);

      headers.jwt_token = jwtLimpo;
    }

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

    const dica =
      !integraResp.ok && integraResp.status === 403 && integraText.includes("jwt_token")
        ? "JWT de procuração inválido ou expirado — verifique expiração, ambiente e claims do token SERPRO"
        : undefined;

    return res.json({
      ok: integraResp.ok,
      http_status: integraResp.status,
      ambiente: SERPRO_AMBIENTE,
      duracao_ms: Date.now() - inicio,
      stage: "ok",
      payload: integraJson ?? { raw: integraText },
      ...(dica ? { diagnostico: dica } : {}),
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
  if (blob.includes("unsupported pkcs12") || blob.includes("err_crypto_unsupported_operation")) {
  return "OpenSSL 3 rejeitou o PKCS#12 (algoritmo legado). O proxy já converte para PEM no boot — se está vendo isso, o redeploy ainda não pegou a versão nova.";
  }
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
