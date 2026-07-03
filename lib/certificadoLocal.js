// proxy-serpro/lib/certificadoLocal.js
// Modo LOCAL: carrega o certificado A1 (.pfx) de um arquivo no disco, sem
// Supabase/Lovable Cloud. Usado quando LOCAL_CERT_PATH + LOCAL_CERT_SENHA
// estão definidos no .env — pensado para rodar o proxy na máquina do
// próprio escritório (npm start + navegador), sem nenhum serviço externo.
//
// Devolve um objeto com o MESMO formato de CacheEntry do loader
// multi-tenant (lib/certificadoEscritorio.js), então as rotas /esocial/*
// funcionam sem mudança nenhuma.

import { readFileSync } from "node:fs";
import { Agent } from "undici";
import { pfxToPem } from "./pfxToPem.js";

let _entry = null;

/**
 * Carrega (uma única vez; depois devolve do cache) o contexto mTLS do
 * certificado local. Lança Error com mensagem amigável se o arquivo não
 * existir, a senha estiver errada ou o .pfx for inválido.
 *
 * @param {{ certPath: string, senha: string }} params
 */
export function carregarContextoLocal({ certPath, senha }) {
  if (_entry) return _entry;

  let buf;
  try {
    buf = readFileSync(certPath);
  } catch (err) {
    throw new Error(
      `Não consegui ler o certificado em "${certPath}" — confira se o arquivo existe e o caminho em LOCAL_CERT_PATH está certo. (${err.code ?? err.message})`,
    );
  }

  // Autodetect: um .pfx binário começa com 0x30 (ASN.1 SEQUENCE). Se o
  // arquivo foi salvo em base64 (texto), decodifica antes.
  if (buf.length > 0 && buf[0] !== 0x30) {
    const decodificado = Buffer.from(buf.toString("utf8").replace(/\s+/g, ""), "base64");
    if (decodificado.length > 0 && decodificado[0] === 0x30) {
      console.log("[cert-local] arquivo em base64 detectado, decodificado");
      buf = decodificado;
    }
  }

  let pem;
  try {
    pem = pfxToPem(buf, senha);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (/mac verify|invalid password|PKCS#12 MAC/i.test(msg)) {
      throw new Error(
        "Senha do certificado incorreta — confira LOCAL_CERT_SENHA no arquivo .env.",
      );
    }
    throw new Error(
      `Arquivo .pfx inválido ou corrompido (${msg}) — confira se é mesmo o certificado A1 exportado com chave privada.`,
    );
  }

  if (pem.validadeEm && pem.validadeEm.getTime() < Date.now()) {
    throw new Error(
      `Certificado A1 VENCIDO em ${pem.validadeEm.toISOString().slice(0, 10)} — emita um novo certificado.`,
    );
  }

  const agent = new Agent({
    connect: {
      key: pem.pemKey,
      cert: pem.pemCert,
      ...(pem.pemCa.length > 0 ? { ca: pem.pemCa } : {}),
    },
  });

  const agora = Date.now();
  _entry = {
    escritorioId: "local",
    agent,
    tokenCache: { accessToken: null, jwtToken: null, expiresAt: 0 },
    thumbprint: pem.thumbprintSha256,
    titularCnpj: pem.titularCnpj,
    titularNome: pem.titularNome,
    validadeEm: pem.validadeEm ? pem.validadeEm.toISOString() : null,
    pemKey: pem.pemKey,
    pemCert: pem.pemCert,
    loadedAt: agora,
    lastUsedAt: agora,
  };
  return _entry;
}
