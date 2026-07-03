// proxy-serpro/lib/httpErros.js
// Helpers de diagnóstico de erro compartilhados pelas rotas /serpro/* e
// /esocial/* — ambas fazem fetch mTLS via undici contra gateways
// governamentais e se beneficiam da mesma classificação de falha de
// handshake/certificado.

/** Extrai uma versão serializável (JSON-safe) de um Error, incluindo `cause`. */
export function extrairDetalhesErro(err) {
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

/** Traduz erros comuns de handshake/certificado mTLS em uma dica legível. */
export function classificarErroMtls(detalhes) {
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
    return "Handshake TLS interrompido pelo servidor remoto — certificado provavelmente não está habilitado para este serviço.";
  }
  if (blob.includes("enotfound") || blob.includes("eai_again") || blob.includes("etimedout")) {
    return "Não foi possível alcançar o servidor remoto — checar conectividade do container.";
  }
  if (blob.includes("alert") || blob.includes("handshake") || blob.includes("tls")) {
    return "Falha no handshake TLS — checar validade, senha e habilitação do certificado.";
  }
  return null;
}

/** Mapeia um CertificadoError (lib/certificadoEscritorio.js) para {status, body} HTTP. */
export function certificadoErrorParaResposta(err) {
  return {
    status: err.status,
    body: { ok: false, stage: "cert_load", error_code: err.code, error: err.message },
  };
}
