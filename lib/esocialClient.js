// proxy-serpro/lib/esocialClient.js
// Cliente SOAP dos Web Services de Consulta/Download de eventos do eSocial
// (ambiente de Produção). Reaproveita o mesmo agent mTLS (cert A1 por
// escritório) já usado nas rotas /serpro/*.
//
// Fluxo (ambos síncronos — sem etapa de "consultar resultado" separada):
//   1) ConsultarIdentificadoresEventosEmpregador: dado tpEvt+perApur, devolve
//      a lista de {id, nrRec} dos eventos do empregador naquele período.
//   2) SolicitarDownloadEventosPorId: dado uma lista de `id`, devolve o XML
//      original de cada evento (o mesmo XML assinado que foi transmitido ao
//      eSocial).
//
// Endpoints e namespaces confirmados contra os XSDs oficiais
// (ConsultaIdentificadoresEventosEmpregador-v1_0_0.xsd,
// SolicitacaoDownloadEventosPorId-v1_0_0.xsd) e a implementação de
// referência do projeto ACBr (ACBreSocialServicos.ini /
// ACBreSocialWebServices.pas), já que a SERPRO/gov.br não publica um
// catálogo REST para este serviço — é SOAP/XML puro com mTLS.
//
// IMPORTANTE: este código não foi (e não pôde ser, neste ambiente) testado
// contra o Web Service real do eSocial — não há certificado real nem
// alcance de rede até esocial.gov.br neste sandbox. A assinatura XML foi
// validada isoladamente (round-trip enveloped-signature/RSA-SHA256/C14N
// contra os XSDs). Recomenda-se validar a primeira chamada em produção
// consultando o CNPJ do próprio escritório antes de rodar para clientes.

import { fetch as undiciFetch } from "undici";
import { assinarXmlESocial } from "./esocialSign.js";
import { campo, atributo, blocoBruto, blocosBrutos, decodeXmlEntities } from "./esocialXml.js";

const ESOCIAL_CONSULTA_URL =
  "https://webservices.download.esocial.gov.br/servicos/empregador/dwlcirurgico/WsConsultarIdentificadoresEventos.svc";
const ESOCIAL_DOWNLOAD_URL =
  "https://webservices.download.esocial.gov.br/servicos/empregador/dwlcirurgico/WsSolicitarDownloadEventos.svc";

const NS_CONSULTA_SCHEMA =
  "http://www.esocial.gov.br/schema/consulta/identificadores-eventos/empregador/v1_0_0";
const NS_CONSULTA_SERVICO =
  "http://www.esocial.gov.br/servicos/empregador/consulta/identificadores-eventos/v1_0_0";
const NS_DOWNLOAD_SCHEMA = "http://www.esocial.gov.br/schema/download/solicitacao/id/v1_0_0";
const NS_DOWNLOAD_SERVICO =
  "http://www.esocial.gov.br/servicos/empregador/download/solicitacao/v1_0_0";

/** Tamanho de lote por chamada de download (defensivo — ajuste se o eSocial acusar limite excedido). */
const DOWNLOAD_LOTE_SIZE = 50;

export class ESocialValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "ESocialValidationError";
    this.code = "esocial_validacao";
  }
}

/** Erro de resposta SOAP inesperada (fault, HTML de erro do gateway, etc). */
export class ESocialUpstreamError extends Error {
  constructor(message, { httpStatus, rawResponse } = {}) {
    super(message);
    this.name = "ESocialUpstreamError";
    this.httpStatus = httpStatus ?? null;
    this.rawResponse = rawResponse ?? null;
  }
}

/** Falha de rede/mTLS ao tentar alcançar o Web Service (distinto de um fault SOAP). */
export class ESocialNetworkError extends Error {
  constructor(cause) {
    super(cause instanceof Error ? cause.message : String(cause));
    this.name = "ESocialNetworkError";
    this.cause = cause;
  }
}

function escapeXml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

/**
 * Deriva tpInsc/nrInsc do identificador do empregador (cliente) a partir de
 * um CNPJ ou CPF. O eSocial identifica o empregador sempre pela RAIZ do
 * CNPJ (8 primeiros dígitos, a matriz) — eventos e obrigações são
 * consolidados no grupo econômico, não por filial — então um CNPJ de 14
 * dígitos de qualquer filial é normalizado para a raiz da matriz de
 * propósito, não por engano. Isso reflete o schema oficial
 * (TIdeEmpregador: nrInsc de 8 a 15 dígitos) e a implementação de
 * referência do ACBr (`FCnpj := Copy(FCnpj, 1, 8)`).
 */
function ideEmpregador(cnpjOuCpf) {
  const digitos = String(cnpjOuCpf ?? "").replace(/\D/g, "");
  if (digitos.length === 14 || digitos.length === 8) {
    return { tpInsc: "1", nrInsc: digitos.slice(0, 8) };
  }
  if (digitos.length === 11) {
    return { tpInsc: "2", nrInsc: digitos };
  }
  throw new ESocialValidationError(
    "cliente_cnpj inválido: informe um CNPJ (14 dígitos, ou 8 já como raiz) ou CPF (11 dígitos)",
  );
}

function validarTpEvt(tpEvt) {
  if (typeof tpEvt !== "string" || tpEvt.length !== 6) {
    throw new ESocialValidationError(
      "tp_evt inválido: deve ter exatamente 6 caracteres (ex: 'S-1200')",
    );
  }
}

function validarPerApur(perApur) {
  if (typeof perApur !== "string" || !/^\d{4}(-\d{2})?$/.test(perApur)) {
    throw new ESocialValidationError("per_apur inválido: use 'AAAA' ou 'AAAA-MM'");
  }
}

function ideEmpregadorXml({ tpInsc, nrInsc }) {
  return (
    "<ideEmpregador>" +
    `<tpInsc>${escapeXml(tpInsc)}</tpInsc>` +
    `<nrInsc>${escapeXml(nrInsc)}</nrInsc>` +
    "</ideEmpregador>"
  );
}

function payloadConsultaEmpregador({ tpInsc, nrInsc, tpEvt, perApur }) {
  return (
    `<eSocial xmlns="${NS_CONSULTA_SCHEMA}">` +
    "<consultaIdentificadoresEvts>" +
    ideEmpregadorXml({ tpInsc, nrInsc }) +
    "<consultaEvtsEmpregador>" +
    `<tpEvt>${escapeXml(tpEvt)}</tpEvt>` +
    `<perApur>${escapeXml(perApur)}</perApur>` +
    "</consultaEvtsEmpregador>" +
    "</consultaIdentificadoresEvts>" +
    "</eSocial>"
  );
}

function payloadDownloadPorId({ tpInsc, nrInsc, ids }) {
  const idsXml = ids.map((id) => `<id>${escapeXml(id)}</id>`).join("");
  return (
    `<eSocial xmlns="${NS_DOWNLOAD_SCHEMA}">` +
    "<download>" +
    ideEmpregadorXml({ tpInsc, nrInsc }) +
    "<solicDownloadEvtsPorId>" +
    idsXml +
    "</solicDownloadEvtsPorId>" +
    "</download>" +
    "</eSocial>"
  );
}

/** Monta o envelope SOAP 1.1 comum às duas operações (só muda ns/nomes de elemento). */
function envelopeSoap({ nsServico, elementoOperacao, elementoParametro, signedPayloadXml }) {
  return (
    '<?xml version="1.0" encoding="utf-8"?>' +
    `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:v1="${nsServico}">` +
    "<soap:Body>" +
    `<v1:${elementoOperacao}>` +
    `<v1:${elementoParametro}>` +
    signedPayloadXml +
    `</v1:${elementoParametro}>` +
    `</v1:${elementoOperacao}>` +
    "</soap:Body>" +
    "</soap:Envelope>"
  );
}

async function postSoap(url, soapAction, envelopeXml, agent) {
  let resp;
  try {
    resp = await undiciFetch(url, {
      method: "POST",
      headers: {
        "Content-Type": 'text/xml; charset="utf-8"',
        SOAPAction: `"${soapAction}"`,
      },
      body: envelopeXml,
      dispatcher: agent,
    });
  } catch (err) {
    throw new ESocialNetworkError(err);
  }
  const text = await resp.text();
  return { status: resp.status, text };
}

/** Extrai o texto de erro de um SOAP Fault, tratando tanto SOAP 1.1 (faultstring, texto puro) quanto 1.2 (Reason > Text). */
function extrairMensagemFault(text) {
  const faultstring = blocoBruto(text, "faultstring");
  if (faultstring != null) return decodeXmlEntities(faultstring);
  const reason = blocoBruto(text, "Reason");
  if (reason != null) {
    const reasonText = blocoBruto(reason, "Text");
    return decodeXmlEntities(reasonText ?? reason);
  }
  return null;
}

function extrairResultadoOuFalhar(text, status, tagResult) {
  const resultBruto = blocoBruto(text, tagResult);
  if (resultBruto == null) {
    const fault = extrairMensagemFault(text);
    throw new ESocialUpstreamError(
      fault ?? `Resposta inesperada do eSocial (SOAP sem elemento ${tagResult}, HTTP ${status})`,
      { httpStatus: status, rawResponse: text },
    );
  }
  return decodeXmlEntities(resultBruto);
}

/**
 * Consulta os identificadores (id + nrRec) dos eventos não periódicos/não
 * trabalhistas de um empregador em um período — primeiro passo para depois
 * baixar o XML de cada evento com solicitarDownloadEventosPorId.
 *
 * @param {{agent: import("undici").Agent, pemKey: string, pemCert: string,
 *   cnpjCliente: string, tpEvt: string, perApur: string}} params
 */
export async function consultarIdentificadoresEventosEmpregador({
  agent,
  pemKey,
  pemCert,
  cnpjCliente,
  tpEvt,
  perApur,
}) {
  validarTpEvt(tpEvt);
  validarPerApur(perApur);
  const { tpInsc, nrInsc } = ideEmpregador(cnpjCliente);

  const payload = payloadConsultaEmpregador({ tpInsc, nrInsc, tpEvt, perApur });
  const assinado = assinarXmlESocial(payload, pemKey, pemCert);
  const envelope = envelopeSoap({
    nsServico: NS_CONSULTA_SERVICO,
    elementoOperacao: "ConsultarIdentificadoresEventosEmpregador",
    elementoParametro: "consultaEventosEmpregador",
    signedPayloadXml: assinado,
  });

  const { status, text } = await postSoap(
    ESOCIAL_CONSULTA_URL,
    `${NS_CONSULTA_SERVICO}/ServicoConsultarIdentificadoresEventos/ConsultarIdentificadoresEventosEmpregador`,
    envelope,
    agent,
  );

  const inner = extrairResultadoOuFalhar(
    text,
    status,
    "ConsultarIdentificadoresEventosEmpregadorResult",
  );

  const retorno = blocoBruto(inner, "retornoConsultaIdentificadoresEvts") ?? "";
  const statusBloco = blocoBruto(retorno, "status") ?? "";
  const identBloco = blocoBruto(retorno, "retornoIdentificadoresEvts") ?? "";
  const eventos = blocosBrutos(identBloco, "identificadoresEvts").map((b) => ({
    id: campo(b, "id"),
    nrRec: campo(b, "nrRec"),
  }));

  return {
    httpStatus: status,
    cdResposta: campo(statusBloco, "cdResposta"),
    descResposta: campo(statusBloco, "descResposta"),
    qtdeTotEvtsConsulta: campo(identBloco, "qtdeTotEvtsConsulta"),
    dhUltimoEvtRetornado: campo(identBloco, "dhUltimoEvtRetornado"),
    eventos,
  };
}

/**
 * Baixa o XML original de eventos já identificados (via
 * consultarIdentificadoresEventosEmpregador) a partir da lista de `id`.
 * Faz chunking automático em lotes de DOWNLOAD_LOTE_SIZE, uma chamada SOAP
 * por lote, sequencialmente.
 *
 * `obterEntry` é chamado de novo antes de cada lote (em vez de receber um
 * agent/pemKey/pemCert fixos) para se autocurar caso o cache LRU de
 * certificados (lib/certificadoEscritorio.js) evicte ou revalide a entrada
 * do escritório no meio de um download grande com muitos lotes.
 *
 * Se um lote falhar, os arquivos já baixados nos lotes anteriores são
 * anexados ao erro lançado (`err.arquivosParciais`) em vez de descartados —
 * quem chamar pode decidir usar o que já foi baixado.
 *
 * @param {{obterEntry: () => Promise<{agent: import("undici").Agent, pemKey: string, pemCert: string}>,
 *   cnpjCliente: string, ids: string[]}} params
 */
export async function solicitarDownloadEventosPorId({ obterEntry, cnpjCliente, ids }) {
  if (!Array.isArray(ids) || ids.length === 0) {
    throw new ESocialValidationError(
      "ids deve ser uma lista não vazia de identificadores de evento (retornados por /esocial/eventos/identificadores)",
    );
  }
  if (ids.some((id) => typeof id !== "string" || id.trim() === "")) {
    throw new ESocialValidationError("ids deve conter apenas strings não vazias");
  }
  const { tpInsc, nrInsc } = ideEmpregador(cnpjCliente);

  const lotes = [];
  for (let i = 0; i < ids.length; i += DOWNLOAD_LOTE_SIZE) {
    lotes.push(ids.slice(i, i + DOWNLOAD_LOTE_SIZE));
  }

  const arquivos = [];
  const statusPorLote = [];

  for (const lote of lotes) {
    try {
      const entry = await obterEntry();
      const payload = payloadDownloadPorId({ tpInsc, nrInsc, ids: lote });
      const assinado = assinarXmlESocial(payload, entry.pemKey, entry.pemCert);
      const envelope = envelopeSoap({
        nsServico: NS_DOWNLOAD_SERVICO,
        elementoOperacao: "SolicitarDownloadEventosPorId",
        elementoParametro: "solicitacao",
        signedPayloadXml: assinado,
      });

      const { status, text } = await postSoap(
        ESOCIAL_DOWNLOAD_URL,
        `${NS_DOWNLOAD_SERVICO}/ServicoSolicitarDownloadEventos/SolicitarDownloadEventosPorId`,
        envelope,
        entry.agent,
      );

      const inner = extrairResultadoOuFalhar(text, status, "SolicitarDownloadEventosPorIdResult");

      const downloadBloco = blocoBruto(inner, "download") ?? "";
      const statusBloco = blocoBruto(downloadBloco, "status") ?? "";
      statusPorLote.push({
        httpStatus: status,
        cdResposta: campo(statusBloco, "cdResposta"),
        descResposta: campo(statusBloco, "descResposta"),
      });

      const retDownload = blocoBruto(downloadBloco, "retornoSolicDownloadEvts") ?? "";
      const arquivosBloco = blocoBruto(retDownload, "arquivos") ?? "";

      for (const arqRaw of blocosBrutos(arquivosBloco, "arquivo")) {
        const arqStatusBloco = blocoBruto(arqRaw, "status") ?? "";
        const item = {
          id: null,
          nrRec: null,
          cdResposta: campo(arqStatusBloco, "cdResposta"),
          descResposta: campo(arqStatusBloco, "descResposta"),
          xml: null,
        };

        const evtId = atributo(arqRaw, "evt", "Id");
        if (evtId != null) {
          item.id = evtId;
          item.xml = blocoBruto(arqRaw, "evt");
        } else {
          const recNr = atributo(arqRaw, "rec", "nrRec");
          if (recNr != null) {
            item.nrRec = recNr;
            item.xml = blocoBruto(arqRaw, "rec");
          }
        }

        arquivos.push(item);
      }
    } catch (err) {
      if (arquivos.length > 0) {
        err.arquivosParciais = arquivos;
        err.statusPorLoteParcial = statusPorLote;
      }
      throw err;
    }
  }

  return { statusPorLote, arquivos };
}
