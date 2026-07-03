// proxy-serpro/lib/esocialSign.js
// Assinatura digital XML (enveloped signature) exigida pelos Web Services de
// Consulta/Download do eSocial, conforme Manual de Orientação do
// Desenvolvedor: RSA-SHA256, digest SHA-256, canonicalização C14N (não
// exclusiva), transforms [enveloped-signature, C14N], referência de
// documento inteiro (URI vazia — os esquemas de consulta/download não
// definem atributo Id no elemento assinado) e KeyInfo contendo somente
// X509Certificate (sem cadeia, sem X509SubjectName/KeyValue).
//
// Verificado empiricamente (round-trip com SignedXml.checkSignature) contra
// os XSDs oficiais publicados em ConsultaIdentificadoresEventosEmpregador-
// v1_0_0.xsd e SolicitacaoDownloadEventosPorId-v1_0_0.xsd.

import { SignedXml } from "xml-crypto";

function pemCertParaBase64Der(pemCert) {
  return pemCert
    .replace(/-----BEGIN CERTIFICATE-----/g, "")
    .replace(/-----END CERTIFICATE-----/g, "")
    .replace(/\r?\n/g, "")
    .trim();
}

/**
 * Assina o elemento raiz de um XML eSocial (enveloped signature).
 * @param {string} xml     documento com elemento raiz único (ex: <eSocial>...)
 * @param {string} pemKey  chave privada PEM (RSA)
 * @param {string} pemCert certificado PEM do titular
 * @returns {string} XML assinado (com <Signature> como último filho da raiz)
 */
export function assinarXmlESocial(xml, pemKey, pemCert) {
  const certDer = pemCertParaBase64Der(pemCert);
  const sig = new SignedXml({
    privateKey: pemKey,
    publicCert: pemCert,
    signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
    canonicalizationAlgorithm: "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    getKeyInfoContent: () =>
      `<X509Data><X509Certificate>${certDer}</X509Certificate></X509Data>`,
  });

  sig.addReference({
    xpath: "/*",
    transforms: [
      "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
      "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    ],
    digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256",
    isEmptyUri: true,
  });

  sig.computeSignature(xml, { location: { reference: "/*", action: "append" } });
  return sig.getSignedXml();
}
