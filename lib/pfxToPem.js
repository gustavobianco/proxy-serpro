// proxy-serpro/lib/pfxToPem.js
// Converte um PKCS#12 (.pfx/.p12) em PEM (key + cert + cadeia).
//
// Motivo: Node 18+/OpenSSL 3 rejeita PKCS#12 com algoritmos legados
// (RC2-40, 3DES-SHA1) usados em certificados A1 brasileiros, com erro
// "Unsupported PKCS12 PFX data". node-forge é puro JS e aceita esses
// algoritmos, então convertemos para PEM e passamos key+cert ao undici.
//
// Reaproveitado pelo loader por escritório (lib/certificadoEscritorio.js).

import { createHash } from "node:crypto";
import forge from "node-forge";

/**
 * @param {Buffer} pfxBuffer  Conteúdo binário do .pfx
 * @param {string} senha      Senha do PKCS#12
 * @returns {{
 *   pemKey: string,
 *   pemCert: string,
 *   pemCa: string[],
 *   thumbprintSha256: string,
 *   titularCnpj: string|null,
 *   titularNome: string|null,
 *   validadeEm: Date|null
 * }}
 */
export function pfxToPem(pfxBuffer, senha) {
  const p12Der = pfxBuffer.toString("binary");
  const p12Asn1 = forge.asn1.fromDer(p12Der);
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, senha);

  // chave privada (PKCS#8 shrouded ou keyBag)
  const keyBags = p12.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  let keyObj = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag]?.[0]?.key;
  if (!keyObj) {
    const plainKeyBags = p12.getBags({ bagType: forge.pki.oids.keyBag });
    keyObj = plainKeyBags[forge.pki.oids.keyBag]?.[0]?.key;
  }
  if (!keyObj) throw new Error("nenhuma chave privada encontrada no PKCS#12");

  // certificados
  const certBags = p12.getBags({ bagType: forge.pki.oids.certBag });
  const certs = (certBags[forge.pki.oids.certBag] ?? []).map((b) => b.cert);
  if (certs.length === 0) throw new Error("nenhum certificado encontrado no PKCS#12");

  // titular = certificado cuja chave pública casa com a privada
  const pubKeyPem = forge.pki.publicKeyToPem(
    forge.pki.setRsaPublicKey(keyObj.n, keyObj.e),
  );
  const titular =
    certs.find((c) => forge.pki.publicKeyToPem(c.publicKey) === pubKeyPem) ??
    certs[0];
  const cadeia = certs.filter((c) => c !== titular);

  const pemKey = forge.pki.privateKeyToPem(keyObj);
  const pemCert = forge.pki.certificateToPem(titular);
  const pemCa = cadeia.map((c) => forge.pki.certificateToPem(c));

  // metadados úteis (thumbprint do DER do cert do titular)
  const certDer = forge.asn1.toDer(forge.pki.certificateToAsn1(titular)).getBytes();
  const certBuf = Buffer.from(certDer, "binary");
  const thumbprintSha256 = createHash("sha256").update(certBuf).digest("hex");

  const titularNome = titular.subject.getField("CN")?.value ?? null;
  let titularCnpj = null;
  const m = (titularNome ?? "").match(/(\d{2}\.?\d{3}\.?\d{3}\/?\d{4}-?\d{2})/);
  if (m) titularCnpj = m[1].replace(/\D/g, "");

  const validadeEm = titular.validity?.notAfter ?? null;

  return { pemKey, pemCert, pemCa, thumbprintSha256, titularCnpj, titularNome, validadeEm };
}
