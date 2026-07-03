// proxy-serpro/lib/esocialXml.js
// Helpers mínimos de extração de XML por regex, no mesmo espírito do
// TLeitor (extração sequencial por substring) usado pelas implementações
// de referência do eSocial (ex: ACBr). Evitamos um parser DOM completo
// aqui de propósito: os campos "evt"/"rec" do retorno de download contêm o
// XML original do evento aninhado cru, e queremos devolver esse XML
// byte-a-byte como foi recebido — sem reserializar via DOM, o que
// poderia alterar espaçamento/ordem de atributos e quebrar a fidelidade
// do arquivo original (importante para fins de auditoria/compliance).

/** Extrai o texto (decodificado) do primeiro elemento <tag>...</tag> ou <tag/>. */
export function campo(xml, tag) {
  const re = new RegExp(
    `<(?:\\w+:)?${tag}(?:\\s[^>]*)?(?:/>|>([\\s\\S]*?)<\\/(?:\\w+:)?${tag}>)`,
  );
  const m = xml.match(re);
  if (!m) return null;
  return m[1] !== undefined ? decodeXmlEntities(m[1].trim()) : "";
}

/** Extrai o valor de um atributo do primeiro elemento <tag ... attr="...">. */
export function atributo(xml, tag, attr) {
  const re = new RegExp(`<(?:\\w+:)?${tag}\\s+[^>]*\\b${attr}="([^"]*)"`);
  const m = xml.match(re);
  return m ? decodeXmlEntities(m[1]) : null;
}

/**
 * Extrai o conteúdo interno CRU (sem decodificar) do primeiro <tag>...</tag>.
 * Também aceita a forma self-closing <tag/> (devolve "" nesse caso), já que
 * um elemento complexo vazio pode ser serializado assim pelo gateway SOAP.
 */
export function blocoBruto(xml, tag) {
  const re = new RegExp(
    `<(?:\\w+:)?${tag}(?:\\s[^>]*)?(?:\\/>|>([\\s\\S]*?)<\\/(?:\\w+:)?${tag}>)`,
  );
  const m = xml.match(re);
  if (!m) return null;
  return m[1] !== undefined ? m[1] : "";
}

/** Extrai o conteúdo interno CRU de todas as ocorrências de <tag>...</tag> (irmãos, não aninhados). */
export function blocosBrutos(xml, tag) {
  const re = new RegExp(
    `<(?:\\w+:)?${tag}(?:\\s[^>]*)?(?:\\/>|>([\\s\\S]*?)<\\/(?:\\w+:)?${tag}>)`,
    "g",
  );
  const out = [];
  let m;
  while ((m = re.exec(xml)) !== null) out.push(m[1] !== undefined ? m[1] : "");
  return out;
}

/** Decodifica entidades XML predefinidas (ordem importa: &amp; por último). */
export function decodeXmlEntities(s) {
  return s
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}
