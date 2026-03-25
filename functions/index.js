/**
 * MBDJ — Cloud Functions: SEFAZ + Mercado Livre + Mercado Pago
 * v2.3 — Integração Mercado Pago (saldo + lançamentos futuros)
 * 
 * Changelog v2.3:
 *   - NOVO: mpSincronizar — puxa saldo MP + calendário de lançamentos futuros
 *     → Usa mesmo token OAuth do ML (mesma plataforma)
 *     → Balance: disponível + a liberar
 *     → Pedidos: busca payments com money_release_date
 *     → Calendário: agrupa por dia, retorna bruto/taxas/líquido
 *     → Salva snapshot no Firestore (config/mp_sync + config/mp_calendario)
 * 
 * Changelog v2.2:
 *   - Fix CRÍTICO: "Unsupported PKCS12 PFX data" em Node.js 18+
 *     → Usa node-forge para extrair cert+chave do PFX legado
 *     → Passa PEM (não PFX) para tls.createSecureContext
 *   - uploadCertificado agora valida via node-forge (não tls)
 *   - Cache converte PFX→PEM uma vez e reutiliza
 * 
 * Changelog v2.1:
 *   - Cache do certificado em memória
 *   - Retry automático com backoff
 *   - Extração de impostos detalhados
 *   - Tratamento cStat 656 (rate limit)
 */

const functions = require("firebase-functions");
const admin = require("firebase-admin");
const https = require("https");
const tls = require("tls");
const zlib = require("zlib");
const forge = require("node-forge");
const { DOMParser } = require("@xmldom/xmldom");

admin.initializeApp();
const db = admin.firestore();

// ══════════════════════════════════════════════════════════
//  CONFIGURAÇÃO
// ══════════════════════════════════════════════════════════
const CONFIG = {
  CNPJ: "44578505000103",
  UF_CODIGO: "35",
  AMBIENTE: "1",
  URL_PROD: "https://www1.nfe.fazenda.gov.br/NFeDistribuicaoDFe/NFeDistribuicaoDFe.asmx",
  URL_HOMOLOG: "https://hom1.nfe.fazenda.gov.br/NFeDistribuicaoDFe/NFeDistribuicaoDFe.asmx",
  MAX_ITERATIONS: 10,
  RATE_LIMIT_MS: 1500,
  RETRY_MAX: 2,
  RETRY_DELAY_MS: 3000,
};

// ══════════════════════════════════════════════════════════
//  CACHE DE CERTIFICADO EM MEMÓRIA (PEM convertido)
// ══════════════════════════════════════════════════════════
let _certCache = null;

/**
 * Converte PFX (que pode usar algoritmos legados RC2/3DES)
 * para PEM usando node-forge, que lida com esses formatos.
 * O Node.js 18+ recusa PFX legado via tls.createSecureContext.
 */
function pfxToPem(pfxBuffer, password) {
  // Decode o PFX com node-forge
  const pfxAsn1 = forge.asn1.fromDer(pfxBuffer.toString("binary"));
  const pfx = forge.pkcs12.pkcs12FromAsn1(pfxAsn1, false, password);

  // Extrair certificados
  const certBags = pfx.getBags({ bagType: forge.pki.oids.certBag });
  const certs = certBags[forge.pki.oids.certBag] || [];
  if (certs.length === 0) {
    throw new Error("Nenhum certificado encontrado no PFX.");
  }

  // Extrair chave privada
  const keyBags = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
  const keys = keyBags[forge.pki.oids.pkcs8ShroudedKeyBag] || [];
  if (keys.length === 0) {
    throw new Error("Nenhuma chave privada encontrada no PFX.");
  }

  // Converter para PEM
  const certPem = certs.map(bag => forge.pki.certificateToPem(bag.cert)).join("\n");
  const keyPem = forge.pki.privateKeyToPem(keys[0].key);

  // Extrair info do certificado para log
  const mainCert = certs[0].cert;
  const cn = mainCert.subject.getField("CN");
  const notAfter = mainCert.validity.notAfter;

  return {
    cert: certPem,
    key: keyPem,
    cn: cn ? cn.value : "N/A",
    expiraEm: notAfter.toISOString(),
    expirado: notAfter < new Date(),
  };
}

async function getCertificado() {
  // Cache válido por 5 minutos
  if (_certCache && (Date.now() - _certCache.loadedAt) < 300000) {
    return _certCache;
  }

  const doc = await db.collection("config").doc("sefaz_cert").get();
  if (!doc.exists || !doc.data().pfx_base64) {
    throw new Error("Certificado A1 não encontrado. Faça upload em Config SEFAZ.");
  }
  if (!doc.data().password) {
    throw new Error("Senha do certificado não encontrada.");
  }

  const pfxBuffer = Buffer.from(doc.data().pfx_base64, "base64");
  const password = doc.data().password;

  // Converter PFX legado → PEM via node-forge
  const pem = pfxToPem(pfxBuffer, password);

  if (pem.expirado) {
    console.warn(`[CERT] ⚠️ Certificado EXPIRADO! CN=${pem.cn}, expirou em ${pem.expiraEm}`);
    throw new Error(`Certificado A1 expirado em ${pem.expiraEm.substring(0, 10)}. Renove o certificado.`);
  }

  console.log(`[CERT] Certificado carregado: CN=${pem.cn}, expira em ${pem.expiraEm.substring(0, 10)}`);

  _certCache = {
    cert: pem.cert,
    key: pem.key,
    cn: pem.cn,
    expiraEm: pem.expiraEm,
    loadedAt: Date.now(),
  };

  return _certCache;
}

// ══════════════════════════════════════════════════════════
//  SOAP ENVELOPES
// ══════════════════════════════════════════════════════════
function buildSoapDistNSU(ultNSU, cnpj, uf, ambiente) {
  const nsu = String(ultNSU).padStart(15, "0");
  return `<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
  <soap12:Body>
    <nfeDistDFeInteresse xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe">
      <nfeDadosMsg>
        <distDFeInt xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.01">
          <tpAmb>${ambiente}</tpAmb>
          <cUFAutor>${uf}</cUFAutor>
          <CNPJ>${cnpj}</CNPJ>
          <distNSU>
            <ultNSU>${nsu}</ultNSU>
          </distNSU>
        </distDFeInt>
      </nfeDadosMsg>
    </nfeDistDFeInteresse>
  </soap12:Body>
</soap12:Envelope>`;
}

function buildSoapConsChNFe(chaveNFe, cnpj, uf, ambiente) {
  return `<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
  <soap12:Body>
    <nfeDistDFeInteresse xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe">
      <nfeDadosMsg>
        <distDFeInt xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.01">
          <tpAmb>${ambiente}</tpAmb>
          <cUFAutor>${uf}</cUFAutor>
          <CNPJ>${cnpj}</CNPJ>
          <consChNFe>
            <chNFe>${chaveNFe}</chNFe>
          </consChNFe>
        </distDFeInt>
      </nfeDadosMsg>
    </nfeDistDFeInteresse>
  </soap12:Body>
</soap12:Envelope>`;
}

// ══════════════════════════════════════════════════════════
//  CHAMADA SOAP COM CERTIFICADO A1 (PEM) + RETRY
// ══════════════════════════════════════════════════════════
async function callSefaz(soapBody) {
  const cert = await getCertificado();
  const url = CONFIG.AMBIENTE === "1" ? CONFIG.URL_PROD : CONFIG.URL_HOMOLOG;
  const parsedUrl = new URL(url);

  // ✅ Usa PEM (cert + key) em vez de PFX — compatível com Node 18+
  const sslContext = tls.createSecureContext({
    cert: cert.cert,
    key: cert.key,
  });
  const agent = new https.Agent({ secureContext: sslContext });

  const options = {
    hostname: parsedUrl.hostname,
    port: 443,
    path: parsedUrl.pathname,
    method: "POST",
    headers: {
      "Content-Type": "application/soap+xml; charset=utf-8",
      "Content-Length": Buffer.byteLength(soapBody, "utf-8"),
    },
    agent: agent,
  };

  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      const data = [];
      res.on("data", (chunk) => data.push(chunk));
      res.on("end", () => {
        const body = Buffer.concat(data).toString("utf-8");
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(body);
        } else {
          reject(new Error(`SEFAZ HTTP ${res.statusCode}: ${body.substring(0, 500)}`));
        }
      });
    });
    req.on("error", (e) => reject(new Error(`SEFAZ Connection Error: ${e.message}`)));
    req.setTimeout(30000, () => { req.destroy(); reject(new Error("SEFAZ Timeout (30s)")); });
    req.write(soapBody);
    req.end();
  });
}

async function callSefazWithRetry(soapBody) {
  let lastError;
  for (let attempt = 0; attempt <= CONFIG.RETRY_MAX; attempt++) {
    try {
      return await callSefaz(soapBody);
    } catch (e) {
      lastError = e;
      const msg = e.message || "";
      const isRetryable = msg.includes("Timeout") || msg.includes("Connection Error") ||
        msg.includes("ECONNRESET") || msg.includes("ETIMEDOUT") || msg.includes("socket hang up");
      if (!isRetryable || attempt >= CONFIG.RETRY_MAX) throw e;
      const delay = CONFIG.RETRY_DELAY_MS * (attempt + 1);
      console.warn(`[callSefaz] Tentativa ${attempt + 1} falhou (${msg}). Retentando em ${delay}ms...`);
      await sleep(delay);
    }
  }
  throw lastError;
}

// ══════════════════════════════════════════════════════════
//  PARSER — resposta SOAP da SEFAZ
// ══════════════════════════════════════════════════════════
function parseSefazResponse(xmlResponse) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlResponse, "text/xml");

  const retNode = doc.getElementsByTagNameNS("http://www.portalfiscal.inf.br/nfe", "retDistDFeInt");
  if (!retNode || retNode.length === 0) {
    throw new Error("Resposta SEFAZ inválida: retDistDFeInt não encontrado");
  }

  const ret = retNode[0];
  const cStat = getTagText(ret, "cStat");
  const xMotivo = getTagText(ret, "xMotivo");
  const ultNSU = getTagText(ret, "ultNSU");
  const maxNSU = getTagText(ret, "maxNSU");

  const result = { cStat, xMotivo, ultNSU: ultNSU || "0", maxNSU: maxNSU || "0", documentos: [] };

  if (cStat !== "138") return result;

  const docZips = ret.getElementsByTagNameNS("http://www.portalfiscal.inf.br/nfe", "docZip");
  for (let i = 0; i < docZips.length; i++) {
    const docZip = docZips[i];
    const nsu = docZip.getAttribute("NSU") || "";
    const schema = docZip.getAttribute("schema") || "";
    const base64Content = docZip.textContent || "";

    try {
      const compressed = Buffer.from(base64Content, "base64");
      let xmlContent;
      try { xmlContent = zlib.gunzipSync(compressed).toString("utf-8"); }
      catch (_e1) {
        try { xmlContent = zlib.inflateSync(compressed).toString("utf-8"); }
        catch (_e2) { xmlContent = zlib.inflateRawSync(compressed).toString("utf-8"); }
      }

      const nfeData = parseNFeXMLContent(xmlContent, schema);
      if (nfeData) {
        nfeData._nsu = nsu;
        nfeData._schema = schema;
        result.documentos.push(nfeData);
      }
    } catch (e) {
      console.warn(`Erro ao descomprimir docZip NSU ${nsu}:`, e.message);
    }
  }

  return result;
}

function parseNFeXMLContent(xmlContent, schema) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlContent, "text/xml");
  const ns = "http://www.portalfiscal.inf.br/nfe";

  const isResumo = schema.includes("resNFe") || doc.getElementsByTagNameNS(ns, "resNFe").length > 0;
  const isEvento = schema.includes("resEvento") || doc.getElementsByTagNameNS(ns, "resEvento").length > 0;
  const isNFeCompleta = doc.getElementsByTagNameNS(ns, "nfeProc").length > 0 || doc.getElementsByTagNameNS(ns, "NFe").length > 0;

  if (isResumo) {
    const resNFe = doc.getElementsByTagNameNS(ns, "resNFe")[0];
    if (!resNFe) return null;
    return {
      tipo: "resumo",
      chave: resNFe.getAttribute("chNFe") || getTagTextNS(resNFe, ns, "chNFe"),
      cnpj: getTagTextNS(resNFe, ns, "CNPJ"),
      nome: getTagTextNS(resNFe, ns, "xNome"),
      ie: getTagTextNS(resNFe, ns, "IE"),
      emissao: (getTagTextNS(resNFe, ns, "dhEmi") || "").substring(0, 10),
      valor: parseFloat(getTagTextNS(resNFe, ns, "vNF")) || 0,
      situacao: getTagTextNS(resNFe, ns, "cSitNFe"),
      xmlOriginal: xmlContent,
    };
  }

  if (isEvento) return { tipo: "evento", xmlOriginal: xmlContent };
  if (isNFeCompleta) return parseNFeCompleta(doc, ns, xmlContent);
  return null;
}

function parseNFeCompleta(doc, ns, xmlOriginal) {
  const infNFe = doc.getElementsByTagNameNS(ns, "infNFe");
  if (infNFe.length === 0) return null;

  const inf = infNFe[0];
  const chaveId = inf.getAttribute("Id") || "";
  const chave = chaveId.replace(/^NFe/, "");

  const ide = inf.getElementsByTagNameNS(ns, "ide");
  let numero = "", serie = "", emissao = "", natOp = "";
  if (ide.length > 0) {
    numero = getTagTextNS(ide[0], ns, "nNF");
    serie = getTagTextNS(ide[0], ns, "serie");
    const dhEmi = getTagTextNS(ide[0], ns, "dhEmi") || getTagTextNS(ide[0], ns, "dEmi");
    emissao = dhEmi ? dhEmi.substring(0, 10) : "";
    natOp = getTagTextNS(ide[0], ns, "natOp");
  }

  const emit = inf.getElementsByTagNameNS(ns, "emit");
  let emitNome = "", emitCNPJ = "";
  if (emit.length > 0) {
    emitNome = getTagTextNS(emit[0], ns, "xNome");
    const emitFant = getTagTextNS(emit[0], ns, "xFant");
    if (emitFant && emitFant.length > 2) emitNome = emitFant;
    emitCNPJ = getTagTextNS(emit[0], ns, "CNPJ") || getTagTextNS(emit[0], ns, "CPF");
  }

  const dest = inf.getElementsByTagNameNS(ns, "dest");
  let destNome = "", destCNPJ = "";
  if (dest.length > 0) {
    destNome = getTagTextNS(dest[0], ns, "xNome");
    const destFant = getTagTextNS(dest[0], ns, "xFant");
    if (destFant && destFant.length > 2) destNome = destFant;
    destCNPJ = getTagTextNS(dest[0], ns, "CNPJ") || getTagTextNS(dest[0], ns, "CPF");
  }

  const emitCNPJLimpo = (emitCNPJ || "").replace(/[.\-\/]/g, "");
  let fornNome, fornCNPJ;
  if (emitCNPJLimpo === CONFIG.CNPJ) {
    fornNome = destNome; fornCNPJ = destCNPJ;
  } else {
    fornNome = emitNome; fornCNPJ = emitCNPJ;
  }

  if (fornCNPJ && fornCNPJ.length === 14) {
    fornCNPJ = fornCNPJ.replace(/^(\d{2})(\d{3})(\d{3})(\d{4})(\d{2})$/, "$1.$2.$3/$4-$5");
  }

  const icmsTot = inf.getElementsByTagNameNS(ns, "ICMSTot");
  let valorTotal = "0", vICMS = "0", vPIS = "0", vCOFINS = "0", vIPI = "0", vST = "0", vBC = "0", vProd = "0", vBCST = "0";
  if (icmsTot.length > 0) {
    valorTotal = getTagTextNS(icmsTot[0], ns, "vNF");
    vICMS = getTagTextNS(icmsTot[0], ns, "vICMS");
    vPIS = getTagTextNS(icmsTot[0], ns, "vPIS");
    vCOFINS = getTagTextNS(icmsTot[0], ns, "vCOFINS");
    vIPI = getTagTextNS(icmsTot[0], ns, "vIPI");
    vST = getTagTextNS(icmsTot[0], ns, "vST");
    vBC = getTagTextNS(icmsTot[0], ns, "vBC");
    vProd = getTagTextNS(icmsTot[0], ns, "vProd");
    vBCST = getTagTextNS(icmsTot[0], ns, "vBCST");
  }

  const dets = inf.getElementsByTagNameNS(ns, "det");
  const produtos = [];
  let somaBcPIS = 0, somaBcCOFINS = 0, aliqPISItem = 0, aliqCOFINSItem = 0;
  for (let d = 0; d < dets.length; d++) {
    const prod = dets[d].getElementsByTagNameNS(ns, "prod");
    if (prod.length > 0) {
      produtos.push({
        codigo: getTagTextNS(prod[0], ns, "cProd"),
        descricao: getTagTextNS(prod[0], ns, "xProd"),
        ncm: getTagTextNS(prod[0], ns, "NCM"),
        cfop: getTagTextNS(prod[0], ns, "CFOP"),
        unidade: getTagTextNS(prod[0], ns, "uCom"),
        qtd: getTagTextNS(prod[0], ns, "qCom"),
        vUnit: getTagTextNS(prod[0], ns, "vUnCom"),
        vTotal: getTagTextNS(prod[0], ns, "vProd"),
      });
    }
    const pisNodes = dets[d].getElementsByTagNameNS(ns, "PIS");
    if (pisNodes.length > 0) {
      const bcP = parseFloat(getTagTextNS(pisNodes[0], ns, "vBC")) || 0;
      const alP = parseFloat(getTagTextNS(pisNodes[0], ns, "pPIS")) || 0;
      somaBcPIS += bcP;
      if (alP > 0) aliqPISItem = alP;
    }
    const cofNodes = dets[d].getElementsByTagNameNS(ns, "COFINS");
    if (cofNodes.length > 0) {
      const bcC = parseFloat(getTagTextNS(cofNodes[0], ns, "vBC")) || 0;
      const alC = parseFloat(getTagTextNS(cofNodes[0], ns, "pCOFINS")) || 0;
      somaBcCOFINS += bcC;
      if (alC > 0) aliqCOFINSItem = alC;
    }
  }

  const dups = inf.getElementsByTagNameNS(ns, "dup");
  const duplicatas = [];
  for (let dd = 0; dd < dups.length; dd++) {
    duplicatas.push({
      nDup: getTagTextNS(dups[dd], ns, "nDup"),
      dVenc: getTagTextNS(dups[dd], ns, "dVenc"),
      vDup: getTagTextNS(dups[dd], ns, "vDup"),
    });
  }

  const transp = inf.getElementsByTagNameNS(ns, "transp");
  let modFrete = "";
  if (transp.length > 0) modFrete = getTagTextNS(transp[0], ns, "modFrete");

  return {
    tipo: "nfe_completa",
    numero, serie, emissao, fornecedor: fornNome, cnpj: fornCNPJ,
    emitente: emitNome, emitenteCNPJ: emitCNPJ,
    destinatario: destNome, destinatarioCNPJ: destCNPJ,
    valor: valorTotal, chave, natOp, produtos, duplicatas,
    impostos: { vICMS, vPIS, vCOFINS, vIPI, vST, vBC, vProd, vBCST, bcPIS: String(somaBcPIS), bcCOFINS: String(somaBcCOFINS), pPIS: String(aliqPISItem), pCOFINS: String(aliqCOFINSItem) },
    modFrete, xmlOriginal,
  };
}

function getTagText(parent, tagName) {
  const els = parent.getElementsByTagName(tagName);
  return els.length > 0 ? (els[0].textContent || "").trim() : "";
}

function getTagTextNS(parent, ns, tagName) {
  const els = parent.getElementsByTagNameNS(ns, tagName);
  return els.length > 0 ? (els[0].textContent || "").trim() : "";
}

// ══════════════════════════════════════════════════════════
//  CLOUD FUNCTION: sincronizarSefaz
// ══════════════════════════════════════════════════════════
exports.sincronizarSefaz = functions
  .runWith({ timeoutSeconds: 120, memory: "512MB" })
  .https.onCall(async (data, context) => {
    if (!context.auth) {
      throw new functions.https.HttpsError("unauthenticated", "Usuário não autenticado.");
    }

    const startTime = Date.now();
    console.log(`[sincronizarSefaz] Iniciado por ${context.auth.uid}`);

    try {
      const configDoc = await db.collection("config").doc("sefaz_sync").get();
      let ultNSU = configDoc.exists ? (configDoc.data().ultNSU || "0") : "0";

      let totalDocs = 0, totalNFe = 0, totalResumos = 0, totalEventos = 0;
      let iterations = 0, hasMore = true;
      const nfesImportadas = [];

      while (hasMore && iterations < CONFIG.MAX_ITERATIONS) {
        iterations++;
        const iterStart = Date.now();

        const soapBody = buildSoapDistNSU(ultNSU, CONFIG.CNPJ, CONFIG.UF_CODIGO, CONFIG.AMBIENTE);
        const response = await callSefazWithRetry(soapBody);
        const result = parseSefazResponse(response);

        console.log(`[sincronizarSefaz] Iter ${iterations} (${Date.now() - iterStart}ms): cStat=${result.cStat} | ${result.documentos.length} docs | ultNSU=${result.ultNSU}`);

        if (result.cStat === "137") { hasMore = false; break; }
        if (result.cStat === "656") {
          console.warn("[sincronizarSefaz] Rate limit SEFAZ (656). Parando.");
          hasMore = false; break;
        }
        if (result.cStat !== "138") {
          throw new Error(`SEFAZ retornou ${result.cStat}: ${result.xMotivo}`);
        }

        for (const doc of result.documentos) {
          totalDocs++;
          if (doc.tipo === "nfe_completa") {
            const saved = await salvarNFeNoFirestore(doc);
            totalNFe++;
            if (saved) nfesImportadas.push({ numero: doc.numero, fornecedor: doc.fornecedor, valor: doc.valor, emissao: doc.emissao });
          } else if (doc.tipo === "resumo") {
            totalResumos++;
            if (doc.situacao === "1" && doc.chave) {
              try {
                const soapChave = buildSoapConsChNFe(doc.chave, CONFIG.CNPJ, CONFIG.UF_CODIGO, CONFIG.AMBIENTE);
                const resChave = await callSefazWithRetry(soapChave);
                const resultChave = parseSefazResponse(resChave);
                for (const d of resultChave.documentos) {
                  if (d.tipo === "nfe_completa") {
                    const saved = await salvarNFeNoFirestore(d);
                    totalNFe++;
                    if (saved) nfesImportadas.push({ numero: d.numero, fornecedor: d.fornecedor, valor: d.valor, emissao: d.emissao });
                  }
                }
                await sleep(CONFIG.RATE_LIMIT_MS);
              } catch (e) {
                console.warn(`Erro ao buscar NF-e chave ${doc.chave}:`, e.message);
                await salvarResumoNoFirestore(doc);
              }
            }
          } else if (doc.tipo === "evento") {
            totalEventos++;
          }
        }

        ultNSU = result.ultNSU;
        hasMore = parseInt(result.ultNSU) < parseInt(result.maxNSU);
        if (hasMore) await sleep(CONFIG.RATE_LIMIT_MS);
      }

      await db.collection("config").doc("sefaz_sync").set({
        ultNSU, ultimaSincronizacao: new Date().toISOString(), totalDocsSincronizados: totalDocs,
      }, { merge: true });

      const duracao = ((Date.now() - startTime) / 1000).toFixed(1);
      const resultado = {
        success: true, ultNSU, totalDocs, totalNFe, totalResumos, totalEventos,
        iteracoes: iterations, hasMore, duracaoSegundos: duracao,
        nfesImportadas: nfesImportadas.slice(0, 20),
        msg: totalNFe > 0
          ? `✅ ${totalNFe} NF-e(s) importada(s) da SEFAZ em ${duracao}s!`
          : `Nenhuma NF-e nova encontrada. (${totalDocs} docs processados em ${duracao}s)`,
      };
      console.log(`[sincronizarSefaz] Concluído em ${duracao}s`);
      return resultado;

    } catch (error) {
      console.error(`[sincronizarSefaz] ERRO:`, error);
      throw new functions.https.HttpsError("internal", error.message);
    }
  });

// ══════════════════════════════════════════════════════════
//  SALVAR NF-e NO FIRESTORE
// ══════════════════════════════════════════════════════════
async function salvarNFeNoFirestore(nfe) {
  const existing = await db.collection("dados").doc("notas_fiscais").get();
  let nfeItems = [];

  if (existing.exists) {
    const data = existing.data();
    if (data._chunked) {
      const chunks = await db.collection("dados")
        .where("_parentKey", "==", "notas_fiscais").orderBy("_chunkIndex").get();
      chunks.forEach(c => {
        try { nfeItems = nfeItems.concat(JSON.parse(c.data().valor)); } catch (e) { }
      });
    } else if (data.valor) {
      try { nfeItems = JSON.parse(data.valor); } catch (e) { nfeItems = []; }
    }
  }

  if (nfe.chave && nfeItems.some(n => n.chave === nfe.chave)) return false;

  nfeItems.push({
    numero: nfe.numero, serie: nfe.serie, emissao: nfe.emissao,
    fornecedor: nfe.fornecedor, cnpj: nfe.cnpj,
    emitente: nfe.emitente || "", emitenteCNPJ: nfe.emitenteCNPJ || "",
    destinatario: nfe.destinatario || "", destinatarioCNPJ: nfe.destinatarioCNPJ || "",
    valor: formatCurrencyBR(parseFloat(nfe.valor) || 0),
    chave: nfe.chave, status: "Processada", natOp: nfe.natOp,
    produtos: nfe.produtos || [], duplicatas: nfe.duplicatas || [],
    impostos: nfe.impostos || {}, modFrete: nfe.modFrete || "",
    origem: "sefaz_auto", _importadoEm: new Date().toISOString(),
  });

  const jsonVal = JSON.stringify(nfeItems);
  const CHUNK_THRESHOLD = 800000, CHUNK_TARGET = 500000;

  if (jsonVal.length < CHUNK_THRESHOLD) {
    await db.collection("dados").doc("notas_fiscais").set({ valor: jsonVal, atualizado_em: new Date().toISOString() });
  } else {
    const chunks = []; let currentChunk = [], currentSize = 0;
    for (const item of nfeItems) {
      const itemJson = JSON.stringify(item);
      if (currentSize + itemJson.length > CHUNK_TARGET && currentChunk.length > 0) { chunks.push(currentChunk); currentChunk = []; currentSize = 0; }
      currentChunk.push(item); currentSize += itemJson.length;
    }
    if (currentChunk.length > 0) chunks.push(currentChunk);

    const oldChunks = await db.collection("dados").where("_parentKey", "==", "notas_fiscais").get();
    if (!oldChunks.empty) { const batch = db.batch(); oldChunks.forEach(d => batch.delete(d.ref)); await batch.commit(); }

    await db.collection("dados").doc("notas_fiscais").set({ _chunked: true, _totalChunks: chunks.length, _totalItems: nfeItems.length, atualizado_em: new Date().toISOString() });
    for (let i = 0; i < chunks.length; i++) {
      await db.collection("dados").doc(`notas_fiscais__chunk_${i}`).set({ valor: JSON.stringify(chunks[i]), _parentKey: "notas_fiscais", _chunkIndex: i, atualizado_em: new Date().toISOString() });
    }
  }
  console.log(`[salvarNFe] NF-e ${nfe.numero} salva (total: ${nfeItems.length})`);

  await gerarCreditosTribServer(nfe);
  return true;
}

// ══════════════════════════════════════════════════════════
//  GERAÇÃO AUTOMÁTICA DE CRÉDITOS TRIBUTÁRIOS (server)
// ══════════════════════════════════════════════════════════
const CFOPS_CREDITO = ['5401','5403','5405','6401','6403','6405','1401','1403','2401','2403'];

async function gerarCreditosTribServer(nfe) {
  const emitCNPJLimpo = (nfe.emitenteCNPJ || nfe.cnpj || "").replace(/[.\-\/]/g, "");
  if (emitCNPJLimpo === CONFIG.CNPJ) return 0;

  const cfopsNFe = (nfe.produtos || []).map(p => String(p.cfop || ""));
  const temCfopCredito = cfopsNFe.some(c => CFOPS_CREDITO.includes(c));
  if (!temCfopCredito) return 0;

  const impostos = nfe.impostos || {};
  const vPIS = parseFloat(impostos.vPIS) || 0;
  const vCOFINS = parseFloat(impostos.vCOFINS) || 0;
  const vICMS = parseFloat(impostos.vICMS) || 0;
  const vBC = parseFloat(impostos.vBC) || 0;

  const bcPIS = parseFloat(impostos.bcPIS) || 0;
  const bcCOFINS = parseFloat(impostos.bcCOFINS) || 0;
  const pPIS = parseFloat(impostos.pPIS) || 0;
  const pCOFINS = parseFloat(impostos.pCOFINS) || 0;

  if (vPIS === 0 && vCOFINS === 0 && vICMS === 0) return 0;

  const aliqPIS = pPIS > 0 ? pPIS : (bcPIS > 0 ? (vPIS / bcPIS * 100) : 0);
  const aliqCOFINS = pCOFINS > 0 ? pCOFINS : (bcCOFINS > 0 ? (vCOFINS / bcCOFINS * 100) : 0);
  const aliqICMS = vBC > 0 ? (vICMS / vBC * 100) : 0;
  const basePISExib = bcPIS > 0 ? bcPIS : (parseFloat(impostos.vProd) || parseFloat(nfe.valor) || 0);
  const baseCOFINSExib = bcCOFINS > 0 ? bcCOFINS : (parseFloat(impostos.vProd) || parseFloat(nfe.valor) || 0);

  const ctDoc = await db.collection("dados").doc("creditos_trib").get();
  let ctItems = [];
  if (ctDoc.exists) {
    const data = ctDoc.data();
    if (data._chunked) {
      const chunks = await db.collection("dados").where("_parentKey", "==", "creditos_trib").orderBy("_chunkIndex").get();
      chunks.forEach(c => { try { ctItems = ctItems.concat(JSON.parse(c.data().valor)); } catch (e) {} });
    } else if (data.valor) {
      try { ctItems = JSON.parse(data.valor); } catch (e) { ctItems = []; }
    }
  }

  const nfeRef = String(nfe.numero || "");
  if (ctItems.some(ct => ct.nfRef === nfeRef && ct._chaveNFe === nfe.chave)) return 0;

  const competencia = nfe.emissao || "";
  const fornecedor = nfe.fornecedor || "";
  const cfopsStr = cfopsNFe.filter(c => CFOPS_CREDITO.includes(c)).join(", ");
  let count = 0;

  if (vPIS > 0) {
    ctItems.push({ imposto: "PIS", natureza: "Crédito", competencia, valor: formatCurrencyBR(vPIS), baseCalculo: formatCurrencyBR(basePISExib), aliquota: aliqPIS.toFixed(2) + "%", nfRef: nfeRef, fornecedor, descricao: `PIS s/ compra NF-e ${nfeRef} (CFOP ${cfopsStr})`, _chaveNFe: nfe.chave || "", _geradoAuto: true });
    count++;
  }
  if (vCOFINS > 0) {
    ctItems.push({ imposto: "COFINS", natureza: "Crédito", competencia, valor: formatCurrencyBR(vCOFINS), baseCalculo: formatCurrencyBR(baseCOFINSExib), aliquota: aliqCOFINS.toFixed(2) + "%", nfRef: nfeRef, fornecedor, descricao: `COFINS s/ compra NF-e ${nfeRef} (CFOP ${cfopsStr})`, _chaveNFe: nfe.chave || "", _geradoAuto: true });
    count++;
  }
  if (vICMS > 0) {
    ctItems.push({ imposto: "ICMS", natureza: "Crédito", competencia, valor: formatCurrencyBR(vICMS), baseCalculo: formatCurrencyBR(vBC), aliquota: aliqICMS.toFixed(2) + "%", nfRef: nfeRef, fornecedor, descricao: `ICMS próprio s/ compra NF-e ${nfeRef} (CFOP ${cfopsStr})`, _chaveNFe: nfe.chave || "", _geradoAuto: true });
    count++;
  }

  if (count > 0) {
    const jsonVal = JSON.stringify(ctItems);
    if (jsonVal.length < 800000) {
      await db.collection("dados").doc("creditos_trib").set({ valor: jsonVal, atualizado_em: new Date().toISOString() });
    } else {
      const chunks = []; let curr = [], sz = 0;
      for (const item of ctItems) { const ij = JSON.stringify(item); if (sz + ij.length > 500000 && curr.length > 0) { chunks.push(curr); curr = []; sz = 0; } curr.push(item); sz += ij.length; }
      if (curr.length > 0) chunks.push(curr);
      const old = await db.collection("dados").where("_parentKey", "==", "creditos_trib").get();
      if (!old.empty) { const b = db.batch(); old.forEach(d => b.delete(d.ref)); await b.commit(); }
      await db.collection("dados").doc("creditos_trib").set({ _chunked: true, _totalChunks: chunks.length, _totalItems: ctItems.length, atualizado_em: new Date().toISOString() });
      for (let i = 0; i < chunks.length; i++) { await db.collection("dados").doc(`creditos_trib__chunk_${i}`).set({ valor: JSON.stringify(chunks[i]), _parentKey: "creditos_trib", _chunkIndex: i, atualizado_em: new Date().toISOString() }); }
    }
    console.log(`[CreditosTrib] ${count} crédito(s) gerado(s) para NF-e ${nfeRef} de ${fornecedor} | PIS: ${aliqPIS.toFixed(2)}% COFINS: ${aliqCOFINS.toFixed(2)}% ICMS: ${aliqICMS.toFixed(2)}%`);
  }
  return count;
}

async function salvarResumoNoFirestore(resumo) {
  if (resumo.chave) {
    await db.collection("sefaz_resumos").doc(resumo.chave).set({
      tipo: resumo.tipo, chave: resumo.chave, cnpj: resumo.cnpj, nome: resumo.nome,
      emissao: resumo.emissao, valor: resumo.valor, situacao: resumo.situacao,
      _importadoEm: new Date().toISOString(),
    });
  }
}

// ══════════════════════════════════════════════════════════
//  CLOUD FUNCTION: uploadCertificado
// ══════════════════════════════════════════════════════════
exports.uploadCertificado = functions
  .runWith({ timeoutSeconds: 30, memory: "256MB" })
  .https.onCall(async (data, context) => {
    if (!context.auth) throw new functions.https.HttpsError("unauthenticated", "Não autenticado.");

    const { pfxBase64, password } = data;
    if (!pfxBase64 || !password) throw new functions.https.HttpsError("invalid-argument", "Certificado e senha são obrigatórios.");

    try {
      const pfxBuffer = Buffer.from(pfxBase64, "base64");
      if (pfxBuffer.length < 100) throw new Error("Arquivo muito pequeno para ser um PFX válido");
      if (pfxBuffer.length > 50000) throw new Error("Arquivo muito grande (max 50KB)");

      // ✅ Valida via node-forge (suporta PFX legado com RC2/3DES)
      const pem = pfxToPem(pfxBuffer, password);

      const info = {
        cn: pem.cn,
        expiraEm: pem.expiraEm,
        expirado: pem.expirado,
      };

      if (pem.expirado) {
        throw new functions.https.HttpsError(
          "invalid-argument",
          `Certificado expirado em ${pem.expiraEm.substring(0, 10)}. Renove o certificado A1.`
        );
      }

      console.log(`[uploadCert] Certificado válido: CN=${pem.cn}, expira em ${pem.expiraEm.substring(0, 10)}`);
    } catch (e) {
      if (e instanceof functions.https.HttpsError) throw e;
      const msg = e.message || "";
      if (msg.includes("Invalid password") || msg.includes("PKCS#12 MAC could not be verified")) {
        throw new functions.https.HttpsError("invalid-argument", "Senha do certificado incorreta.");
      }
      if (msg.includes("Too few bytes") || msg.includes("ASN.1") || msg.includes("Invalid PFX")) {
        throw new functions.https.HttpsError("invalid-argument", "Arquivo não é um certificado PFX/P12 válido.");
      }
      throw new functions.https.HttpsError("invalid-argument", `Certificado inválido: ${msg}`);
    }

    _certCache = null;
    await db.collection("config").doc("sefaz_cert").set({
      pfx_base64: pfxBase64,
      password,
      uploadedAt: new Date().toISOString(),
      uploadedBy: context.auth.uid,
    });
    return { success: true, msg: "✅ Certificado A1 validado e salvo com sucesso!" };
  });

// ══════════════════════════════════════════════════════════
//  CLOUD FUNCTION: statusSefaz
// ══════════════════════════════════════════════════════════
exports.statusSefaz = functions
  .https.onCall(async (data, context) => {
    if (!context.auth) throw new functions.https.HttpsError("unauthenticated", "Não autenticado.");

    const certDoc = await db.collection("config").doc("sefaz_cert").get();
    const syncDoc = await db.collection("config").doc("sefaz_sync").get();

    // Tentar extrair info do certificado
    let certInfo = null;
    if (certDoc.exists && certDoc.data().pfx_base64) {
      try {
        const pfxBuffer = Buffer.from(certDoc.data().pfx_base64, "base64");
        const pem = pfxToPem(pfxBuffer, certDoc.data().password);
        certInfo = { cn: pem.cn, expiraEm: pem.expiraEm, expirado: pem.expirado };
      } catch (e) {
        certInfo = { erro: e.message };
      }
    }

    return {
      certificadoConfigurado: certDoc.exists && !!certDoc.data().pfx_base64,
      certificadoUploadedAt: certDoc.exists ? certDoc.data().uploadedAt : null,
      certificadoInfo: certInfo,
      ultimaSincronizacao: syncDoc.exists ? syncDoc.data().ultimaSincronizacao : null,
      ultNSU: syncDoc.exists ? syncDoc.data().ultNSU : "0",
      totalDocsSincronizados: syncDoc.exists ? syncDoc.data().totalDocsSincronizados : 0,
      cnpj: CONFIG.CNPJ,
      ambiente: CONFIG.AMBIENTE === "1" ? "Produção" : "Homologação",
    };
  });

// ══════════════════════════════════════════════════════════
//  MERCADO LIVRE — INTEGRAÇÃO API
// ══════════════════════════════════════════════════════════

const ML_CONFIG = {
  APP_ID: "3526571885666255",
  SECRET_KEY: "IkCYM5wNRIJDPxv0ZKgu8NZwhjyZwBSN",
  REDIRECT_URI: "https://mbdj-financeiro.web.app/auth/ml/callback",
  AUTH_URL: "https://auth.mercadolivre.com.br/authorization",
  TOKEN_URL: "https://api.mercadolibre.com/oauth/token",
  API_BASE: "https://api.mercadolibre.com",
};

exports.mlGetAuthUrl = functions
  .runWith({ timeoutSeconds: 10, memory: "128MB" })
  .https.onCall(async (data, context) => {
    const crypto = require("crypto");
    const codeVerifier = crypto.randomBytes(64).toString("base64url").substring(0, 128);
    const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");

    const url = `${ML_CONFIG.AUTH_URL}?response_type=code&client_id=${ML_CONFIG.APP_ID}&redirect_uri=${encodeURIComponent(ML_CONFIG.REDIRECT_URI)}&code_challenge=${codeChallenge}&code_challenge_method=S256`;
    return { url, code_verifier: codeVerifier };
  });

exports.mlExchangeToken = functions
  .runWith({ timeoutSeconds: 30, memory: "256MB" })
  .https.onCall(async (data, context) => {
    const { code, code_verifier } = data;
    if (!code) throw new functions.https.HttpsError("invalid-argument", "Code não informado.");
    if (!code_verifier) throw new functions.https.HttpsError("invalid-argument", "code_verifier não informado.");

    try {
      const fetch = (await import("node-fetch")).default;
      const response = await fetch(ML_CONFIG.TOKEN_URL, {
        method: "POST",
        headers: { "accept": "application/json", "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          client_id: ML_CONFIG.APP_ID,
          client_secret: ML_CONFIG.SECRET_KEY,
          code: code,
          redirect_uri: ML_CONFIG.REDIRECT_URI,
          code_verifier: code_verifier,
        }),
      });

      const tokenData = await response.json();
      if (tokenData.error) {
        console.error("[mlExchangeToken] Erro ML:", tokenData);
        throw new functions.https.HttpsError("unknown", `ML: ${tokenData.error} - ${tokenData.message}`);
      }

      await db.collection("config").doc("ml_tokens").set({
        access_token: tokenData.access_token,
        refresh_token: tokenData.refresh_token,
        token_type: tokenData.token_type,
        expires_in: tokenData.expires_in,
        user_id: tokenData.user_id,
        scope: tokenData.scope,
        obtido_em: new Date().toISOString(),
        expira_em: new Date(Date.now() + tokenData.expires_in * 1000).toISOString(),
      });

      console.log(`[mlExchangeToken] Token obtido! User ID: ${tokenData.user_id}`);
      return { success: true, user_id: tokenData.user_id };
    } catch (err) {
      if (err instanceof functions.https.HttpsError) throw err;
      console.error("[mlExchangeToken] Erro:", err);
      throw new functions.https.HttpsError("internal", err.message);
    }
  });

exports.mlCallback = functions
  .runWith({ timeoutSeconds: 10, memory: "128MB" })
  .https.onRequest(async (req, res) => {
    const code = req.query.code || "";
    res.redirect(`https://mbdj-financeiro.web.app/?ml_code=${encodeURIComponent(code)}`);
  });

async function getMLToken() {
  const doc = await db.collection("config").doc("ml_tokens").get();
  if (!doc.exists) throw new Error("ML não conectado. Faça a autorização primeiro.");

  const data = doc.data();
  const expiraEm = new Date(data.expira_em);

  if (expiraEm > new Date(Date.now() + 300000)) {
    return data.access_token;
  }

  console.log("[ML] Token expirado, renovando...");
  const fetch = (await import("node-fetch")).default;
  const response = await fetch(ML_CONFIG.TOKEN_URL, {
    method: "POST",
    headers: { "accept": "application/json", "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      client_id: ML_CONFIG.APP_ID,
      client_secret: ML_CONFIG.SECRET_KEY,
      refresh_token: data.refresh_token,
    }),
  });

  const tokenData = await response.json();
  if (tokenData.error) throw new Error(`Erro refresh ML: ${tokenData.error} - ${tokenData.message}`);

  await db.collection("config").doc("ml_tokens").set({
    access_token: tokenData.access_token,
    refresh_token: tokenData.refresh_token,
    token_type: tokenData.token_type,
    expires_in: tokenData.expires_in,
    user_id: tokenData.user_id,
    scope: tokenData.scope,
    obtido_em: new Date().toISOString(),
    expira_em: new Date(Date.now() + tokenData.expires_in * 1000).toISOString(),
  });

  console.log("[ML] Token renovado com sucesso.");
  return tokenData.access_token;
}

async function mlApiGet(endpoint) {
  const token = await getMLToken();
  const fetch = (await import("node-fetch")).default;
  const url = endpoint.startsWith("http") ? endpoint : `${ML_CONFIG.API_BASE}${endpoint}`;
  const response = await fetch(url, {
    headers: { "Authorization": `Bearer ${token}` },
  });
  if (!response.ok) {
    const err = await response.text();
    throw new Error(`ML API ${response.status}: ${err}`);
  }
  return response.json();
}

exports.mlSincronizarEstoque = functions
  .runWith({ timeoutSeconds: 120, memory: "512MB" })
  .https.onCall(async (data, context) => {
    const startTime = Date.now();

    try {
      const token = await getMLToken();
      const tokenDoc = await db.collection("config").doc("ml_tokens").get();
      const sellerId = tokenDoc.data().user_id;

      // 1. Buscar apenas itens ATIVOS
      let allItems = [];
      let offset = 0;
      let hasMore = true;

      while (hasMore) {
        const result = await mlApiGet(`/users/${sellerId}/items/search?status=active&offset=${offset}&limit=50`);
        allItems = allItems.concat(result.results || []);
        offset += 50;
        hasMore = offset < (result.paging ? result.paging.total : 0);
        if (hasMore) await sleep(200);
      }

      console.log(`[mlEstoque] ${allItems.length} itens ATIVOS encontrados`);

      const produtos = [];
      const skusSeen = new Set(); // Deduplicar variações com mesmo SKU
      const batchSize = 20;
      let debugCount = 0;

      for (let i = 0; i < allItems.length; i += batchSize) {
        const batch = allItems.slice(i, i + batchSize);
        const ids = batch.join(",");
        const itemsData = await mlApiGet(`/items?ids=${ids}`);

        for (const wrapper of itemsData) {
          if (wrapper.code !== 200 || !wrapper.body) continue;
          const item = wrapper.body;
          if (item.status !== "active") continue;

          function extractSku(obj, item) {
            if (obj.seller_custom_field) return obj.seller_custom_field;
            if (obj.attributes) {
              const skuAttr = obj.attributes.find(a => a.id === "SELLER_SKU");
              if (skuAttr && skuAttr.value_name) return skuAttr.value_name;
            }
            if (item && item.seller_custom_field) return item.seller_custom_field;
            return null;
          }

          // Processar variações ou item sem variação
          const variations = (item.variations && item.variations.length > 0) ? item.variations : [item];

          for (const v of variations) {
            const isVariation = v !== item;
            const invId = isVariation ? v.inventory_id : item.inventory_id;
            const sku = extractSku(isVariation ? v : item, item);

            // Pular se já processamos este SKU (variações compartilham inventory_id)
            if (sku && skusSeen.has(sku)) continue;
            if (sku) skusSeen.add(sku);

            // Buscar estoque Full
            let stockData = null;
            if (invId) {
              try {
                stockData = await mlApiGet(`/inventories/${invId}/stock/fulfillment`);
                // Debug: logar primeiros 3 responses
                if (debugCount < 3) {
                  console.log(`[mlEstoque] DEBUG fulfillment invId=${invId}: ${JSON.stringify(stockData).substring(0, 300)}`);
                  debugCount++;
                }
              } catch (e) {
                // Sem fulfillment — item pode não ser Full
              }
            }

            // Extrair quantidades do fulfillment
            let aptas = 0, emTransferencia = 0, entradaPendente = 0, naoAptas = 0, extraviadas = 0, emRevisao = 0;

            if (stockData) {
              aptas = stockData.available_quantity || 0;
              naoAptas = stockData.not_available_quantity || 0;

              // Breakdown de não-aptas
              if (stockData.not_available_detail && Array.isArray(stockData.not_available_detail)) {
                for (const d of stockData.not_available_detail) {
                  if (d.status === "transfer") emTransferencia += (d.quantity || 0);
                  else if (d.status === "pending" || d.status === "inbound") entradaPendente += (d.quantity || 0);
                  else if (d.status === "lost") extraviadas += (d.quantity || 0);
                  else if (d.status === "notSupported" || d.status === "damaged") emRevisao += (d.quantity || 0);
                }
              }
            }

            // Total = tudo no Full
            const totalFull = stockData ? (stockData.total || (aptas + naoAptas)) : aptas;

            const skuKey = sku || (invId || item.id);

            // Deduplicar por inventory_id (estoque físico único no Full)
            // Anúncio próprio + catálogo compartilham mesmo inventory_id
            const dedupKey = invId || item.id;
            if (skusSeen.has(dedupKey)) {
              console.log(`[mlEstoque] DEDUP: pular ${skuKey} (invId=${invId}, item=${item.id}) — já visto`);
              continue;
            }

            // Só adicionar se tem qualquer estoque
            if (totalFull > 0 || aptas > 0) {
              skusSeen.add(dedupKey);
              produtos.push({
                item_id: item.id,
                variation_id: isVariation ? v.id : null,
                titulo: item.title,
                sku: skuKey,
                preco: item.price,
                status: item.status,
                inventory_id: invId || "",
                full_aptas: aptas,
                full_transferencia: emTransferencia,
                full_entrada: entradaPendente,
                full_nao_aptas: naoAptas,
                full_extraviadas: extraviadas,
                full_em_revisao: emRevisao,
                full_total: totalFull,
              });
            }

            if (isVariation) await sleep(100);
          }
        }
        await sleep(300);
      }

      // Ordenar por aptas desc
      produtos.sort((a, b) => b.full_aptas - a.full_aptas);

      console.log(`[mlEstoque] ${produtos.length} SKUs com estoque:`);
      produtos.forEach(p => {
        console.log(`[mlEstoque]   ${p.sku}: aptas=${p.full_aptas} transf=${p.full_transferencia} naoAptas=${p.full_nao_aptas} total=${p.full_total} | ${p.titulo.substring(0, 45)}`);
      });

      await db.collection("config").doc("ml_estoque_sync").set({
        ultima_sincronizacao: new Date().toISOString(),
        total_itens: allItems.length, total_skus: produtos.length,
        duracao_seg: ((Date.now() - startTime) / 1000).toFixed(1),
      });

      const duracao = ((Date.now() - startTime) / 1000).toFixed(1);
      console.log(`[mlEstoque] Concluído em ${duracao}s: ${produtos.length} SKUs com estoque de ${allItems.length} itens ativos`);

      return {
        success: true, total_itens: allItems.length, total_skus: produtos.length,
        produtos, duracao,
      };
    } catch (err) {
      console.error("[mlEstoque] Erro:", err);
      return { success: false, error: err.message };
    }
  });

exports.mlStatus = functions
  .runWith({ timeoutSeconds: 10, memory: "128MB" })
  .https.onCall(async (data, context) => {
    const doc = await db.collection("config").doc("ml_tokens").get();
    if (!doc.exists) return { connected: false };

    const d = doc.data();
    const expirado = new Date(d.expira_em) < new Date();
    let userName = "";

    if (!expirado) {
      try {
        const user = await mlApiGet("/users/me");
        userName = user.nickname || user.first_name || "";
      } catch (e) { /* ignora */ }
    }

    const syncDoc = await db.collection("config").doc("ml_estoque_sync").get();
    const lastSync = syncDoc.exists ? syncDoc.data() : null;

    return {
      connected: true, user_id: d.user_id, user_name: userName,
      token_expira: d.expira_em, token_expirado: expirado,
      ultima_sincronizacao: lastSync ? lastSync.ultima_sincronizacao : null,
      total_skus_sync: lastSync ? lastSync.total_ativos : 0,
    };
  });

exports.mlWebhook = functions
  .runWith({ timeoutSeconds: 30, memory: "256MB" })
  .https.onRequest(async (req, res) => {
    if (req.method !== "POST") { res.status(200).send("OK"); return; }
    try {
      const notification = req.body;
      console.log("[mlWebhook] Notificação:", JSON.stringify(notification));
      await db.collection("ml_notifications").add({
        ...notification, received_at: new Date().toISOString(), processed: false,
      });
      res.status(200).send("OK");
    } catch (err) {
      console.error("[mlWebhook] Erro:", err);
      res.status(200).send("OK");
    }
  });

// ══════════════════════════════════════════════════════════
//  MERCADO PAGO — SALDO + LANÇAMENTOS FUTUROS (v2)
// ══════════════════════════════════════════════════════════

/**
 * mpSincronizar v2 — Usa payments/search com net_received_amount
 * 
 * Em vez de calcular líquido manualmente, usa o campo net_received_amount
 * que é o valor exato que o MP libera na conta do seller.
 * 
 * Endpoint: GET /v1/payments/search?range=money_release_date&begin_date=NOW&end_date=NOW+30DAYS
 * Cada payment retorna: money_release_date, net_received_amount, transaction_amount
 */
exports.mpSincronizar = functions
  .runWith({ timeoutSeconds: 120, memory: "512MB" })
  .https.onCall(async (data, context) => {
    const startTime = Date.now();

    try {
      const token = await getMLToken();
      const tokenDoc = await db.collection("config").doc("ml_tokens").get();
      const sellerId = tokenDoc.data().user_id;
      const fetch = (await import("node-fetch")).default;

      console.log(`[mpSync v2] Iniciado para seller ${sellerId}`);

      // Saldo não disponível via API OAuth do ML (403). Gerenciado manualmente em Contas Bancárias.

      // ── 2. BUSCAR PAYMENTS POR DATA DE LIBERAÇÃO (AGORA a D+35) ──
      // begin_date = agora (não meia-noite). Liberações anteriores à hora atual já estão no saldo.
      // Ex: sync às 9:48 → pega 10h, 11h, ..., 21h de hoje + dias futuros
      const hoje = new Date();
      // Horário Brasil (UTC-3)
      const brNow = new Date(hoje.getTime() - 3 * 60 * 60 * 1000);
      const hojeStr = brNow.toISOString().split("T")[0];
      const brHora = brNow.toISOString().split("T")[1].substring(0, 8); // HH:MM:SS
      const ate35 = new Date(brNow);
      ate35.setDate(ate35.getDate() + 35);
      const beginDate = hojeStr + "T" + brHora + ".000-03:00";
      const endDate = ate35.toISOString().split("T")[0] + "T23:59:59.000-03:00";

      console.log(`[mpSync v2] Buscando payments de ${beginDate} até ${endDate} (AGORA BR a D+35)`);

      let allPayments = [];
      let offset = 0;
      let hasMore = true;

      while (hasMore && offset < 2000) {
        const url = `https://api.mercadopago.com/v1/payments/search?` +
          `sort=money_release_date&criteria=asc` +
          `&range=money_release_date` +
          `&begin_date=${encodeURIComponent(beginDate)}` +
          `&end_date=${encodeURIComponent(endDate)}` +
          `&status=approved` +
          `&offset=${offset}&limit=50`;

        try {
          const res = await fetch(url, {
            headers: { "Authorization": `Bearer ${token}` },
          });

          if (!res.ok) {
            const errText = await res.text();
            console.warn(`[mpSync v2] Payments search ${res.status} offset ${offset}: ${errText.substring(0, 200)}`);
            break;
          }

          const pmtData = await res.json();
          const results = pmtData.results || [];
          allPayments = allPayments.concat(results);
          offset += 50;
          hasMore = offset < (pmtData.paging ? pmtData.paging.total : 0);
          if (hasMore) await sleep(300);
        } catch (e) {
          console.warn(`[mpSync v2] Erro payments offset ${offset}:`, e.message);
          break;
        }
      }

      console.log(`[mpSync v2] ${allPayments.length} payments encontrados`);

      // Debug: logar estrutura do primeiro payment pra identificar campos
      if (allPayments.length > 0) {
        const sample = allPayments[0];
        console.log(`[mpSync v2] SAMPLE payment id=${sample.id}: transaction_amount=${sample.transaction_amount}, net_received_amount=${sample.net_received_amount}, td.net=${sample.transaction_details ? sample.transaction_details.net_received_amount : 'N/A'}, money_release_date=${sample.money_release_date}, money_release_status=${sample.money_release_status}, status=${sample.status}`);
        console.log(`[mpSync v2] SAMPLE fee_details: ${JSON.stringify(sample.fee_details || [])}`);
        console.log(`[mpSync v2] SAMPLE transaction_details: ${JSON.stringify(sample.transaction_details || {})}`);
      }

      // ── 3. AGRUPAR POR DATA DE LIBERAÇÃO ──
      // Apenas payments PENDENTES de liberação (não os já liberados)
      const paymentMap = {};
      let totalAReceber = 0;
      let skippedReleased = 0;
      let skippedNegative = 0;

      for (const pmt of allPayments) {
        const releaseDate = pmt.money_release_date;
        if (!releaseDate) continue;

        // Pular payments já liberados — só queremos os futuros
        if (pmt.money_release_status === "released") {
          skippedReleased++;
          continue;
        }

        const relDateStr = releaseDate.substring(0, 10);
        const relHora = releaseDate.substring(11, 16) || "";

        // net_received_amount está em transaction_details
        const tdNet = pmt.transaction_details ? (pmt.transaction_details.net_received_amount || 0) : 0;
        const directNet = pmt.net_received_amount || 0;
        const netAmount = tdNet || directNet || 0;
        const grossAmount = pmt.transaction_amount || 0;
        const taxas = grossAmount - netAmount;

        // Apenas recebíveis positivos — "a pagar" será tratado no Contas a Pagar
        if (netAmount <= 0) {
          skippedNegative++;
          continue;
        }

        totalAReceber += netAmount;

        if (!paymentMap[relDateStr]) {
          paymentMap[relDateStr] = { total: 0, bruto: 0, taxas: 0, lancamentos: [] };
        }
        paymentMap[relDateStr].total += netAmount;
        paymentMap[relDateStr].bruto += grossAmount;
        paymentMap[relDateStr].taxas += taxas;

        // Guardar até 10 lançamentos por dia (pra não estourar o payload)
        if (paymentMap[relDateStr].lancamentos.length < 10) {
          paymentMap[relDateStr].lancamentos.push({
            payment_id: pmt.id,
            descricao: pmt.description || "Liberação de dinheiro",
            bruto: grossAmount,
            liquido: netAmount,
            taxas: taxas,
            hora: relHora,
          });
        }
      }

      // ── 4. MONTAR CALENDÁRIO ORDENADO ──
      const calendario = Object.keys(paymentMap)
        .sort()
        .map(dt => ({
          data: dt,
          total: paymentMap[dt].total,
          bruto: paymentMap[dt].bruto,
          taxas: paymentMap[dt].taxas,
          qtd_lancamentos: paymentMap[dt].lancamentos.length,
          lancamentos: paymentMap[dt].lancamentos,
        }));

      const calendarioFuturo = calendario.filter(d => d.data >= hojeStr);
      const calendarioPassado = calendario.filter(d => d.data < hojeStr);

      // ── 5. SALVAR NO FIRESTORE ──
      await db.collection("config").doc("mp_sync").set({
        ultima_sincronizacao: new Date().toISOString(),
        total_a_receber: totalAReceber,
        total_pagamentos: allPayments.length,
        payments_pendentes: allPayments.length - skippedReleased - skippedNegative,
      });

      await db.collection("config").doc("mp_calendario").set({
        atualizado_em: new Date().toISOString(),
        calendario: JSON.stringify(calendario),
      });

      const duracao = ((Date.now() - startTime) / 1000).toFixed(1);
      console.log(`[mpSync v2] Concluido em ${duracao}s: ${allPayments.length} payments total, ${skippedReleased} já liberados, ${skippedNegative} negativos, ${calendarioFuturo.length} dias futuros, total a receber: ${totalAReceber.toFixed(2)}`);

      return {
        success: true,
        duracao,
        resumo: {
          total_a_receber: totalAReceber,
          total_pagamentos: allPayments.length - skippedReleased - skippedNegative,
        },
        calendario_futuro: calendarioFuturo.slice(0, 60),
      };
    } catch (err) {
      console.error("[mpSync v2] Erro:", err);
      return { success: false, error: err.message };
    }
  });

// ══════════════════════════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════════════════════════
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function formatCurrencyBR(n) { return "R$ " + n.toFixed(2).replace(".", ",").replace(/\B(?=(\d{3})+(?!\d))/g, "."); }
