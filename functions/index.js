/**
 * MBDJ — Cloud Function: Consulta NF-e via SEFAZ Distribuição de DF-e
 * 
 * Usa o serviço NFeDistribuicaoDFe (Ambiente Nacional) para buscar
 * todas as NF-e destinadas ao CNPJ da empresa.
 * 
 * Requer: Certificado digital e-CNPJ A1 (.pfx) armazenado no Firebase Secret Manager.
 */
const functions = require("firebase-functions");
const admin = require("firebase-admin");
const https = require("https");
const zlib = require("zlib");
const { DOMParser } = require("@xmldom/xmldom");

admin.initializeApp();
const db = admin.firestore();

// ══════════════════════════════════════════════════════════
//  CONFIGURAÇÃO — ajustar conforme sua empresa
// ══════════════════════════════════════════════════════════
const CONFIG = {
  CNPJ: "44578505000103",           // CNPJ da MBDJ (sem pontuação)
  UF_CODIGO: "35",                   // 35 = São Paulo
  AMBIENTE: "1",                     // 1 = Produção, 2 = Homologação
  // Endpoints SEFAZ Ambiente Nacional
  URL_PROD: "https://www1.nfe.fazenda.gov.br/NFeDistribuicaoDFe/NFeDistribuicaoDFe.asmx",
  URL_HOMOLOG: "https://hom1.nfe.fazenda.gov.br/NFeDistribuicaoDFe/NFeDistribuicaoDFe.asmx",
};

// ══════════════════════════════════════════════════════════
//  SOAP ENVELOPE — Consulta por NSU (número sequencial único)
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
          <tpAmb>\${ambiente}</tpAmb>
          <cUFAutor>\${uf}</cUFAutor>
          <CNPJ>\${cnpj}</CNPJ>
          <distNSU>
            <ultNSU>\${nsu}</ultNSU>
          </distNSU>
        </distDFeInt>
      </nfeDadosMsg>
    </nfeDistDFeInteresse>
  </soap12:Body>
</soap12:Envelope>`;
}

// Consulta por chave de acesso específica
function buildSoapConsChNFe(chaveNFe, cnpj, uf, ambiente) {
  return `<?xml version="1.0" encoding="utf-8"?>
<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
  <soap12:Body>
    <nfeDistDFeInteresse xmlns="http://www.portalfiscal.inf.br/nfe/wsdl/NFeDistribuicaoDFe">
      <nfeDadosMsg>
        <distDFeInt xmlns="http://www.portalfiscal.inf.br/nfe" versao="1.01">
          <tpAmb>\${ambiente}</tpAmb>
          <cUFAutor>\${uf}</cUFAutor>
          <CNPJ>\${cnpj}</CNPJ>
          <consChNFe>
            <chNFe>\${chaveNFe}</chNFe>
          </consChNFe>
        </distDFeInt>
      </nfeDadosMsg>
    </nfeDistDFeInteresse>
  </soap12:Body>
</soap12:Envelope>`;
}

// ══════════════════════════════════════════════════════════
//  CHAMADA SOAP COM CERTIFICADO A1
// ══════════════════════════════════════════════════════════
async function callSefaz(soapBody) {
  // Carregar certificado do Secret Manager do Firebase
  const certPfx = await loadCertificate();
  const certPass = await loadCertificatePassword();

  const url = CONFIG.AMBIENTE === "1" ? CONFIG.URL_PROD : CONFIG.URL_HOMOLOG;
  const parsedUrl = new URL(url);

  const options = {
    hostname: parsedUrl.hostname,
    port: 443,
    path: parsedUrl.pathname,
    method: "POST",
    headers: {
      "Content-Type": "application/soap+xml; charset=utf-8",
      "Content-Length": Buffer.byteLength(soapBody, "utf-8"),
    },
    pfx: certPfx,
    passphrase: certPass,
    rejectUnauthorized: true,
  };

  return new Promise((resolve, reject) => {
    const req = https.request(options, (res) => {
      let data = [];
      res.on("data", (chunk) => data.push(chunk));
      res.on("end", () => {
        const body = Buffer.concat(data).toString("utf-8");
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(body);
        } else {
          reject(new Error(`SEFAZ HTTP \${res.statusCode}: \${body.substring(0, 500)}`));
        }
      });
    });
    req.on("error", (e) => reject(new Error(`SEFAZ Connection Error: \${e.message}`)));
    req.setTimeout(30000, () => { req.destroy(); reject(new Error("SEFAZ Timeout (30s)")); });
    req.write(soapBody);
    req.end();
  });
}

// ══════════════════════════════════════════════════════════
//  CERTIFICADO A1 — carregamento seguro
// ══════════════════════════════════════════════════════════
// O certificado .pfx deve ser armazenado como Secret no Firebase.
// Alternativa: armazenar como base64 no Firestore collection "config".

async function loadCertificate() {
  // Opção 1: Firebase Secret Manager (recomendado para produção)
  // const secret = functions.config().sefaz?.cert_pfx_base64;

  // Opção 2: Firestore (mais fácil de configurar)
  const doc = await db.collection("config").doc("sefaz_cert").get();
  if (!doc.exists || !doc.data().pfx_base64) {
    throw new Error("Certificado A1 não encontrado. Faça upload em Configurações > SEFAZ.");
  }
  return Buffer.from(doc.data().pfx_base64, "base64");
}

async function loadCertificatePassword() {
  // Opção 1: Firebase Secret Manager
  // return functions.config().sefaz?.cert_password;

  // Opção 2: Firestore
  const doc = await db.collection("config").doc("sefaz_cert").get();
  if (!doc.exists || !doc.data().password) {
    throw new Error("Senha do certificado não encontrada.");
  }
  return doc.data().password;
}

// ══════════════════════════════════════════════════════════
//  PARSER — processa resposta SOAP da SEFAZ
// ══════════════════════════════════════════════════════════
function parseSefazResponse(xmlResponse) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlResponse, "text/xml");

  // Extrair retDistDFeInt
  const retNode = doc.getElementsByTagNameNS("http://www.portalfiscal.inf.br/nfe", "retDistDFeInt");
  if (!retNode || retNode.length === 0) {
    throw new Error("Resposta SEFAZ inválida: retDistDFeInt não encontrado");
  }

  const ret = retNode[0];
  const cStat = getTagText(ret, "cStat");
  const xMotivo = getTagText(ret, "xMotivo");
  const ultNSU = getTagText(ret, "ultNSU");
  const maxNSU = getTagText(ret, "maxNSU");

  // cStat 137 = Nenhum documento localizado
  // cStat 138 = Documentos localizados
  const result = {
    cStat,
    xMotivo,
    ultNSU: ultNSU || "0",
    maxNSU: maxNSU || "0",
    documentos: [],
  };

  if (cStat !== "138") {
    return result;
  }

  // Extrair docZip (documentos comprimidos em gzip + base64)
  const docZips = ret.getElementsByTagNameNS("http://www.portalfiscal.inf.br/nfe", "docZip");
  for (let i = 0; i < docZips.length; i++) {
    const docZip = docZips[i];
    const nsu = docZip.getAttribute("NSU") || "";
    const schema = docZip.getAttribute("schema") || "";
    const base64Content = docZip.textContent || "";

    try {
      // Descomprimir gzip
      const compressed = Buffer.from(base64Content, "base64");
      // Tentar gunzip (padrão SEFAZ DFe), depois inflate, depois inflateRaw
                let xmlContent;
                try { xmlContent = zlib.gunzipSync(compressed).toString("utf-8"); }
                catch (_e1) {
                              try { xmlContent = zlib.inflateSync(compressed).toString("utf-8"); }
                              catch (_e2) { xmlContent = zlib.inflateRawSync(compressed).toString("utf-8"); }
                }

      // Parsear o XML do documento
      const nfeData = parseNFeXMLContent(xmlContent, schema);
      if (nfeData) {
        nfeData._nsu = nsu;
        nfeData._schema = schema;
        result.documentos.push(nfeData);
      }
    } catch (e) {
      console.warn(`Erro ao descomprimir docZip NSU \${nsu}:`, e.message);
    }
  }

  return result;
}

function parseNFeXMLContent(xmlContent, schema) {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlContent, "text/xml");
  const ns = "http://www.portalfiscal.inf.br/nfe";

  // Pode ser: nfeProc (NF-e completa), resNFe (resumo), resEvento (evento)
  const isResumo = schema.includes("resNFe") || doc.getElementsByTagNameNS(ns, "resNFe").length > 0;
  const isEvento = schema.includes("resEvento") || doc.getElementsByTagNameNS(ns, "resEvento").length > 0;
  const isNFeCompleta = doc.getElementsByTagNameNS(ns, "nfeProc").length > 0 || doc.getElementsByTagNameNS(ns, "NFe").length > 0;

  if (isResumo) {
    // Resumo da NF-e — dados básicos
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
      situacao: getTagTextNS(resNFe, ns, "cSitNFe"), // 1=autorizada, 2=uso denegado, 3=cancelada
      xmlOriginal: xmlContent,
    };
  }

  if (isEvento) {
    // Evento (cancelamento, carta correção, etc.)
    return {
      tipo: "evento",
      xmlOriginal: xmlContent,
    };
  }

  if (isNFeCompleta) {
    // NF-e completa — extrair tudo
    return parseNFeCompleta(doc, ns, xmlContent);
  }

  return null;
}

function parseNFeCompleta(doc, ns, xmlOriginal) {
  const infNFe = doc.getElementsByTagNameNS(ns, "infNFe");
  if (infNFe.length === 0) return null;

  const inf = infNFe[0];
  const chaveId = inf.getAttribute("Id") || "";
  const chave = chaveId.replace(/^NFe/, "");

  // ide
  const ide = inf.getElementsByTagNameNS(ns, "ide");
  let numero = "", serie = "", emissao = "", natOp = "";
  if (ide.length > 0) {
    numero = getTagTextNS(ide[0], ns, "nNF");
    serie = getTagTextNS(ide[0], ns, "serie");
    const dhEmi = getTagTextNS(ide[0], ns, "dhEmi") || getTagTextNS(ide[0], ns, "dEmi");
    emissao = dhEmi ? dhEmi.substring(0, 10) : "";
    natOp = getTagTextNS(ide[0], ns, "natOp");
  }

  // emit
  const emit = inf.getElementsByTagNameNS(ns, "emit");
  let fornNome = "", fornCNPJ = "";
  if (emit.length > 0) {
    fornNome = getTagTextNS(emit[0], ns, "xFant") || getTagTextNS(emit[0], ns, "xNome");
    fornCNPJ = getTagTextNS(emit[0], ns, "CNPJ") || getTagTextNS(emit[0], ns, "CPF");
  }

  // Formatar CNPJ
  if (fornCNPJ && fornCNPJ.length === 14) {
    fornCNPJ = fornCNPJ.replace(/^(\d{2})(\d{3})(\d{3})(\d{4})(\d{2})$/, "$1.$2.$3/$4-$5");
  }

  // total
  const icmsTot = inf.getElementsByTagNameNS(ns, "ICMSTot");
  let valorTotal = "0";
  if (icmsTot.length > 0) {
    valorTotal = getTagTextNS(icmsTot[0], ns, "vNF");
  }

  // produtos
  const dets = inf.getElementsByTagNameNS(ns, "det");
  const produtos = [];
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
  }

  // duplicatas
  const dups = inf.getElementsByTagNameNS(ns, "dup");
  const duplicatas = [];
  for (let dd = 0; dd < dups.length; dd++) {
    duplicatas.push({
      nDup: getTagTextNS(dups[dd], ns, "nDup"),
      dVenc: getTagTextNS(dups[dd], ns, "dVenc"),
      vDup: getTagTextNS(dups[dd], ns, "vDup"),
    });
  }

  return {
    tipo: "nfe_completa",
    numero, serie, emissao, fornecedor: fornNome, cnpj: fornCNPJ,
    valor: valorTotal, chave, natOp, produtos, duplicatas,
    xmlOriginal,
  };
}

// Helpers XML
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
//  Chamada pelo frontend via HTTP
// ══════════════════════════════════════════════════════════
exports.sincronizarSefaz = functions
  .runWith({ timeoutSeconds: 120, memory: "512MB" })
  .https.onCall(async (data, context) => {
    // Verificar autenticação
    if (!context.auth) {
      throw new functions.https.HttpsError("unauthenticated", "Usuário não autenticado.");
    }

    console.log(`[sincronizarSefaz] Iniciado por \${context.auth.uid}`);

    try {
      // Carregar último NSU processado
      const configDoc = await db.collection("config").doc("sefaz_sync").get();
      let ultNSU = configDoc.exists ? (configDoc.data().ultNSU || "0") : "0";

      console.log(`[sincronizarSefaz] Último NSU: \${ultNSU}`);

      let totalDocs = 0;
      let totalNFe = 0;
      let totalResumos = 0;
      let iterations = 0;
      const maxIterations = 10; // Segurança: máximo 10 chamadas por execução
      let hasMore = true;

      while (hasMore && iterations < maxIterations) {
        iterations++;
        console.log(`[sincronizarSefaz] Iteração \${iterations}, NSU: \${ultNSU}`);

        // Montar e enviar SOAP
        const soapBody = buildSoapDistNSU(ultNSU, CONFIG.CNPJ, CONFIG.UF_CODIGO, CONFIG.AMBIENTE);
        const response = await callSefaz(soapBody);

        // Parsear resposta
        const result = parseSefazResponse(response);
        console.log(`[sincronizarSefaz] cStat=\${result.cStat} | \${result.xMotivo} | \${result.documentos.length} docs | ultNSU=\${result.ultNSU} maxNSU=\${result.maxNSU}`);

        if (result.cStat === "137") {
          // Nenhum documento novo
          hasMore = false;
          break;
        }

        if (result.cStat !== "138") {
          throw new Error(`SEFAZ retornou \${result.cStat}: \${result.xMotivo}`);
        }

        // Processar documentos
        for (const doc of result.documentos) {
          totalDocs++;

          if (doc.tipo === "nfe_completa") {
            // Salvar NF-e completa no Firestore
            await salvarNFeNoFirestore(doc);
            totalNFe++;
          } else if (doc.tipo === "resumo") {
            // Resumo: se situação = autorizada, buscar NF-e completa por chave
            if (doc.situacao === "1" && doc.chave) {
              try {
                const soapChave = buildSoapConsChNFe(doc.chave, CONFIG.CNPJ, CONFIG.UF_CODIGO, CONFIG.AMBIENTE);
                const resChave = await callSefaz(soapChave);
                const resultChave = parseSefazResponse(resChave);
                for (const d of resultChave.documentos) {
                  if (d.tipo === "nfe_completa") {
                    await salvarNFeNoFirestore(d);
                    totalNFe++;
                  }
                }
              } catch (e) {
                console.warn(`Erro ao buscar NF-e chave \${doc.chave}:`, e.message);
                // Salvar resumo mesmo assim
                await salvarResumoNoFirestore(doc);
              }
              totalResumos++;
            }
          }
          // Eventos são logados mas não processados por enquanto
        }

        // Atualizar NSU
        ultNSU = result.ultNSU;
        hasMore = parseInt(result.ultNSU) < parseInt(result.maxNSU);

        // Rate limit: aguardar 1s entre chamadas (respeitar SEFAZ)
        if (hasMore) await sleep(1000);
      }

      // Salvar último NSU processado
      await db.collection("config").doc("sefaz_sync").set({
        ultNSU: ultNSU,
        ultimaSincronizacao: new Date().toISOString(),
        totalDocsSincronizados: totalDocs,
      }, { merge: true });

      const resultado = {
        success: true,
        ultNSU,
        totalDocs,
        totalNFe,
        totalResumos,
        iteracoes: iterations,
        hasMore,
        msg: totalNFe > 0
          ? `✅ \${totalNFe} NF-e(s) importada(s) da SEFAZ!`
          : "Nenhuma NF-e nova encontrada.",
      };

      console.log(`[sincronizarSefaz] Concluído:`, resultado);
      return resultado;

    } catch (error) {
      console.error("[sincronizarSefaz] ERRO:", error);
      throw new functions.https.HttpsError("internal", error.message);
    }
  });

// ══════════════════════════════════════════════════════════
//  SALVAR NF-e NO FIRESTORE (compatível com o frontend)
// ══════════════════════════════════════════════════════════
async function salvarNFeNoFirestore(nfe) {
  // Verificar duplicata por chave de acesso
  const existing = await db.collection("dados").doc("notas_fiscais").get();
  let nfeItems = [];

  if (existing.exists) {
    const data = existing.data();
    if (data._chunked) {
      // Dados chunked — carregar todos os chunks
      const chunks = await db.collection("dados")
        .where("_parentKey", "==", "notas_fiscais")
        .orderBy("_chunkIndex")
        .get();
      chunks.forEach(c => {
        try { nfeItems = nfeItems.concat(JSON.parse(c.data().valor)); } catch (e) { }
      });
    } else if (data.valor) {
      try { nfeItems = JSON.parse(data.valor); } catch (e) { nfeItems = []; }
    }
  }

  // Verificar se já existe
  if (nfe.chave && nfeItems.some(n => n.chave === nfe.chave)) {
    console.log(`[salvarNFe] NF-e \${nfe.numero} (chave \${nfe.chave.substring(0, 15)}...) já existe, pulando.`);
    return;
  }

  // Adicionar no formato compatível com o frontend
  nfeItems.push({
    numero: nfe.numero,
    serie: nfe.serie,
    emissao: nfe.emissao,
    fornecedor: nfe.fornecedor,
    cnpj: nfe.cnpj,
    valor: formatCurrencyBR(parseFloat(nfe.valor) || 0),
    chave: nfe.chave,
    status: "Processada",
    natOp: nfe.natOp,
    produtos: nfe.produtos || [],
    duplicatas: nfe.duplicatas || [],
    origem: "sefaz_auto",
    _importadoEm: new Date().toISOString(),
  });

  // Salvar usando a mesma lógica de chunking do frontend
  const jsonVal = JSON.stringify(nfeItems);
  const CHUNK_THRESHOLD = 800000;
  const CHUNK_TARGET = 500000;

  if (jsonVal.length < CHUNK_THRESHOLD) {
    await db.collection("dados").doc("notas_fiscais").set({
      valor: jsonVal,
      atualizado_em: new Date().toISOString(),
    });
  } else {
    // Auto-chunking
    const chunks = [];
    let currentChunk = [], currentSize = 0;

    for (const item of nfeItems) {
      const itemJson = JSON.stringify(item);
      if (currentSize + itemJson.length > CHUNK_TARGET && currentChunk.length > 0) {
        chunks.push(currentChunk);
        currentChunk = [];
        currentSize = 0;
      }
      currentChunk.push(item);
      currentSize += itemJson.length;
    }
    if (currentChunk.length > 0) chunks.push(currentChunk);

    // Limpar chunks antigos
    const oldChunks = await db.collection("dados")
      .where("_parentKey", "==", "notas_fiscais").get();
    const batch = db.batch();
    oldChunks.forEach(d => batch.delete(d.ref));
    await batch.commit();

    // Salvar manifesto
    await db.collection("dados").doc("notas_fiscais").set({
      _chunked: true,
      _totalChunks: chunks.length,
      _totalItems: nfeItems.length,
      atualizado_em: new Date().toISOString(),
    });

    // Salvar chunks
    for (let i = 0; i < chunks.length; i++) {
      await db.collection("dados").doc(`notas_fiscais__chunk_\${i}`).set({
        valor: JSON.stringify(chunks[i]),
        _parentKey: "notas_fiscais",
        _chunkIndex: i,
        atualizado_em: new Date().toISOString(),
      });
    }
  }

  console.log(`[salvarNFe] NF-e \${nfe.numero} salva (total: \${nfeItems.length})`);
}

async function salvarResumoNoFirestore(resumo) {
  // Salvar resumos em coleção separada para referência
  if (resumo.chave) {
    await db.collection("sefaz_resumos").doc(resumo.chave).set({
      ...resumo,
      xmlOriginal: undefined, // Não salvar XML do resumo
      _importadoEm: new Date().toISOString(),
    });
  }
}

// ══════════════════════════════════════════════════════════
//  CLOUD FUNCTION: uploadCertificado
//  Recebe o .pfx em base64 e armazena no Firestore
// ══════════════════════════════════════════════════════════
exports.uploadCertificado = functions
  .runWith({ timeoutSeconds: 30, memory: "256MB" })
  .https.onCall(async (data, context) => {
    if (!context.auth) {
      throw new functions.https.HttpsError("unauthenticated", "Não autenticado.");
    }

    const { pfxBase64, password } = data;
    if (!pfxBase64 || !password) {
      throw new functions.https.HttpsError("invalid-argument", "Certificado e senha são obrigatórios.");
    }

    // Validar que o PFX é válido
    try {
      const crypto = require("crypto");
      // Tentar decodificar para validar
      const pfxBuffer = Buffer.from(pfxBase64, "base64");
      // Básico: verificar que tem tamanho razoável
      if (pfxBuffer.length < 100) throw new Error("Arquivo muito pequeno");
      if (pfxBuffer.length > 50000) throw new Error("Arquivo muito grande (max 50KB)");
    } catch (e) {
      throw new functions.https.HttpsError("invalid-argument", `Certificado inválido: \${e.message}`);
    }

    // Salvar no Firestore
    await db.collection("config").doc("sefaz_cert").set({
      pfx_base64: pfxBase64,
      password: password,
      uploadedAt: new Date().toISOString(),
      uploadedBy: context.auth.uid,
    });

    return { success: true, msg: "Certificado A1 salvo com sucesso!" };
  });

// ══════════════════════════════════════════════════════════
//  CLOUD FUNCTION: statusSefaz
//  Retorna status da configuração (certificado, último sync, etc.)
// ══════════════════════════════════════════════════════════
exports.statusSefaz = functions
  .https.onCall(async (data, context) => {
    if (!context.auth) {
      throw new functions.https.HttpsError("unauthenticated", "Não autenticado.");
    }

    const certDoc = await db.collection("config").doc("sefaz_cert").get();
    const syncDoc = await db.collection("config").doc("sefaz_sync").get();

    return {
      certificadoConfigurado: certDoc.exists && !!certDoc.data().pfx_base64,
      certificadoUploadedAt: certDoc.exists ? certDoc.data().uploadedAt : null,
      ultimaSincronizacao: syncDoc.exists ? syncDoc.data().ultimaSincronizacao : null,
      ultNSU: syncDoc.exists ? syncDoc.data().ultNSU : "0",
      cnpj: CONFIG.CNPJ,
      ambiente: CONFIG.AMBIENTE === "1" ? "Produção" : "Homologação",
    };
  });

// ══════════════════════════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════════════════════════
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function formatCurrencyBR(n) {
  return "R$ " + n.toFixed(2).replace(".", ",").replace(/\B(?=(\d{3})+(?!\d))/g, ".");
}
