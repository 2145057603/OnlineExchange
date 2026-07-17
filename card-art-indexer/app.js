"use strict";

const PCK_MAGIC = 0x43504447;
const PCK_BASE_OFFSET = 0x70;
const MAX_FILE_SIZE = 768 * 1024 * 1024;
const MAX_JSON_FILES = 96;
const MAX_JSON_BYTES = 1024 * 1024;
const MAX_RESOURCE_TREE_ENTRIES = 6000;
const decoder = new TextDecoder("utf-8", { fatal: false });
const semanticTokens = [
  "cardart", "cardimage", "cardillustration", "cardportrait", "cardskin",
  "portrait", "illustration", "artwork", "replacement",
  "\u5361\u9762", "\u5361\u56fe", "\u5361\u724c\u56fe\u7247", "\u5361\u724c\u63d2\u753b", "\u63d2\u753b", "\u8096\u50cf", "\u7acb\u7ed8", "\u76ae\u80a4", "\u66ff\u6362",
  "\u30ab\u30fc\u30c9\u30a2\u30fc\u30c8", "\u30ab\u30fc\u30c9\u753b\u50cf", "\u30ab\u30fc\u30c9\u30a4\u30e9\u30b9\u30c8", "\u30a4\u30e9\u30b9\u30c8", "\u7acb\u3061\u7d75", "\u5dee\u3057\u66ff\u3048",
  "\uce74\ub4dc\uc544\ud2b8", "\uce74\ub4dc\uc774\ubbf8\uc9c0", "\uce74\ub4dc\uc77c\ub7ec\uc2a4\ud2b8", "\uc77c\ub7ec\uc2a4\ud2b8", "\ucd08\uc0c1\ud654", "\uc2a4\ud0a8", "\uad50\uccb4",
  "ilustracion", "ilustraci\u00f3n", "ilustracao", "ilustra\u00e7\u00e3o", "retrato", "\u0438\u043b\u043b\u044e\u0441\u0442\u0440\u0430\u0446\u0438\u044f", "\u043f\u043e\u0440\u0442\u0440\u0435\u0442"
];

const elements = {
  input: document.querySelector("#pckInput"),
  folderInput: document.querySelector("#folderInput"),
  dropZone: document.querySelector("#dropZone"),
  status: document.querySelector("#status"),
  modId: document.querySelector("#modId"),
  modVersion: document.querySelector("#modVersion"),
  summary: document.querySelector("#summaryPanel"),
  mappings: document.querySelector("#mappingPanel"),
  resources: document.querySelector("#resourcePanel"),
  diagnostics: document.querySelector("#diagnosticPanel"),
  fileTitle: document.querySelector("#fileTitle"),
  hashBadge: document.querySelector("#hashBadge"),
  metrics: document.querySelector("#metrics"),
  mappingCount: document.querySelector("#mappingCount"),
  mappingRows: document.querySelector("#mappingRows"),
  emptyMappings: document.querySelector("#emptyMappings"),
  resourceCount: document.querySelector("#resourceCount"),
  resourceFilter: document.querySelector("#resourceFilter"),
  resourceHint: document.querySelector("#resourceHint"),
  resourceTree: document.querySelector("#resourceTree"),
  diagnosticList: document.querySelector("#diagnostics"),
  download: document.querySelector("#downloadButton"),
  copy: document.querySelector("#copyButton")
};

let currentResult = null;

elements.input.addEventListener("change", () => loadSelectedFile(elements.input.files[0]));
elements.folderInput.addEventListener("change", () => loadModFolder(elements.folderInput.files));
["dragenter", "dragover"].forEach((eventName) => elements.dropZone.addEventListener(eventName, (event) => {
  event.preventDefault();
  elements.dropZone.classList.add("is-dragging");
}));
["dragleave", "drop"].forEach((eventName) => elements.dropZone.addEventListener(eventName, (event) => {
  event.preventDefault();
  elements.dropZone.classList.remove("is-dragging");
}));
elements.dropZone.addEventListener("drop", (event) => loadSelectedFile(event.dataTransfer.files[0]));
elements.modId.addEventListener("input", renderResult);
elements.modVersion.addEventListener("input", renderResult);
elements.resourceFilter.addEventListener("input", renderResourceTree);
elements.download.addEventListener("click", downloadIndex);
elements.copy.addEventListener("click", copyIndex);

async function loadModFolder(fileList) {
  const files = [...fileList];
  if (files.length === 0) return;
  const manifestFile = files.find((file) => file.name.toLowerCase() === "mod_manifest.json");
  let manifest = null;
  if (manifestFile) {
    try { manifest = JSON.parse(await manifestFile.text()); }
    catch { setStatus("已找到 mod_manifest.json，但文件不是有效 JSON；仍会继续分析 PCK。", true); }
  }
  const pckFiles = files.filter((file) => file.name.toLowerCase().endsWith(".pck"));
  const expectedPckName = manifest?.id ? `${manifest.id}.pck`.toLowerCase() : "";
  const pckFile = pckFiles.find((file) => file.name.toLowerCase() === expectedPckName) || pckFiles[0];
  if (!pckFile) {
    setStatus("所选文件夹中没有找到 .pck 文件。", true);
    return;
  }
  if (manifest?.id) elements.modId.value = String(manifest.id);
  if (manifest?.version) elements.modVersion.value = String(manifest.version);
  const expectedDllName = manifest?.id ? `${manifest.id}.dll`.toLowerCase() : "";
  const dllFile = files.find((file) => file.name.toLowerCase() === expectedDllName)
    || files.find((file) => file.name.toLowerCase().endsWith(".dll"));
  await loadSelectedFile(pckFile, dllFile || null);
}

async function loadSelectedFile(file, dllFile = null) {
  if (!file) return;
  if (!file.name.toLowerCase().endsWith(".pck")) {
    setStatus("请选择 .pck 文件。", true);
    return;
  }
  if (file.size > MAX_FILE_SIZE) {
    setStatus("文件超过 768 MiB 的浏览器安全解析上限。", true);
    return;
  }

  try {
    setStatus("正在本地读取 PCK 与计算 SHA-256…");
    const buffer = await file.arrayBuffer();
    const [hashBuffer, archive, dll] = await Promise.all([
      crypto.subtle.digest("SHA-256", buffer),
      Promise.resolve(parsePck(buffer)),
      inspectDll(dllFile)
    ]);
    setStatus("正在分析 JSON 与资源映射…");
    const hash = bytesToHex(new Uint8Array(hashBuffer));
    currentResult = analyzeArchive(file, archive, hash, dll);
    elements.resourceFilter.value = "";
    renderResult();
    setStatus("解析完成。索引仅保留在当前浏览器内存，下载前不会写入网络。");
  } catch (error) {
    currentResult = null;
    hideResults();
    setStatus(`解析失败：${error.message || "未知错误"}`, true);
  }
}

function parsePck(buffer) {
  const view = new DataView(buffer);
  if (view.byteLength < PCK_BASE_OFFSET + 4 || view.getUint32(0, true) !== PCK_MAGIC) {
    throw new Error("不是有效的 Godot PCK 文件。");
  }
  const directoryOffset = readU64(view, 0x20);
  if (directoryOffset > view.byteLength - 4) throw new Error("PCK 目录偏移无效。");

  let cursor = directoryOffset;
  const count = view.getUint32(cursor, true);
  cursor += 4;
  if (count > 200000) throw new Error("PCK 目录条目数量异常。");

  const entries = [];
  const byPath = new Map();
  for (let index = 0; index < count; index += 1) {
    requireRange(view, cursor, 4, "PCK 条目名称长度");
    const nameLength = view.getUint32(cursor, true);
    cursor += 4;
    if (nameLength > 65535) throw new Error("PCK 条目名称过长。");
    requireRange(view, cursor, nameLength, "PCK 条目名称");
    const path = normalizePath(decoder.decode(new Uint8Array(buffer, cursor, nameLength)));
    cursor = align4(cursor + nameLength);
    requireRange(view, cursor, 36, "PCK 条目元数据");
    const offset = readU64(view, cursor);
    const size = readU64(view, cursor + 8);
    const flags = view.getUint32(cursor + 32, true);
    cursor += 36;
    const absoluteOffset = PCK_BASE_OFFSET + offset;
    if (size > Number.MAX_SAFE_INTEGER || absoluteOffset > view.byteLength || size > view.byteLength - absoluteOffset) {
      throw new Error(`PCK 条目范围无效：${path || index}`);
    }
    const entry = { path, offset: absoluteOffset, size, flags };
    entries.push(entry);
    byPath.set(path.toLowerCase(), entry);
  }
  return { buffer, entries, byPath };
}

async function inspectDll(file) {
  if (!file) return null;
  const maxDllBytes = 128 * 1024 * 1024;
  if (file.size > maxDllBytes) {
    return { fileName: file.name, skipped: "DLL 超过 128 MiB 静态分析上限", resourceReferences: [] };
  }
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  const strings = extractStaticStrings(bytes);
  const resourceReferences = [...new Set(strings
    .filter((value) => looksLikeImage(value))
    .map(normalizePath)
    .filter(Boolean))].slice(0, 4096);
  const hash = bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", buffer)));
  return { fileName: file.name, sha256: hash, stringCount: strings.length, resourceReferences };
}

function extractStaticStrings(bytes) {
  const values = new Set();
  let ascii = "";
  for (let index = 0; index < bytes.length; index += 1) {
    const value = bytes[index];
    if (value >= 32 && value <= 126) {
      ascii += String.fromCharCode(value);
    } else {
      if (ascii.length >= 5) values.add(ascii);
      ascii = "";
    }
  }
  if (ascii.length >= 5) values.add(ascii);

  for (let start = 0; start + 10 < bytes.length; start += 1) {
    let index = start;
    let text = "";
    while (index + 1 < bytes.length && bytes[index] >= 32 && bytes[index] <= 126 && bytes[index + 1] === 0 && text.length < 1024) {
      text += String.fromCharCode(bytes[index]);
      index += 2;
    }
    if (text.length >= 5) {
      values.add(text);
      start = index - 1;
    }
  }
  return [...values];
}

function analyzeArchive(file, archive, hash, dll) {
  const mappings = new Map();
  const diagnostics = [];
  let jsonScanned = 0;
  let compressedEntries = 0;
  let skippedLargeJson = 0;
  for (const entry of archive.entries) if ((entry.flags & 1) !== 0) compressedEntries += 1;

  const jsonEntries = archive.entries.filter((entry) => entry.path.toLowerCase().endsWith(".json"));
  for (const entry of jsonEntries) {
    if (jsonScanned >= MAX_JSON_FILES) break;
    if ((entry.flags & 1) !== 0) continue;
    if (entry.size > MAX_JSON_BYTES) {
      skippedLargeJson += 1;
      continue;
    }
    jsonScanned += 1;
    const text = decoder.decode(readEntry(archive, entry));
    let data;
    try {
      data = JSON.parse(text.replace(/\0+$/g, ""));
    } catch {
      continue;
    }
    if (samePath(entry.path, "generated/card_replacements.json")) {
      extractReplacementMappings(data, entry.path, archive, mappings);
    } else if (samePath(entry.path, "data/framed_card_project.json") || samePath(entry.path, "deta/framed_card_project.json")) {
      extractFramedMappings(data, entry.path, archive, mappings);
    } else {
      extractHeuristicMappings(data, entry.path, archive, mappings);
    }
  }

  if (dll) extractDllResourceMappings(dll, archive, mappings);

  if (compressedEntries > 0) diagnostics.push(`已跳过 ${compressedEntries} 个带压缩标记的 PCK 条目。`);
  if (jsonEntries.length > MAX_JSON_FILES) diagnostics.push(`JSON 文件超过上限，仅扫描前 ${MAX_JSON_FILES} 个。`);
  if (skippedLargeJson > 0) diagnostics.push(`已跳过 ${skippedLargeJson} 个超过 1 MiB 的 JSON 文件。`);
  if (dll?.skipped) diagnostics.push(`DLL 静态分析已跳过：${dll.skipped}。`);
  if (dll && !dll.skipped) diagnostics.push(`已本地检查 ${dll.fileName} 的 ${dll.stringCount} 条静态字符串，找到 ${dll.resourceReferences.length} 条图片资源引用；DLL 未被执行。`);
  if (mappings.size === 0) diagnostics.push("未发现可确认映射：可检查模组是否使用运行时替换、压缩资源或非标准数据结构。");
  diagnostics.push("输出索引应由游戏内模组再次校验 PCK SHA-256 与资源路径后再导入。");

  return {
    file,
    hash,
    archiveEntryCount: archive.entries.length,
    jsonScanned,
    compressedEntries,
    resources: archive.entries.map((entry) => ({
      path: entry.path,
      size: entry.size,
      compressed: (entry.flags & 1) !== 0
    })),
    dll,
    diagnostics,
    mappings: [...mappings.values()].sort((left, right) => left.cardId.localeCompare(right.cardId) || left.resourcePath.localeCompare(right.resourcePath))
  };
}

function extractDllResourceMappings(dll, archive, mappings) {
  for (const resourcePath of dll.resourceReferences) {
    if (!resourceExists(archive, resourcePath)) continue;
    const cardId = inferCardId(resourcePath);
    addMapping(mappings, archive, cardId, resourcePath, dll.fileName, "DLL 静态资源引用 + 文件名推断", "medium");
  }
}

function extractReplacementMappings(data, sourceFile, archive, mappings) {
  const entries = Array.isArray(data) ? data : Array.isArray(data?.entries) ? data.entries : [];
  for (const entry of entries) {
    if (!isObject(entry) || (entry.kind && String(entry.kind).toLowerCase() !== "image")) continue;
    const imagePath = firstString(entry, ["image", "portrait", "path", "texture", "replacement"]);
    const cardId = firstString(entry, ["cardId", "id", "target", "modelId"]) || inferCardId(imagePath);
    addMapping(mappings, archive, cardId, imagePath, sourceFile, "确定 JSON 字段", "high");
  }
}

function extractFramedMappings(data, sourceFile, archive, mappings) {
  const entries = Array.isArray(data) ? data : Array.isArray(data?.entries) ? data.entries : Array.isArray(data?.cards) ? data.cards : [];
  for (const entry of entries) {
    if (!isObject(entry)) continue;
    const imagePath = firstString(entry, ["portrait", "image"]);
    const cardId = firstString(entry, ["cardId", "id"]) || inferPortraitCardId(imagePath);
    addMapping(mappings, archive, cardId, imagePath, sourceFile, "Framed JSON", "high");
  }
}

function extractHeuristicMappings(root, sourceFile, archive, mappings) {
  for (const item of walkObjects(root)) {
    if (!item.semantic && !hasSemantic(item.value)) continue;
    for (const [propertyName, value] of Object.entries(item.value)) {
      if (typeof value !== "string" || !looksLikeImage(value)) continue;
      const explicit = firstString(item.value, ["cardId", "card_id", "modelId", "model_id", "targetCard", "target_card", "target", "card", "id"]);
      const cardId = explicit || plausibleCardKey(propertyName) || plausibleCardKey(item.contextKey) || inferCardId(value);
      const evidence = explicit ? "JSON 语义 + 显式卡牌字段" : "JSON 语义 + 路径/键名推断";
      addMapping(mappings, archive, cardId, value, sourceFile, evidence, explicit ? "high" : "medium");
    }
  }
}

function* walkObjects(value, contextKey = "", semantic = false, depth = 0) {
  if (depth > 16 || value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    for (const item of value) yield* walkObjects(item, contextKey, semantic, depth + 1);
    return;
  }
  yield { value, contextKey, semantic };
  for (const [key, child] of Object.entries(value)) {
    if (child && typeof child === "object") yield* walkObjects(child, key, semantic || containsSemantic(key), depth + 1);
  }
}

function addMapping(mappings, archive, cardId, imagePath, sourceFile, evidence, confidence) {
  if (!cardId || !imagePath) return;
  const resourcePath = normalizePath(imagePath);
  if (!resourceExists(archive, resourcePath)) return;
  const normalizedCardId = String(cardId).trim();
  if (!normalizedCardId) return;
  const key = `${normalizedCardId.toLowerCase()}|${resourcePath.toLowerCase()}`;
  const candidate = { cardId: normalizedCardId, resourcePath, sourceFile, evidence, confidence };
  const existing = mappings.get(key);
  if (!existing || (existing.confidence === "medium" && confidence === "high")) mappings.set(key, candidate);
}

function resourceExists(archive, resourcePath) {
  const key = resourcePath.toLowerCase();
  return archive.byPath.has(key) || archive.byPath.has(`${key}.import`);
}

function firstString(object, keys) {
  if (!isObject(object)) return "";
  for (const key of keys) {
    const foundKey = Object.keys(object).find((candidate) => candidate.toLowerCase() === key.toLowerCase());
    const value = foundKey ? object[foundKey] : null;
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return "";
}

function inferCardId(path) {
  const normalized = normalizePath(path);
  let match = normalized.match(/^generated\/assets\/card_art\/(.+)_card_art\.[^.]+$/i);
  if (match) return match[1];
  match = normalized.match(/(?:^|\/)cards\/(.+)_portrait\.[^.]+$/i) || normalized.match(/^assets\/images\/cards\/(.+)_portrait\.[^.]+$/i);
  if (match) return match[1];
  match = normalized.match(/^NadjaCard\/(.+)_nadja\d*\.[^.]+$/i);
  if (match) return toPascalCase(match[1]);
  return inferLooseCardId(normalized);
}

function inferPortraitCardId(path) { return inferCardId(path); }

function inferLooseCardId(path) {
  const name = path.split("/").pop()?.replace(/\.[^.]+$/, "") || "";
  const match = name.match(/^(.+?)(?:[_ -](?:card[_ -]?art|portrait|replacement|alternate|alt|skin|art))\d*$/i);
  return match ? match[1] : "";
}

function plausibleCardKey(value) {
  if (!value || !/^[A-Za-z0-9_.-]{2,100}$/.test(value)) return "";
  const reserved = new Set(["image", "portrait", "path", "texture", "replacement", "art", "cardart", "card_art", "entries", "cards"]);
  return reserved.has(value.toLowerCase()) ? "" : value;
}

function hasSemantic(object) {
  return Object.entries(object).some(([key, value]) => containsSemantic(key) || (typeof value === "string" && value.length < 97 && !looksLikeImage(value) && containsSemantic(value)));
}

function containsSemantic(value) {
  const normalized = normalizeToken(String(value));
  return semanticTokens.some((token) => normalized.includes(normalizeToken(token)));
}

function normalizeToken(value) { return value.normalize("NFKC").toLowerCase().replace(/[^\p{L}\p{N}]+/gu, ""); }
function looksLikeImage(value) { return /\.(png|jpe?g|webp|ctex)(?:\.import)?$/i.test(String(value).trim()); }
function normalizePath(path) { return String(path || "").replaceAll("\\", "/").trim().replace(/\0+$/g, "").replace(/^res:\/\//i, "").replace(/\.import$/i, ""); }
function samePath(left, right) { return normalizePath(left).toLowerCase() === normalizePath(right).toLowerCase(); }
function isObject(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function toPascalCase(value) { return value.split(/[_ -]+/).filter(Boolean).map((part) => part[0].toUpperCase() + part.slice(1)).join(""); }

function readEntry(archive, entry) { return new Uint8Array(archive.buffer, entry.offset, entry.size); }
function readU64(view, offset) {
  requireRange(view, offset, 8, "PCK 64 位字段");
  const value = Number(view.getBigUint64(offset, true));
  if (!Number.isSafeInteger(value)) throw new Error("PCK 条目偏移超出浏览器可安全处理的范围。");
  return value;
}
function requireRange(view, offset, length, label) { if (offset < 0 || length < 0 || offset > view.byteLength - length) throw new Error(`${label}越界。`); }
function align4(value) { return (value + 3) & ~3; }
function bytesToHex(bytes) { return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join(""); }

function buildIndex() {
  if (!currentResult) return null;
  const modId = elements.modId.value.trim();
  const modVersion = elements.modVersion.value.trim();
  return {
    schemaVersion: 1,
    indexType: "local-card-art-pck-index",
    generatedBy: { name: "Card Art Local PCK Indexer", version: "1.0.0" },
    generatedAtUtc: new Date().toISOString(),
    indexId: `local:${modId || "unknown-mod"}:${currentResult.hash.slice(0, 16)}`,
    mod: { id: modId, version: modVersion },
    pck: { fileName: currentResult.file.name, size: currentResult.file.size, sha256: currentResult.hash },
    staticDll: currentResult.dll ? {
      fileName: currentResult.dll.fileName,
      sha256: currentResult.dll.sha256 || "",
      resourceReferences: currentResult.dll.resourceReferences
    } : null,
    mappings: currentResult.mappings,
    diagnostics: currentResult.diagnostics
  };
}

function renderResult() {
  if (!currentResult) return;
  const index = buildIndex();
  elements.summary.classList.remove("hidden");
  elements.mappings.classList.remove("hidden");
  elements.resources.classList.remove("hidden");
  elements.diagnostics.classList.remove("hidden");
  elements.fileTitle.textContent = currentResult.file.name;
  elements.hashBadge.textContent = `SHA-256 ${currentResult.hash}`;
  elements.metrics.replaceChildren(
    metric(currentResult.archiveEntryCount, "PCK 条目"),
    metric(currentResult.jsonScanned, "JSON 已扫描"),
    metric(currentResult.mappings.length, "可导入映射"),
    metric(currentResult.dll?.resourceReferences.length || 0, "DLL 图片引用")
  );
  elements.mappingCount.textContent = `${currentResult.mappings.length} 条`;
  elements.mappingRows.replaceChildren(...currentResult.mappings.map(mappingRow));
  elements.emptyMappings.classList.toggle("hidden", currentResult.mappings.length !== 0);
  renderResourceTree();
  elements.diagnosticList.replaceChildren(...index.diagnostics.map((item) => {
    const row = document.createElement("li"); row.textContent = item; return row;
  }));
}

function renderResourceTree() {
  if (!currentResult) return;
  const resources = currentResult.resources || [];
  const filter = elements.resourceFilter.value.trim().replaceAll("\\", "/").toLocaleLowerCase();
  const matched = filter ? resources.filter((entry) => entry.path.toLocaleLowerCase().includes(filter)) : resources;
  const visible = matched.slice(0, MAX_RESOURCE_TREE_ENTRIES);
  const truncated = visible.length !== matched.length;

  elements.resourceCount.textContent = truncated
    ? `显示 ${visible.length} / ${matched.length}，共 ${resources.length} 个条目`
    : filter ? `匹配 ${matched.length} / 共 ${resources.length} 个条目` : `${resources.length} 个条目`;
  elements.resourceHint.textContent = truncated
    ? `为避免浏览器因 ${matched.length} 个条目同时渲染而卡顿，目前仅显示前 ${MAX_RESOURCE_TREE_ENTRIES} 条；请继续输入路径缩小范围。`
    : filter ? `正在按完整路径筛选“${elements.resourceFilter.value.trim()}”。` : "展开目录即可查看 PCK 的原始资源路径；“压缩”表示该条目不能直接由当前静态 JSON 解析器读取。";

  elements.resourceTree.replaceChildren();
  if (visible.length === 0) {
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent = filter ? "没有匹配该路径的资源。" : "PCK 目录中没有资源条目。";
    elements.resourceTree.append(empty);
    return;
  }
  appendResourceBranch(elements.resourceTree, buildResourceTree(visible), 0);
}

function buildResourceTree(resources) {
  const root = { directories: new Map(), files: [] };
  for (const resource of resources) {
    const segments = resource.path.split("/").filter(Boolean);
    const fileName = segments.pop() || resource.path;
    let branch = root;
    for (const segment of segments) {
      if (!branch.directories.has(segment)) branch.directories.set(segment, { directories: new Map(), files: [] });
      branch = branch.directories.get(segment);
    }
    branch.files.push({ ...resource, fileName });
  }
  return root;
}

function appendResourceBranch(parent, branch, depth) {
  const directories = [...branch.directories.entries()].sort(([left], [right]) => left.localeCompare(right));
  for (const [name, child] of directories) {
    const details = document.createElement("details");
    details.open = depth < 1;
    const summary = document.createElement("summary");
    summary.textContent = `${name}/`;
    details.append(summary);
    appendResourceBranch(details, child, depth + 1);
    parent.append(details);
  }
  const files = [...branch.files].sort((left, right) => left.fileName.localeCompare(right.fileName));
  for (const resource of files) {
    const row = document.createElement("div");
    row.className = `resource-file${resource.compressed ? " is-compressed" : ""}`;
    row.title = resource.path;
    const name = document.createElement("span");
    name.textContent = resource.fileName;
    row.append(name);
    if (resource.compressed) {
      const tag = document.createElement("span");
      tag.className = "resource-tag";
      tag.textContent = "压缩";
      row.append(tag);
    }
    const meta = document.createElement("span");
    meta.className = "resource-meta";
    meta.textContent = formatBytes(resource.size);
    row.append(meta);
    parent.append(row);
  }
}

function formatBytes(size) {
  if (!Number.isFinite(size) || size < 0) return "大小未知";
  if (size < 1024) return `${size} B`;
  const units = ["KiB", "MiB", "GiB"];
  let value = size / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  return `${value >= 10 ? value.toFixed(0) : value.toFixed(1)} ${units[unit]}`;
}

function metric(value, label) { const node = document.createElement("div"); node.className = "metric"; node.innerHTML = `<strong>${value}</strong><span>${label}</span>`; return node; }
function mappingRow(mapping) {
  const row = document.createElement("tr");
  for (const [text, className] of [[mapping.cardId, ""], [mapping.resourcePath, "path"], [mapping.evidence, ""], [mapping.confidence === "high" ? "高" : "中", `confidence ${mapping.confidence}`]]) {
    const cell = document.createElement("td"); cell.textContent = text; cell.className = className; row.append(cell);
  }
  return row;
}

function downloadIndex() {
  const index = buildIndex(); if (!index) return;
  const blob = new Blob([JSON.stringify(index, null, 2)], { type: "application/json" });
  const link = document.createElement("a"); link.href = URL.createObjectURL(blob);
  link.download = `${safeFileName(index.mod.id || currentResult.file.name.replace(/\.pck$/i, ""))}-${currentResult.hash.slice(0, 12)}.card-art-index.json`;
  link.click(); URL.revokeObjectURL(link.href);
}

async function copyIndex() {
  const index = buildIndex(); if (!index) return;
  try { await navigator.clipboard.writeText(JSON.stringify(index, null, 2)); setStatus("索引 JSON 已复制到剪贴板。"); }
  catch { setStatus("浏览器不允许写入剪贴板，请使用下载按钮。", true); }
}

function safeFileName(value) { return String(value).replace(/[^a-z0-9._-]+/gi, "_").replace(/^_+|_+$/g, "") || "card-art-index"; }
function setStatus(message, error = false) { elements.status.textContent = message; elements.status.classList.toggle("error", error); }
function hideResults() { elements.summary.classList.add("hidden"); elements.mappings.classList.add("hidden"); elements.resources.classList.add("hidden"); elements.diagnostics.classList.add("hidden"); }
