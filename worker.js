// ═══════════════════════════════════════════════════════════
// 🌸 AMIOKI INVENTORY v4 — Cloudflare Worker
// Patched: matchItem (Jaccard+containment), deductOrUnmatch
//          (per-item dedup guard, $0 line item skip),
//          approveBatch (exact+fuzzy inv match, skip
//          qty_delivered when no inv match found),
//          sweepUnmatched (per-iteration try/catch)
// ═══════════════════════════════════════════════════════════

const ROLES = {
  ashley: { label: "Ashley",           filter: "Ashley",  isMaster: false, canEdit: false },
  liz:    { label: "Liz",              filter: "Liz",     isMaster: false, canEdit: false },
  sydni:  { label: "Sydni",            filter: "Sydni",   isMaster: false, canEdit: false },
  ami:    { label: "Ami",              filter: "Amioki",  isMaster: false, canEdit: true  },
  master: { label: "Master Dashboard", filter: null,      isMaster: true,  canEdit: true  }
};

const ARCHIVE_CATEGORIES = ["limited edition", "discontinued", "out-of-rotation", "out of rotation"];

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Max-Age": "86400"
};

const CARRIERS = {
  "verizon":    "@vtext.com",
  "att":        "@txt.att.net",
  "tmobile":    "@tmomail.net",
  "cricket":    "@sms.cricketwireless.net",
  "boost":      "@sms.myboostmobile.com",
  "metropcs":   "@mymetropcs.com",
  "sprint":     "@messaging.sprintpcs.com",
  "uscellular": "@email.uscc.net"
};

// ═══════════════════════════════════════════════════════════
// ENTRY POINT
// ═══════════════════════════════════════════════════════════

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });

    const url = new URL(request.url);
    const action = url.searchParams.get("action") || "";

    try {
      if (request.method === "POST" && action === "squareWebhook") {
        return await handleSquareWebhook(request, env, ctx);
      }

      if (action === "triggerDigest") {
        const secret = url.searchParams.get("secret") || "";
        if (secret !== (env.DIGEST_SECRET || "")) return json({ ok: false, error: "Unauthorized" }, 401);
        const override = url.searchParams.get("override") === "true";
        ctx.waitUntil(sendDailyDigests(env, override));
        return json({ ok: true, message: override ? "Digest sent (override)" : "Digest triggered" });
      }

      if (action === "ping") return json({ ok: true, version: "v4", time: new Date().toISOString() });
      if (action === "login") return await handleLogin(url, env);

      const token = url.searchParams.get("token") || "";
      const who = await verifyToken(token, env);
      if (!who) return json({ ok: false, error: "Auth required" }, 401);

      const role = ROLES[who];

      // ── READ actions (all roles) ──
      if (action === "getInventory")   return json({ ok: true, items:   await getInventory(env, who) });
      if (action === "getStats")       return json({ ok: true, stats:   await getStats(env, who) });
      if (action === "getSalesLog")    return json({ ok: true, sales:   await getSalesLog(env, who, url.searchParams) });
      if (action === "getMyProfile")   return json({ ok: true, profile: await getProfile(env, who) });
      if (action === "updateMyProfile") return json(await updateProfile(env, who, url.searchParams));

      // ── CROCHETER actions ──
      if (action === "getPieceRates")  return json({ ok: true, rates: await getPieceRates(env, url.searchParams.get("crocheter")) });
      if (action === "logProduction")  return json(await logProduction(env, url.searchParams, who, ctx));
      if (action === "getMyBatches")   return json({ ok: true, batches: await getMyBatches(env, who) });
      if (action === "submitQC")       return json(await submitQC(env, url.searchParams, who));
      if (action === "getQC")          return json({ ok: true, qc: await getQC(env, url.searchParams) });

      if (action === "getContracts") {
        return json(role.isMaster
          ? { ok: true, contracts: await getAllContracts(env) }
          : { ok: true, contract: await getMyActiveContract(env, who) });
      }

      // ── EDIT actions (ami + master) ──
      if (!role.canEdit) return json({ ok: false, error: "Not allowed" }, 403);

      if (action === "getUnmatched")     return json({ ok: true, unmatched: await getUnmatched(env) });
      if (action === "addItem")          return json(await addItem(env, url.searchParams, ctx));
      if (action === "updateItem")       return json(await updateItem(env, url.searchParams, ctx, who));
      if (action === "deleteItem")       return json(await deleteItem(env, url.searchParams));
      if (action === "adjustStock")      return json(await adjustStock(env, url.searchParams, ctx, who));
      if (action === "resolveUnmatched") return json(await resolveUnmatched(env, url.searchParams, ctx, who));
      if (action === "updatePieceRate")  return json(await updatePieceRate(env, url.searchParams));
      if (action === "manualDelivery")   return json(await manualDelivery(env, url.searchParams, ctx));

      // ── AMI GOALS + RATE CARD (ami + master) ──
      if (action === "getAmiGoals")       return json(await getAmiGoals(env, who));
      if (action === "createAmiGoal")     return json(await createAmiGoal(env, url.searchParams, who));
      if (action === "logAmiGoalBatch")   return json(await logAmiGoalBatch(env, url.searchParams, who, ctx));
      if (action === "completeAmiGoal")   return json(await completeAmiGoal(env, url.searchParams));
      if (action === "deleteAmiGoal")     return json(await deleteAmiGoal(env, url.searchParams));
      if (action === "getAmiGoalHistory") return json(await getAmiGoalHistory(env, who));
      if (action === "getAmiRates")       return json({ ok: true, rates: await getAmiRates(env) });
      if (action === "saveAmiRate")       return json(await saveAmiRate(env, url.searchParams));
      
      // ── SUPPLIERS (ami + master) ──
      if (action === "getSuppliers")          return json({ ok: true, suppliers: await getSuppliers(env) });
      if (action === "saveSupplier")          return json(await saveSupplier(env, url.searchParams, ctx));
      if (action === "receiveSupplierOrder")  return json(await receiveSupplierOrder(env, url.searchParams, ctx));
      if (action === "getSupplierDeliveries") return json({ ok: true, deliveries: await getSupplierDeliveries(env, url.searchParams) });
      if (action === "paySupplier")           return json(await paySupplier(env, url.searchParams, ctx));

      // ── MASTER-only actions ──
      if (!role.isMaster) return json({ ok: false, error: "Master only" }, 403);

      if (action === "getArchive")           return json({ ok: true, archived: await getArchive(env) });
      if (action === "restoreItem")          return json(await restoreItem(env, url.searchParams, ctx));
      if (action === "archiveItem")          return json(await archiveItemManual(env, url.searchParams, ctx));
      if (action === "getCrocheters")        return json({ ok: true, crocheters: await getCrocheters(env) });
      if (action === "updateCrocheter")      return json(await updateCrocheterByMaster(env, url.searchParams));
      if (action === "rebuildInventory")     return json(await rebuildInventory(env));
      if (action === "sendTestDigest")       return json(await sendTestDigest(env, url.searchParams));
      if (action === "parseContract")        return json(await parseContractPDF(env, url.searchParams));
      if (action === "saveContract")         return json(await saveContract(env, url.searchParams, ctx));
      if (action === "updateContractItem")   return json(await updateContractItem(env, url.searchParams));
      if (action === "getPendingBatches")    return json({ ok: true, batches: await getAllPendingBatches(env) });
      if (action === "approveBatch")         return json(await approveBatch(env, url.searchParams, ctx));
      if (action === "deleteBatch")          return json(await deleteBatch(env, url.searchParams, ctx));
      if (action === "signQCClient")         return json(await signQCClient(env, url.searchParams));
      if (action === "deleteContract")       return json(await deleteContract(env, url.searchParams, ctx));
      if (action === "completeContract")     return json(await completeContract(env, url.searchParams, ctx));
      if (action === "archiveContract")      return json(await archiveContract(env, url.searchParams, ctx));
      if (action === "getArchivedContracts") {
        const { results } = await env.DB.prepare("SELECT * FROM archived_contracts ORDER BY archived_at DESC").all();
        return json({ ok: true, contracts: results });
      }
      if (action === "getSuppliers")          return json({ ok: true, suppliers: await getSuppliers(env) });
      if (action === "saveSupplier")          return json(await saveSupplier(env, url.searchParams, ctx));
      if (action === "receiveSupplierOrder")  return json(await receiveSupplierOrder(env, url.searchParams, ctx));
      if (action === "getSupplierDeliveries") return json({ ok: true, deliveries: await getSupplierDeliveries(env, url.searchParams) });
      if (action === "paySupplier")           return json(await paySupplier(env, url.searchParams, ctx));

      return json({ ok: false, error: "Unknown action" }, 400);
    } catch (err) {
      console.error("Handler error:", err.message, err.stack);
      return json({ ok: false, error: err.message }, 500);
    }
  }
};

// ═══════════════════════════════════════════════════════════
// AUTH
// ═══════════════════════════════════════════════════════════

async function handleLogin(url, env) {
  const who = (url.searchParams.get("who") || "").toLowerCase();
  const pass = url.searchParams.get("pass") || "";
  if (!ROLES[who]) return json({ ok: false, error: "Unknown role" });
  const expected = env["PASS_" + who.toUpperCase()];
  if (!expected) return json({ ok: false, error: "Role not configured" });
  await new Promise(r => setTimeout(r, 400));
  if (pass !== expected) return json({ ok: false, error: "Wrong password" });
  const token = await makeToken(who, env);
  return json({ ok: true, token, role: who, label: ROLES[who].label, canEdit: ROLES[who].canEdit });
}

async function makeToken(who, env) {
  const bucket = Math.floor(Date.now() / (30 * 24 * 60 * 60 * 1000));
  const sig = await hmac(`${who}|${bucket}`, env.TOKEN_SECRET || "fallback-secret");
  return `${who}.${bucket}.${sig}`;
}

async function verifyToken(token, env) {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [who, bucketStr, sig] = parts;
  if (!ROLES[who]) return null;
  const bucket = Number(bucketStr);
  const nowBucket = Math.floor(Date.now() / (30 * 24 * 60 * 60 * 1000));
  if (bucket !== nowBucket && bucket !== nowBucket - 1) return null;
  const expected = await hmac(`${who}|${bucket}`, env.TOKEN_SECRET || "fallback-secret");
  return constantTimeEq(sig, expected) ? who : null;
}

async function hmac(message, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return btoa(String.fromCharCode(...new Uint8Array(sigBuf)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function constantTimeEq(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// ═══════════════════════════════════════════════════════════
// INVENTORY READS
// ═══════════════════════════════════════════════════════════

async function getInventory(env, who) {
  const role = ROLES[who];
  let stmt;
  if (role.isMaster) {
    stmt = env.DB.prepare("SELECT * FROM items WHERE archived = 0 ORDER BY crocheter, name");
  } else {
    stmt = env.DB.prepare("SELECT * FROM items WHERE crocheter = ? AND archived = 0 ORDER BY name").bind(role.filter);
  }
  const { results } = await stmt.all();
  return results.map(rowToItem);
}

async function getStats(env, who) {
  const items = await getInventory(env, who);
  const stats = { totalItems: items.length, inStock: 0, lowStock: 0, outOfStock: 0, totalOnHand: 0, totalValue: 0 };
  items.forEach(i => {
    stats.totalOnHand += i.on_hand;
    stats.totalValue  += i.on_hand * (i.price || 0);
    if (i.on_hand <= 0) stats.outOfStock++;
    else if (i.min_stock > 0 && i.on_hand < i.min_stock) stats.lowStock++;
    else stats.inStock++;
  });
  return stats;
}

async function getSalesLog(env, who, params) {
  const role  = ROLES[who];
  const limit = Math.min(Number(params.get("limit")) || 50, 200);
  let stmt;
  if (role.isMaster) {
    stmt = env.DB.prepare(
      "SELECT sl.*, i.crocheter FROM sales_log sl LEFT JOIN items i ON sl.item_id = i.id ORDER BY sl.timestamp DESC LIMIT ?"
    ).bind(limit);
  } else {
    stmt = env.DB.prepare(
      "SELECT sl.*, i.crocheter FROM sales_log sl LEFT JOIN items i ON sl.item_id = i.id WHERE i.crocheter = ? ORDER BY sl.timestamp DESC LIMIT ?"
    ).bind(role.filter, limit);
  }
  const { results } = await stmt.all();
  return results;
}

async function getUnmatched(env) {
  const { results } = await env.DB.prepare(
    "SELECT * FROM unmatched_sales WHERE status = 'pending' ORDER BY timestamp DESC"
  ).all();
  return results;
}

async function getArchive(env) {
  const { results } = await env.DB.prepare(
    "SELECT * FROM items WHERE archived = 1 ORDER BY crocheter, name"
  ).all();
  return results.map(rowToItem);
}

async function getCrocheters(env) {
  const { results } = await env.DB.prepare("SELECT * FROM crocheters ORDER BY display_name").all();
  return results;
}

async function getProfile(env, who) {
  const row = await env.DB.prepare("SELECT * FROM crocheters WHERE role = ?").bind(who).first();
  return row || null;
}

function rowToItem(r) {
  return {
    id: r.id, name: r.name, category: r.category || "",
    crocheter: r.crocheter, on_hand: r.on_hand, min_stock: r.min_stock,
    price: r.price || 0, cost: r.cost || 0,
    square_catalog_id: r.square_catalog_id || "",
    archived: r.archived || 0, archive_reason: r.archive_reason || "",
    updated_at: r.updated_at
  };
}

// ═══════════════════════════════════════════════════════════
// CROCHETER PROFILE
// ═══════════════════════════════════════════════════════════

async function updateProfile(env, who, params) {
  const fields = {};
  const allowed = ["email", "phone", "carrier", "notify_low_stock", "notify_sold_out", "notify_sms", "notify_email"];
  allowed.forEach(k => {
    const v = params.get(k);
    if (v !== null) {
      if (k.startsWith("notify_")) fields[k] = v === "1" || v === "true" ? 1 : 0;
      else fields[k] = v.trim();
    }
  });
  if (Object.keys(fields).length === 0) return { ok: false, error: "Nothing to update" };
  const setClauses = Object.keys(fields).map(k => `${k} = ?`).join(", ");
  const values = [...Object.values(fields), new Date().toISOString(), who];
  await env.DB.prepare(`UPDATE crocheters SET ${setClauses}, updated_at = ? WHERE role = ?`).bind(...values).run();
  return { ok: true };
}

async function updateCrocheterByMaster(env, params) {
  const role = (params.get("role") || "").toLowerCase();
  if (!ROLES[role]) return { ok: false, error: "Unknown role" };
  const patch = {};
  const digest = params.get("digest_enabled");
  if (digest !== null) patch.digest_enabled = digest === "1" ? 1 : 0;
  ["email", "phone", "carrier"].forEach(k => {
    const v = params.get(k);
    if (v !== null) patch[k] = v.trim();
  });
  if (!Object.keys(patch).length) return { ok: false, error: "Nothing to update" };
  patch.updated_at = new Date().toISOString();
  const fields = Object.keys(patch).map(k => `${k} = ?`).join(", ");
  await env.DB.prepare(`UPDATE crocheters SET ${fields} WHERE role = ?`)
    .bind(...Object.values(patch), role).run();
  return { ok: true };
}

// ═══════════════════════════════════════════════════════════
// INVENTORY WRITES
// ═══════════════════════════════════════════════════════════

async function addItem(env, params, ctx) {
  const name = (params.get("name") || "").trim();
  if (!name) return { ok: false, error: "Name required" };
  const item = {
    name,
    category:          (params.get("category") || "").trim(),
    crocheter:         (params.get("crocheter") || "Amioki").trim(),
    on_hand:           Math.max(0, Number(params.get("on_hand")) || 0),
    min_stock:         Math.max(0, Number(params.get("min_stock")) || 0),
    price:             Math.max(0, Number(params.get("price")) || 0),
    cost:              Math.max(0, Number(params.get("cost")) || 0),
    square_catalog_id: (params.get("square_catalog_id") || "").trim()
  };
  try {
    const result = await env.DB.prepare(
      `INSERT INTO items (name, category, crocheter, on_hand, min_stock, price, cost, square_catalog_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(item.name, item.category, item.crocheter, item.on_hand, item.min_stock,
      item.price, item.cost, item.square_catalog_id).run();
    ctx.waitUntil(auditLog(env, { action: "add_item", item: item.name, qty: item.on_hand, note: `Created (${item.crocheter})` }));
    return { ok: true, id: result.meta.last_row_id, item };
  } catch (err) {
    if (String(err.message).includes("UNIQUE")) return { ok: false, error: `"${name}" already exists` };
    throw err;
  }
}

async function updateItem(env, params, ctx, who) {
  const id = Number(params.get("id"));
  if (!id) return { ok: false, error: "ID required" };
  const current = await env.DB.prepare("SELECT * FROM items WHERE id = ?").bind(id).first();
  if (!current) return { ok: false, error: "Item not found" };
  if (who === "ami" && current.crocheter !== "Amioki") return { ok: false, error: "Not your item" };
  const patch = {};
  ["name", "category", "crocheter", "square_catalog_id"].forEach(k => {
    const v = params.get(k); if (v !== null) patch[k] = v.trim();
  });
  ["on_hand", "min_stock"].forEach(k => {
    const v = params.get(k); if (v !== null && v !== "") patch[k] = Math.floor(Number(v));
  });
  ["price", "cost"].forEach(k => {
    const v = params.get(k); if (v !== null && v !== "") patch[k] = Number(v);
  });
  if (Object.keys(patch).length === 0) return { ok: false, error: "Nothing to update" };
  const fields = Object.keys(patch).map(k => `${k} = ?`).join(", ");
  const values = [...Object.values(patch), new Date().toISOString(), id];
  await env.DB.prepare(`UPDATE items SET ${fields}, updated_at = ? WHERE id = ?`).bind(...values).run();
  ctx.waitUntil(auditLog(env, { action: "update_item", item: current.name, qty: patch.on_hand ?? current.on_hand, note: `Edited: ${Object.keys(patch).join(", ")}` }));
  return { ok: true };
}

async function deleteItem(env, params) {
  const id = Number(params.get("id"));
  if (!id) return { ok: false, error: "ID required" };
  const current = await env.DB.prepare("SELECT name FROM items WHERE id = ?").bind(id).first();
  if (!current) return { ok: false, error: "Item not found" };
  await env.DB.prepare("DELETE FROM items WHERE id = ?").bind(id).run();
  return { ok: true, message: `Deleted ${current.name}` };
}

async function adjustStock(env, params, ctx, who) {
  const id    = Number(params.get("id"));
  const delta = Math.floor(Number(params.get("delta")) || 0);
  const note  = params.get("note") || "Manual adjust";
  if (!id || !delta) return { ok: false, error: "id and delta required" };
  const current = await env.DB.prepare("SELECT * FROM items WHERE id = ?").bind(id).first();
  if (!current) return { ok: false, error: "Item not found" };
  const role = ROLES[who];
  if (!role.isMaster && current.crocheter !== role.filter) return { ok: false, error: "Not your item" };
  const newQty = Math.max(0, current.on_hand + delta);
  await env.DB.batch([
    env.DB.prepare("UPDATE items SET on_hand=?, cost=CASE WHEN cost IS NULL OR cost=0 THEN ? ELSE cost END, updated_at=? WHERE id=?")
  .bind(newQty, item.piece_rate || 0, now, invItem.id),
    env.DB.prepare(`INSERT INTO sales_log (item_id, item_name, qty, type, note) VALUES (?, ?, ?, ?, ?)`)
      .bind(id, current.name, delta, delta > 0 ? "adjust" : "manual", note)
  ]);
  ctx.waitUntil((async () => {
    await checkAndArchive(env, { ...current, on_hand: newQty }, ctx);
    await checkAndNotify(env, { ...current, on_hand: newQty }, ctx);
    await auditLog(env, { action: "adjust", item: current.name, qty: delta, note: `${note} (by ${who})` });
  })());
  return { ok: true, newQty };
}

// ═══════════════════════════════════════════════════════════
// ARCHIVE
// ═══════════════════════════════════════════════════════════

function isArchiveCategory(category) {
  return ARCHIVE_CATEGORIES.includes((category || "").toLowerCase().trim());
}

async function checkAndArchive(env, item, ctx) {
  if (item.on_hand > 0) return;
  if (!isArchiveCategory(item.category)) return;
  if (item.archived) return;
  await env.DB.batch([
    env.DB.prepare("UPDATE items SET archived = 1, archive_reason = 'auto', updated_at = ? WHERE id = ?")
      .bind(new Date().toISOString(), item.id),
    env.DB.prepare(
      `INSERT INTO archived_items (original_id, name, category, crocheter, last_on_hand, price, cost, square_catalog_id, archive_reason)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'auto')`
    ).bind(item.id, item.name, item.category, item.crocheter, item.on_hand,
      item.price, item.cost, item.square_catalog_id || "")
  ]);
  await auditLog(env, { action: "auto_archive", item: item.name, qty: 0, note: `Auto-archived (category: ${item.category})` });
}

async function archiveItemManual(env, params, ctx) {
  const id = Number(params.get("id"));
  if (!id) return { ok: false, error: "ID required" };
  const item = await env.DB.prepare("SELECT * FROM items WHERE id = ?").bind(id).first();
  if (!item) return { ok: false, error: "Item not found" };
  if (item.archived) return { ok: false, error: "Already archived" };
  await env.DB.batch([
    env.DB.prepare("UPDATE items SET archived = 1, archive_reason = 'manual', updated_at = ? WHERE id = ?")
      .bind(new Date().toISOString(), id),
    env.DB.prepare(
      `INSERT INTO archived_items (original_id, name, category, crocheter, last_on_hand, price, cost, square_catalog_id, archive_reason)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'manual')`
    ).bind(id, item.name, item.category, item.crocheter, item.on_hand,
      item.price, item.cost, item.square_catalog_id || "")
  ]);
  ctx.waitUntil(auditLog(env, { action: "manual_archive", item: item.name, qty: item.on_hand, note: "Manually archived by master" }));
  return { ok: true };
}

async function restoreItem(env, params, ctx) {
  const id = Number(params.get("id"));
  if (!id) return { ok: false, error: "ID required" };
  const item = await env.DB.prepare("SELECT * FROM items WHERE id = ?").bind(id).first();
  if (!item) return { ok: false, error: "Item not found" };
  const restoreQty = Math.max(0, Number(params.get("on_hand")) || 0);
  await env.DB.batch([
    env.DB.prepare("UPDATE items SET archived = 0, archive_reason = '', on_hand = ?, updated_at = ? WHERE id = ?")
      .bind(restoreQty, new Date().toISOString(), id),
    env.DB.prepare("UPDATE archived_items SET restored_at = ? WHERE original_id = ? AND restored_at IS NULL")
      .bind(new Date().toISOString(), id)
  ]);
  ctx.waitUntil(auditLog(env, { action: "restore", item: item.name, qty: restoreQty, note: "Restored from archive by master" }));
  return { ok: true };
}

// ═══════════════════════════════════════════════════════════
// SQUARE WEBHOOK
// ═══════════════════════════════════════════════════════════

async function handleSquareWebhook(request, env, ctx) {
  let payload;
  try { payload = await request.json(); } catch { return new Response("Bad JSON", { status: 400 }); }

  const eventId = payload.event_id || "";
  if (eventId && await isDup(env, "evt_" + eventId)) return new Response("OK");
  if (eventId) await markDup(env, "evt_" + eventId);

  if (payload.type === "payment.updated") {
    const payment = payload?.data?.object?.payment;
    if (!payment) return new Response("OK");
    if (payment.status === "COMPLETED" && payment.order_id && !(await isDup(env, payment.id))) {
      if (await isRefundRelated(payment, env)) {
        await markDup(env, payment.id);
      } else {
        await markDup(env, payment.id);
        ctx.waitUntil(processSquarePayment(payment, env, ctx));
      }
    }
  } else if (payload.type === "refund.updated" || payload.type === "refund.created") {
    const refund = payload?.data?.object?.refund;
    const key = "refund_" + (refund?.id || "");
    if (refund && refund.status === "COMPLETED" && !(await isDup(env, key))) {
      await markDup(env, key);
      ctx.waitUntil(processSquareRefund(refund, env, ctx));
    }
  }
  return new Response("OK");
}

async function isRefundRelated(payment, env) {
  if (payment.refund_ids?.length > 0) return true;
  if (payment.refunded_money?.amount > 0) return true;
  const cents = payment.amount_money?.amount || 0;
  if (cents <= 0) {
    const o = payment.order_id ? await fetchSquareOrder(payment.order_id, env) : null;
    if (!o?.line_items?.length) return true;
  }
  if (payment.order_id) {
    const o = await fetchSquareOrder(payment.order_id, env);
    if (o?.returns?.length > 0) return true;
  }
  return false;
}

async function processSquarePayment(payment, env, ctx) {
  const order = await fetchSquareOrder(payment.order_id, env);
  if (!order?.line_items) return;
  for (const li of order.line_items) {
    await deductOrUnmatch(env, li, Number(li.quantity) || 1, payment.id, "sale", ctx);
  }
}

async function processSquareRefund(refund, env, ctx) {
  let order = null;
  if (refund.payment_id) {
    try {
      const r = await fetch(`https://connect.squareup.com/v2/payments/${refund.payment_id}`, {
        headers: { Authorization: `Bearer ${env.SQUARE_TOKEN}`, "Square-Version": "2024-01-18" }
      });
      const pd = await r.json();
      if (pd?.payment?.order_id) order = await fetchSquareOrder(pd.payment.order_id, env);
    } catch (e) {}
  }
  if (!order && refund.order_id) order = await fetchSquareOrder(refund.order_id, env);
  if (!order?.line_items) return;
  for (const li of order.line_items) {
    await refundOrLog(env, li, Number(li.quantity) || 1, refund.id);
  }
}

async function fetchSquareOrder(orderId, env) {
  try {
    const r = await fetch(`https://connect.squareup.com/v2/orders/${orderId}`, {
      headers: { Authorization: `Bearer ${env.SQUARE_TOKEN}`, "Square-Version": "2024-01-18" }
    });
    return (await r.json()).order || null;
  } catch (e) { return null; }
}

// ─────────────────────────────────────────────────────────
// ✅ PATCHED: deductOrUnmatch
//    Fix 1 — Skip $0 discount/modifier line items (qty || 1 was deducting on $0 rows)
//    Fix 2 — Per-item dedup guard: check sales_log before deducting so webhook
//             retries and same-payment multi-match don't double-count
// ─────────────────────────────────────────────────────────
async function deductOrUnmatch(env, lineItem, qty, paymentId, type, ctx) {
  // Fix 1: skip $0 line items that are discounts or gift cards — Square
  // includes these as separate line items but they have no physical inventory
  const unitPrice = lineItem.base_price_money?.amount
    ?? lineItem.gross_sales_money?.amount
    ?? 1;
  if (
    unitPrice === 0 &&
    (lineItem.item_type === "GIFT_CARD" ||
     (lineItem.name || "").toLowerCase().includes("discount") ||
     (lineItem.name || "").toLowerCase().includes("tip"))
  ) {
    return;
  }
  if (qty <= 0) return;

  const item = await matchItem(env, lineItem.catalog_object_id, lineItem.name);
  if (!item) {
    await env.DB.prepare(
      `INSERT INTO unmatched_sales (square_name, square_catalog_id, qty, square_payment_id) VALUES (?, ?, ?, ?)`
    ).bind(lineItem.name || "", lineItem.catalog_object_id || "", qty, paymentId).run();
    await auditLog(env, {
      action: "unmatched", item: lineItem.name || "(unknown)", qty,
      note: `No match. ID: ${lineItem.catalog_object_id || "none"}`
    });
    return;
  }

  // Fix 2: guard against double-deduction for this exact payment+item combo
  const alreadyDone = await env.DB.prepare(
    "SELECT 1 FROM sales_log WHERE square_payment_id = ? AND item_id = ? AND type = 'sale'"
  ).bind(paymentId, item.id).first();
  if (alreadyDone) {
    await auditLog(env, {
      action: "skip_dup_deduction", item: item.name, qty,
      note: `Payment ${paymentId} already recorded for ${item.name} — skipping`
    });
    return;
  }

  const newQty = Math.max(0, item.on_hand - qty);
  await env.DB.batch([
    env.DB.prepare("UPDATE items SET on_hand = ?, updated_at = ? WHERE id = ?")
      .bind(newQty, new Date().toISOString(), item.id),
    env.DB.prepare(`INSERT INTO sales_log (item_id, item_name, qty, type, square_payment_id) VALUES (?, ?, ?, ?, ?)`)
      .bind(item.id, item.name, qty, type, paymentId)
  ]);

  await checkAndArchive(env, { ...item, on_hand: newQty }, ctx);
  await checkAndNotify(env, { ...item, on_hand: newQty }, ctx);
  await auditLog(env, { action: "sale", item: item.name, qty: -qty, note: `Square sale → ${newQty} left` });
}

async function refundOrLog(env, lineItem, qty, refundId) {
  const item = await matchItem(env, lineItem.catalog_object_id, lineItem.name);
  if (!item) return;
  const newQty = item.on_hand + qty;
  await env.DB.batch([
    env.DB.prepare("UPDATE items SET on_hand = ?, updated_at = ? WHERE id = ?")
      .bind(newQty, new Date().toISOString(), item.id),
    env.DB.prepare(`INSERT INTO sales_log (item_id, item_name, qty, type, square_payment_id, note) VALUES (?, ?, ?, ?, ?, ?)`)
      .bind(item.id, item.name, qty, "refund", refundId, "Square refund")
  ]);
  await auditLog(env, { action: "refund", item: item.name, qty, note: `Refund → ${newQty} on hand` });
}

// ─────────────────────────────────────────────────────────
// ✅ PATCHED: matchItem
//    Fix 3 — Replaced first-word LIKE query with Jaccard similarity + containment
//             bonus. Requires ≥2 words matched for multi-word names. Handles
//             parentheticals ("Mini Loaf Cat", "Pikachu (Smol)") correctly.
//             Threshold lowered to 0.5 but with word-count floor to prevent
//             single-common-word false matches like "Mini" hitting everything.
// ─────────────────────────────────────────────────────────
async function matchItem(env, catalogId, name) {
  // 1. Catalog ID exact match — most reliable, always try first
  if (catalogId) {
    const m = await env.DB.prepare(
      "SELECT * FROM items WHERE square_catalog_id = ? AND archived = 0"
    ).bind(catalogId).first();
    if (m) return m;
  }
  if (!name) return null;

  const norm = normalizeName(name);
  const { results } = await env.DB.prepare("SELECT * FROM items WHERE archived = 0").all();

  // 2. Exact normalized name match
  const exact = results.find(r => normalizeName(r.name) === norm);
  if (exact) return exact;

  // 3. Fuzzy: Jaccard similarity + containment bonus
  const sqWords = norm.split(/\s+/).filter(Boolean);
  if (!sqWords.length) return null;

  let best = null, bestScore = 0;

  for (const r of results) {
    const dbNorm = normalizeName(r.name);
    const dbWords = dbNorm.split(/\s+/).filter(Boolean);
    if (!dbWords.length) continue;

    // Intersection / union (Jaccard)
    const sqSet  = new Set(sqWords);
    const dbSet  = new Set(dbWords);
    const intersect = [...sqSet].filter(w => dbSet.has(w)).length;
    const union     = new Set([...sqSet, ...dbSet]).size;
    const jaccard   = intersect / union;

    // Containment bonus: full normalized name appears inside the other
    const containment = (dbNorm.includes(norm) || norm.includes(dbNorm)) ? 0.2 : 0;

    const score = jaccard + containment;

    // Require at least 2 words matched for multi-word Square names,
    // 1 word for single-word names — prevents "Mini" matching "Mini Possum"
    // when you sold "Mini Loaf Cat"
    const minWordsRequired = sqWords.length === 1 ? 1 : 2;
    if (intersect < minWordsRequired) continue;

    if (score > bestScore && score >= 0.5) {
      bestScore = score;
      best = r;
    }
  }

  return best;
}

function normalizeName(s) {
  return (s || "")
    .toLowerCase()
    .replace(/[\u{1F300}-\u{1F9FF}\u2600-\u27BF\uFE0F]/gu, "")
    .replace(/[()\/,\-:~˚ʚ♡ɞ]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

// ═══════════════════════════════════════════════════════════
// NOTIFICATIONS
// ═══════════════════════════════════════════════════════════

async function checkAndNotify(env, item, ctx) {
  if (!env.GAS_EMAIL_URL) return;
  const roleKey = Object.keys(ROLES).find(k => ROLES[k].filter === item.crocheter);
  if (!roleKey || roleKey === "master" || roleKey === "ami") return;
  const profile = await env.DB.prepare("SELECT * FROM crocheters WHERE role = ?").bind(roleKey).first();
  if (!profile) return;
  const isSoldOut = item.on_hand <= 0;
  const isLow     = !isSoldOut && item.min_stock > 0 && item.on_hand < item.min_stock;
  if (isSoldOut && profile.notify_sold_out) {
    ctx.waitUntil(sendNotification(env, profile, `🌸 Amioki Alert: "${item.name}" is SOLD OUT! Time to crochet more ✿`));
  } else if (isLow && profile.notify_low_stock) {
    ctx.waitUntil(sendNotification(env, profile, `⚠️ Amioki Alert: "${item.name}" is running low — only ${item.on_hand} left (min: ${item.min_stock})`));
  }
}

async function sendNotification(env, profile, message) {
  const recipients = [];
  if (profile.notify_email && profile.email) {
    recipients.push({ type: "email", to: profile.email, subject: "Amioki Inventory Alert 🌸", body: message });
  }
  if (profile.notify_sms && profile.phone && profile.carrier) {
    const gateway = CARRIERS[profile.carrier.toLowerCase()];
    if (gateway) {
      const smsEmail = profile.phone.replace(/\D/g, "") + gateway;
      recipients.push({ type: "sms", to: smsEmail, subject: "Amioki", body: message });
    }
  }
  for (const r of recipients) {
    await sendViaGAS(env, r.to, r.subject, r.body);
  }
}

async function sendDailyDigests(env, override = false) {
  if (!env.GAS_EMAIL_URL) return { sent: 0, blocked: false };

  // ── Unmatched gate (skip when override=true) ──
  if (!override) {
    const { results: pending } = await env.DB.prepare(
      "SELECT COUNT(*) as n FROM unmatched_sales WHERE status = 'pending'"
    ).all();
    const unmatchedCount = pending[0]?.n || 0;
    if (unmatchedCount > 0) {
      const manualUrl = `https://amioki-inventory-api.amioki-co.workers.dev/?action=triggerDigest&secret=${encodeURIComponent(env.DIGEST_SECRET || "")}&override=true`;
      const today = new Date().toLocaleDateString("en-US", { weekday: "long", month: "long", day: "numeric", timeZone: "America/New_York" });
      const masterProfile = await env.DB.prepare("SELECT * FROM crocheters WHERE role = 'ami'").first();
      if (masterProfile?.email) {
        const html = buildWarningEmail(unmatchedCount, manualUrl, today);
        await sendViaGAS(env, masterProfile.email, `⚠️ Amioki Digest Paused — ${unmatchedCount} Unmatched Sale${unmatchedCount > 1 ? "s" : ""}`, html, true);
      }
      return { sent: 0, blocked: true, unmatched: unmatchedCount };
    }
  }

  const now  = new Date().toISOString();
  const today = new Date().toLocaleDateString("en-US", { weekday: "long", month: "long", day: "numeric", timeZone: "America/New_York" });

  const { results: crocheters } = await env.DB.prepare(
    "SELECT * FROM crocheters WHERE digest_enabled = 1"
  ).all();

  let sent = 0;
  // Track earliest "since" across all crocheters — used for Ami's master report
  let earliestSince = now;

  for (const c of crocheters) {
    if (!c.email) continue;
    const role = ROLES[c.role];
    if (!role || role.isMaster) continue; // Ami gets market report separately

    // ── Per-crocheter "since" window ──
    // Use last time we sent this crocheter's digest, falling back to 7 days
    // so a first-ever send still catches recent market history
    const state = await env.DB.prepare(
      "SELECT last_sent_at FROM digest_state WHERE crocheter_role = ?"
    ).bind(c.role).first();
    const since = state?.last_sent_at || new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();

    if (since < earliestSince) earliestSince = since;

    // ── Only this crocheter's item sales since last digest ──
    const { results: sales } = await env.DB.prepare(
      `SELECT sl.item_name, sl.qty, i.on_hand, i.min_stock
       FROM sales_log sl
       LEFT JOIN items i ON sl.item_id = i.id
       WHERE sl.timestamp >= ? AND sl.type = 'sale' AND i.crocheter = ?
       ORDER BY sl.timestamp DESC`
    ).bind(since, role.filter).all();

    // ── Silence if nothing sold for this crocheter since last digest ──
    if (!sales.length) continue;

    const grouped = {};
    sales.forEach(s => { grouped[s.item_name] = (grouped[s.item_name] || 0) + s.qty; });
    const totalSold = Object.values(grouped).reduce((a, b) => a + b, 0);

    const { results: alerts } = await env.DB.prepare(
      `SELECT name, on_hand, min_stock FROM items
       WHERE crocheter = ? AND archived = 0
       AND (on_hand = 0 OR (min_stock > 0 AND on_hand < min_stock))
       ORDER BY on_hand ASC`
    ).bind(role.filter).all();

    const html = buildDigestEmail(c.display_name, today, grouped, totalSold, alerts);
    await sendViaGAS(env, c.email, `🌸 Ami's Adopted Plushie Takeaway — ${today}`, html, true);

    // ── Update last_sent_at for this crocheter ──
    await env.DB.prepare(
      `INSERT INTO digest_state (crocheter_role, last_sent_at)
       VALUES (?, ?)
       ON CONFLICT(crocheter_role) DO UPDATE SET last_sent_at = excluded.last_sent_at`
    ).bind(c.role, now).run();

    sent++;
  }

  // ── Ami's master market report ──
  // Uses earliestSince so it covers the full window across all crocheters
  const masterProfile = await env.DB.prepare("SELECT * FROM crocheters WHERE role = 'ami'").first();
  if (masterProfile?.email) {
    // For Ami's own report use her personal last_sent_at, fallback to earliestSince
    const amiState = await env.DB.prepare(
      "SELECT last_sent_at FROM digest_state WHERE crocheter_role = 'ami'"
    ).first();
    const amiSince = amiState?.last_sent_at || earliestSince;

    const { results: allSales } = await env.DB.prepare(
      `SELECT sl.item_name, sl.qty, i.crocheter
       FROM sales_log sl
       LEFT JOIN items i ON sl.item_id = i.id
       WHERE sl.timestamp >= ? AND sl.type = 'sale'
       ORDER BY i.crocheter, sl.item_name`
    ).bind(amiSince).all();

    if (allSales.length) {
      const reportMap = {};
      allSales.forEach(s => {
        const key = `${s.item_name}||${s.crocheter || "Unknown"}`;
        if (!reportMap[key]) reportMap[key] = { item_name: s.item_name, crocheter: s.crocheter || "Unknown", qty: 0 };
        reportMap[key].qty += s.qty;
      });
      const reportRows = Object.values(reportMap).sort((a, b) =>
        (a.crocheter || "").localeCompare(b.crocheter || "") || a.item_name.localeCompare(b.item_name)
      );
      const totalSoldAll = reportRows.reduce((s, r) => s + r.qty, 0);
      const crochetTotals = {};
      reportRows.forEach(r => { crochetTotals[r.crocheter] = (crochetTotals[r.crocheter] || 0) + r.qty; });
      const html = buildMarketReport(today, reportRows, totalSoldAll, crochetTotals);
      await sendViaGAS(env, masterProfile.email, `🌸 Amioki Market Report — ${today}`, html, true);

      // Update Ami's last_sent_at
      await env.DB.prepare(
        `INSERT INTO digest_state (crocheter_role, last_sent_at)
         VALUES ('ami', ?)
         ON CONFLICT(crocheter_role) DO UPDATE SET last_sent_at = excluded.last_sent_at`
      ).bind(now).run();
    }
    // If no sales at all → no report, no update to last_sent_at (so next trigger still catches these sales)
  }

  return { sent, blocked: false };
}

async function sendTestDigest(env, params) {
  const role = (params.get("role") || "").toLowerCase();
  if (!role) return { ok: false, error: "role required" };
  const profile = await env.DB.prepare("SELECT * FROM crocheters WHERE role = ?").bind(role).first();
  if (!profile?.email) return { ok: false, error: "No email set for this crocheter" };
  const today = new Date().toLocaleDateString("en-US", { weekday: "long", month: "long", day: "numeric" });
  const sampleGrouped = { "Sample Plushie": 2, "Heart Keychain": 3 };
  const sampleAlerts = [{ name: "Baby Chicks", on_hand: 2, min_stock: 5 }, { name: "Axolotl (Pink)", on_hand: 0, min_stock: 10 }];
  const html = buildDigestEmail(profile.display_name, today, sampleGrouped, 5, sampleAlerts);
  await sendViaGAS(env, profile.email, `🌸 Test: Ami's Adopted Plushie Takeaway`, html, true);
  return { ok: true, message: `Test digest sent to ${profile.email}` };
}

function buildDigestEmail(name, today, grouped, totalSold, alerts) {
  const itemRows = Object.entries(grouped)
    .sort((a, b) => b[1] - a[1])
    .map(([item, qty]) => `
      <tr>
        <td style="padding:10px 16px;border-bottom:1px solid #FFE5F0;font-size:14px;color:#4A2540">${item}</td>
        <td style="padding:10px 16px;border-bottom:1px solid #FFE5F0;text-align:center;font-weight:700;font-size:14px;color:#E91E63">${qty}</td>
      </tr>`).join("");
  const soldOutItems = alerts.filter(a => a.on_hand <= 0);
  const lowItems     = alerts.filter(a => a.on_hand > 0 && a.min_stock > 0 && a.on_hand < a.min_stock);
  const soldOutSection = soldOutItems.length ? `
    <div style="background:#FFE5E5;border-radius:12px;padding:14px 16px;margin-top:16px">
      <div style="font-weight:700;color:#C2185B;margin-bottom:8px;font-size:13px">🚨 SOLD OUT — needs restocking:</div>
      ${soldOutItems.map(i => `<div style="font-size:13px;color:#4A2540;padding:3px 0">• ${i.name}</div>`).join("")}
    </div>` : "";
  const lowSection = lowItems.length ? `
    <div style="background:#FFF2A8;border-radius:12px;padding:14px 16px;margin-top:12px">
      <div style="font-weight:700;color:#8B6914;margin-bottom:8px;font-size:13px">⚠️ RUNNING LOW:</div>
      ${lowItems.map(i => `<div style="font-size:13px;color:#4A2540;padding:3px 0">• ${i.name} — ${i.on_hand} left (min ${i.min_stock})</div>`).join("")}
    </div>` : "";
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:0;background:#FFF5FA;font-family:'Helvetica Neue',Arial,sans-serif">
  <div style="max-width:520px;margin:0 auto;padding:24px 16px">
    <div style="background:linear-gradient(135deg,#FFB6D9,#FF8DC0);border-radius:24px;padding:28px 24px;text-align:center;margin-bottom:20px">
      <div style="font-size:32px;margin-bottom:8px">🌸</div>
      <div style="font-family:'Georgia',serif;font-size:22px;font-weight:700;color:white;letter-spacing:-0.5px">Ami's Adopted Plushie Takeaway</div>
      <div style="font-size:13px;color:rgba(255,255,255,0.85);margin-top:6px">${today}</div>
    </div>
    <div style="background:white;border-radius:20px;padding:20px 24px;box-shadow:0 4px 20px rgba(255,107,171,0.12);border:2px solid #FFE5F0;margin-bottom:16px">
      <div style="font-size:15px;color:#4A2540;margin-bottom:16px">Hey <strong>${name}</strong>! Here's what found new homes today 🧶</div>
      <table style="width:100%;border-collapse:collapse">
        <thead><tr style="background:#FFF5FA">
          <th style="padding:10px 16px;text-align:left;font-size:11px;color:#B894A8;text-transform:uppercase;letter-spacing:0.8px;font-weight:600">Item</th>
          <th style="padding:10px 16px;text-align:center;font-size:11px;color:#B894A8;text-transform:uppercase;letter-spacing:0.8px;font-weight:600">Sold</th>
        </tr></thead>
        <tbody>${itemRows}</tbody>
      </table>
      <div style="background:#FFF5FA;border-radius:12px;padding:12px 16px;margin-top:14px;text-align:center">
        <span style="font-size:13px;color:#8B5A75">Total today: </span>
        <span style="font-family:'Georgia',serif;font-size:20px;font-weight:700;color:#E91E63">${totalSold}</span>
        <span style="font-size:13px;color:#8B5A75"> plushie${totalSold !== 1 ? "s" : ""} adopted ✿</span>
      </div>
    </div>
    ${soldOutSection}${lowSection}
    <div style="text-align:center;padding:20px 0 8px;font-size:12px;color:#B894A8">
      Thank you for your work — every plushie matters! 🌸<br>
      <span style="color:#FFB6D9">— Ami & Amioki</span>
    </div>
  </div>
</body></html>`;
}

function buildWarningEmail(count, manualUrl, today) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="margin:0;padding:0;background:#FFF5FA;font-family:'Helvetica Neue',Arial,sans-serif">
  <div style="max-width:520px;margin:0 auto;padding:24px 16px">
    <div style="background:linear-gradient(135deg,#FFB6D9,#FF8DC0);border-radius:24px;padding:24px;text-align:center;margin-bottom:20px">
      <div style="font-size:28px;margin-bottom:6px">⚠️</div>
      <div style="font-size:18px;font-weight:700;color:white">Digest Paused</div>
      <div style="font-size:13px;color:rgba(255,255,255,0.85);margin-top:4px">${today}</div>
    </div>
    <div style="background:white;border-radius:20px;padding:20px 24px;box-shadow:0 4px 20px rgba(255,107,171,0.12);border:2px solid #FFE5F0;margin-bottom:16px">
      <p style="color:#4A2540;font-size:14px;margin-bottom:16px">
        Tonight's digest was <strong>not sent</strong> because there
        ${count === 1 ? "is" : "are"} <strong style="color:#E91E63">${count} unmatched sale${count > 1 ? "s" : ""}</strong>
        that need your attention first.
      </p>
      <p style="color:#8B5A75;font-size:13px;margin-bottom:20px">
        Go to the dashboard → Unmatched tab and resolve them, then tap the button below to send tonight's digest manually.
      </p>
      <div style="text-align:center">
        <a href="${manualUrl}" style="display:inline-block;background:linear-gradient(135deg,#FF8DC0,#FF6BAB);color:white;padding:14px 28px;border-radius:16px;font-weight:700;font-size:15px;text-decoration:none;box-shadow:0 4px 14px rgba(255,107,171,0.35)">
          🌸 Send Digest Now
        </a>
      </div>
      <p style="color:#B894A8;font-size:11px;text-align:center;margin-top:14px">This link expires after one use ✿</p>
    </div>
  </div>
</body></html>`;
}

function buildMarketReport(today, rows, totalSold, crochetTotals) {
  const crocheters = [...new Set(rows.map(r => r.crocheter))];
  const crochetBreakdown = crocheters.map(c => {
    const qty = crochetTotals[c] || 0;
    const emoji = { Ashley: "🧵", Liz: "🪡", Sydni: "🌷", Amioki: "🌸" }[c] || "✿";
    return `<div style="display:flex;justify-content:space-between;padding:8px 16px;border-bottom:1px solid #FFE5F0">
      <span style="font-size:14px;color:#4A2540">${emoji} ${c}</span>
      <span style="font-weight:700;color:#E91E63;font-size:14px">${qty} sold</span>
    </div>`;
  }).join("");
  const itemRows = rows.map(r =>
    `<tr>
      <td style="padding:8px 16px;border-bottom:1px solid #FFE5F0;font-size:13px;color:#4A2540">${r.item_name}</td>
      <td style="padding:8px 16px;border-bottom:1px solid #FFE5F0;font-size:13px;color:#8B5A75">${r.crocheter}</td>
      <td style="padding:8px 16px;border-bottom:1px solid #FFE5F0;text-align:center;font-weight:700;font-size:13px;color:#E91E63">${r.qty}</td>
    </tr>`
  ).join("");
  const csvLines = ["Item,Qty,Crocheter", ...rows.map(r => `"${r.item_name}",${r.qty},"${r.crocheter}"`)].join("\n");
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#FFF5FA;font-family:'Helvetica Neue',Arial,sans-serif">
<div style="max-width:560px;margin:0 auto;padding:24px 16px">
  <div style="background:linear-gradient(135deg,#FFB6D9,#FF8DC0);border-radius:24px;padding:28px 24px;text-align:center;margin-bottom:20px">
    <div style="font-size:32px;margin-bottom:8px">📊</div>
    <div style="font-family:Georgia,serif;font-size:22px;font-weight:700;color:white">Amioki Market Report</div>
    <div style="font-size:13px;color:rgba(255,255,255,0.85);margin-top:6px">${today}</div>
    <div style="margin-top:14px;display:inline-block;background:rgba(255,255,255,.25);padding:8px 20px;border-radius:12px">
      <span style="font-family:Georgia,serif;font-size:28px;font-weight:700;color:white">${totalSold}</span>
      <span style="font-size:13px;color:rgba(255,255,255,.9);margin-left:6px">plushies adopted ✿</span>
    </div>
  </div>
  <div style="background:white;border-radius:20px;overflow:hidden;border:2px solid #FFE5F0;box-shadow:0 4px 20px rgba(255,107,171,.12);margin-bottom:16px">
    <div style="background:#FFF5FA;padding:10px 16px;font-size:11px;font-weight:700;color:#B894A8;text-transform:uppercase;letter-spacing:.8px;border-bottom:2px solid #FFE5F0">By Crocheter</div>
    ${crochetBreakdown}
  </div>
  <div style="background:white;border-radius:20px;overflow:hidden;border:2px solid #FFE5F0;box-shadow:0 4px 20px rgba(255,107,171,.12);margin-bottom:16px">
    <div style="background:#FFF5FA;padding:10px 16px;font-size:11px;font-weight:700;color:#B894A8;text-transform:uppercase;letter-spacing:.8px;border-bottom:2px solid #FFE5F0">All Sales</div>
    <table style="width:100%;border-collapse:collapse">
      <thead><tr style="background:#FFF5FA">
        <th style="padding:8px 16px;text-align:left;font-size:11px;color:#B894A8;font-weight:600;text-transform:uppercase;letter-spacing:.5px">Item</th>
        <th style="padding:8px 16px;text-align:left;font-size:11px;color:#B894A8;font-weight:600;text-transform:uppercase;letter-spacing:.5px">Crocheter</th>
        <th style="padding:8px 16px;text-align:center;font-size:11px;color:#B894A8;font-weight:600;text-transform:uppercase;letter-spacing:.5px">Qty</th>
      </tr></thead>
      <tbody>${itemRows}</tbody>
    </table>
  </div>
  <div style="background:white;border-radius:20px;padding:18px 20px;border:2px solid #FFE5F0;box-shadow:0 4px 20px rgba(255,107,171,.12);margin-bottom:16px">
    <div style="font-size:11px;font-weight:700;color:#B894A8;text-transform:uppercase;letter-spacing:.8px;margin-bottom:10px">📋 Copy for Wayfinder</div>
    <pre style="background:#FFF5FA;border-radius:12px;padding:14px;font-size:12px;color:#4A2540;overflow-x:auto;white-space:pre;font-family:'Courier New',monospace;border:1px solid #FFE5F0;margin:0">${csvLines}</pre>
  </div>
  <div style="text-align:center;padding:16px 0 8px;font-size:12px;color:#B894A8">
    Generated automatically at 9pm ✿<br>
    <span style="color:#FFB6D9">— Amioki System</span>
  </div>
</div>
</body></html>`;
}

async function sendViaGAS(env, to, subject, body, isHtml = false) {
  if (!env.GAS_EMAIL_URL) return;
  try {
    await fetch(env.GAS_EMAIL_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ to, subject, body, isHtml })
    });
  } catch (e) {
    console.error("Email send failed:", e.message);
  }
}

// ═══════════════════════════════════════════════════════════
// UNMATCHED RESOLVE
// ═══════════════════════════════════════════════════════════

async function resolveUnmatched(env, params, ctx, who) {
  const id     = Number(params.get("id"));
  const choice = params.get("choice");
  if (!id || !choice) return { ok: false, error: "id and choice required" };
  const row = await env.DB.prepare("SELECT * FROM unmatched_sales WHERE id = ?").bind(id).first();
  if (!row) return { ok: false, error: "Not found" };
  if (row.status !== "pending") return { ok: false, error: "Already resolved" };

  if (choice === "ignore") {
    await env.DB.prepare("UPDATE unmatched_sales SET status = 'ignored', resolved_at = datetime('now') WHERE id = ?").bind(id).run();
    return { ok: true };
  }
  if (choice === "link") {
    const itemId = Number(params.get("itemId"));
    if (!itemId) return { ok: false, error: "itemId required" };
    const item = await env.DB.prepare("SELECT * FROM items WHERE id = ?").bind(itemId).first();
    if (!item) return { ok: false, error: "Item not found" };
    if (row.square_catalog_id && !item.square_catalog_id) {
      await env.DB.prepare("UPDATE items SET square_catalog_id = ? WHERE id = ?").bind(row.square_catalog_id, itemId).run();
    }
    const newQty = Math.max(0, item.on_hand - row.qty);
    await env.DB.batch([
      env.DB.prepare("UPDATE items SET on_hand = ?, updated_at = ? WHERE id = ?").bind(newQty, new Date().toISOString(), itemId),
      env.DB.prepare(`INSERT INTO sales_log (item_id, item_name, qty, type, square_payment_id, note) VALUES (?, ?, ?, ?, ?, ?)`)
        .bind(itemId, item.name, row.qty, "sale", row.square_payment_id, "Linked from unmatched"),
      env.DB.prepare("UPDATE unmatched_sales SET status = 'resolved', resolution = 'Linked', resolved_at = datetime('now') WHERE id = ?").bind(id)
    ]);
    await checkAndArchive(env, { ...item, on_hand: newQty }, ctx);
    await checkAndNotify(env, { ...item, on_hand: newQty }, ctx);
    ctx.waitUntil(auditLog(env, { action: "resolve_link", item: item.name, qty: -row.qty, note: "Linked from unmatched" }));
    ctx.waitUntil(sweepUnmatched(env, row.square_name, row.square_catalog_id, itemId, ctx));
    return { ok: true, newQty };
  }
  if (choice === "create") {
    const crocheter = params.get("crocheter") || "Amioki";
    const ins = await env.DB.prepare(
      `INSERT INTO items (name, crocheter, on_hand, square_catalog_id) VALUES (?, ?, ?, ?)`
    ).bind(row.square_name, crocheter, 0, row.square_catalog_id || "").run();
    const newId = ins.meta.last_row_id;
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO sales_log (item_id, item_name, qty, type, square_payment_id, note) VALUES (?, ?, ?, ?, ?, ?)`)
        .bind(newId, row.square_name, row.qty, "sale", row.square_payment_id, "Created from unmatched"),
      env.DB.prepare("UPDATE unmatched_sales SET status = 'resolved', resolution = 'Created', resolved_at = datetime('now') WHERE id = ?").bind(id)
    ]);
    ctx.waitUntil(auditLog(env, { action: "resolve_create", item: row.square_name, qty: -row.qty, note: "Created from unmatched" }));
    ctx.waitUntil(sweepUnmatched(env, row.square_name, row.square_catalog_id, newId, ctx));
    return { ok: true, newId };
  }
  return { ok: false, error: "Unknown choice" };
}

// ═══════════════════════════════════════════════════════════
// REBUILD DIAGNOSTIC
// ═══════════════════════════════════════════════════════════

async function rebuildInventory(env) {
  const items = (await env.DB.prepare("SELECT * FROM items").all()).results;
  const report = [];
  for (const it of items) {
    const { results } = await env.DB.prepare(
      "SELECT type, SUM(qty) AS total FROM sales_log WHERE item_id = ? GROUP BY type"
    ).bind(it.id).all();
    const byType = {};
    results.forEach(r => byType[r.type] = r.total);
    report.push({ name: it.name, crocheter: it.crocheter, on_hand: it.on_hand, ...byType });
  }
  return { ok: true, report };
}

// ═══════════════════════════════════════════════════════════
// DEDUP
// ═══════════════════════════════════════════════════════════

async function isDup(env, key) {
  return !!(await env.DB.prepare("SELECT 1 FROM dedup WHERE key = ?").bind(key).first());
}
async function markDup(env, key) {
  await env.DB.prepare("INSERT OR IGNORE INTO dedup (key) VALUES (?)").bind(key).run();
  if (Math.random() < 0.01) {
    await env.DB.prepare("DELETE FROM dedup WHERE created_at < datetime('now', '-1 day')").run();
  }
}

// ═══════════════════════════════════════════════════════════
// AUDIT LOG
// ═══════════════════════════════════════════════════════════

async function auditLog(env, entry) {
  if (!env.GAS_EMAIL_URL) return;
  try {
    await fetch(env.GAS_EMAIL_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ _audit: true, timestamp: new Date().toISOString(), ...entry })
    });
  } catch (e) { console.error("Audit log failed:", e.message); }
}

// ═══════════════════════════════════════════════════════════
// PIECE RATES
// ═══════════════════════════════════════════════════════════

async function getPieceRates(env, crocheter) {
  if (crocheter) {
    const { results } = await env.DB.prepare(
      "SELECT * FROM piece_rates WHERE crocheter = ? ORDER BY item_name"
    ).bind(crocheter).all();
    return results;
  }
  const { results } = await env.DB.prepare("SELECT * FROM piece_rates ORDER BY crocheter, item_name").all();
  return results;
}

async function updatePieceRate(env, params) {
  const id = Number(params.get("id"));
  const crocheter = params.get("crocheter") || "";
  const itemName  = params.get("item_name") || "";
  if (!crocheter || !itemName) return { ok: false, error: "crocheter and item_name required" };
  const patch = {};
  ["labor_rate", "material_cost", "total_rate", "time_min"].forEach(k => {
    const v = params.get(k); if (v !== null && v !== "") patch[k] = Number(v);
  });
  ["notes"].forEach(k => {
    const v = params.get(k); if (v !== null) patch[k] = v;
  });
  patch.updated_at = new Date().toISOString();
  if (id) {
    const fields = Object.keys(patch).map(k => `${k} = ?`).join(", ");
    await env.DB.prepare(`UPDATE piece_rates SET ${fields} WHERE id = ?`)
      .bind(...Object.values(patch), id).run();
  } else {
    await env.DB.prepare(
      `INSERT INTO piece_rates (crocheter, item_name, labor_rate, material_cost, total_rate, time_min, notes)
       VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(crocheter, item_name) DO UPDATE SET
       labor_rate=excluded.labor_rate, material_cost=excluded.material_cost,
       total_rate=excluded.total_rate, time_min=excluded.time_min, notes=excluded.notes, updated_at=excluded.updated_at`
    ).bind(crocheter, itemName, patch.labor_rate || 0, patch.material_cost || 0,
      patch.total_rate || 0, patch.time_min || 0, patch.notes || "").run();
  }
  return { ok: true };
}

// ═══════════════════════════════════════════════════════════
// CONTRACTS
// ═══════════════════════════════════════════════════════════

async function parseContractPDF(env, params) {
  const pdfText  = params.get("pdfText")  || "";
  const crocheter = params.get("crocheter") || "";
  if (!pdfText)   return { ok: false, error: "pdfText required" };
  if (!crocheter) return { ok: false, error: "crocheter required" };
  const prompt = `You are parsing an Amioki contractor agreement PDF. Extract the following and return ONLY valid JSON, no other text:

1. due_date: the project end/due date (string, e.g. "May 31st, 2026")
2. total_items: total number of items (integer)
3. total_value: total dollar amount (number)
4. hourly_rate: hourly rate mentioned (number, default 13.00)
5. margin_of_error: size margin mentioned (string, e.g. "±0.30 inch")
6. items: array of objects, each with:
   - item_name: string
   - qty_needed: integer (ONLY items where qty > 0)
   - piece_rate: total piece rate as number (labor + material)
   - labor_rate: labor portion as number
   - material_cost: material portion as number
   - line_total: qty * piece_rate as number

Contract text:
${pdfText.substring(0, 6000)}

Return ONLY this JSON structure:
{
  "due_date": "",
  "total_items": 0,
  "total_value": 0,
  "hourly_rate": 13.00,
  "margin_of_error": "±0.30 inch",
  "items": []
}`;
  try {
    const resp = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": env.ANTHROPIC_API_KEY || "",
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-20250514",
        max_tokens: 2000,
        messages: [{ role: "user", content: prompt }]
      })
    });
    const data = await resp.json();
    const raw  = data.content?.[0]?.text || "";
    const clean = raw.replace(/```json|```/g, "").trim();
    const parsed = JSON.parse(clean);
    return { ok: true, parsed, crocheter };
  } catch (err) {
    return { ok: false, error: "Parse failed: " + err.message };
  }
}

async function saveContract(env, params, ctx) {
  const crocheter     = params.get("crocheter") || "";
  const crochetersName = params.get("crocheter_name") || crocheter;
  const dueDate       = params.get("due_date")       || "";
  const totalItems    = Number(params.get("total_items"))  || 0;
  const totalValue    = Number(params.get("total_value"))  || 0;
  const hourlyRate    = Number(params.get("hourly_rate"))  || 13.00;
  const marginOfError = params.get("margin_of_error") || "±0.30 inch";
  const itemsJson     = params.get("items") || "[]";
  if (!crocheter) return { ok: false, error: "crocheter required" };
  let items;
  try { items = JSON.parse(itemsJson); } catch { return { ok: false, error: "Invalid items JSON" }; }
  await env.DB.prepare(
    "UPDATE contracts SET status = 'completed' WHERE crocheter = ? AND status = 'active'"
  ).bind(crocheter).run();
  const result = await env.DB.prepare(
    `INSERT INTO contracts (crocheter, crocheter_name, total_items, total_value, due_date, margin_of_error, hourly_rate)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(crocheter, crochetersName, totalItems, totalValue, dueDate, marginOfError, hourlyRate).run();
  const contractId = result.meta.last_row_id;
  for (const item of items) {
    if (!item.item_name || !item.qty_needed) continue;
    await env.DB.prepare(
      `INSERT INTO contract_items (contract_id, item_name, qty_needed, piece_rate, labor_rate, material_cost, line_total)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(contractId, item.item_name, item.qty_needed, item.piece_rate || 0,
      item.labor_rate || 0, item.material_cost || 0, item.line_total || 0).run();
  }
  ctx.waitUntil(auditLog(env, {
    action: "contract_saved", item: crochetersName, qty: totalItems,
    note: `Contract saved. Due: ${dueDate}. Total: $${totalValue}`
  }));
  return { ok: true, contractId };
}

async function getAllContracts(env) {
  const { results: contracts } = await env.DB.prepare(
    "SELECT * FROM contracts ORDER BY uploaded_at DESC"
  ).all();
  for (const c of contracts) {
    const { results: items } = await env.DB.prepare(
      "SELECT * FROM contract_items WHERE contract_id = ? ORDER BY item_name"
    ).bind(c.id).all();
    c.items = items;
    c.progress_pct = c.total_items > 0
      ? Math.round((items.reduce((s, i) => s + i.qty_delivered, 0) / c.total_items) * 100)
      : 0;
  }
  return contracts;
}

async function getMyActiveContract(env, who) {
  const role = ROLES[who];
  const crocheter = role?.filter || who;
  const contract = await env.DB.prepare(
    "SELECT * FROM contracts WHERE crocheter = ? AND status = 'active' ORDER BY uploaded_at DESC LIMIT 1"
  ).bind(who).first() ||
  await env.DB.prepare(
    "SELECT * FROM contracts WHERE crocheter_name = ? AND status = 'active' ORDER BY uploaded_at DESC LIMIT 1"
  ).bind(crocheter).first();
  if (!contract) return null;
  const { results: items } = await env.DB.prepare(
    "SELECT * FROM contract_items WHERE contract_id = ? ORDER BY item_name"
  ).bind(contract.id).all();
  contract.items = items;
  return contract;
}

async function updateContractItem(env, params) {
  const id = Number(params.get("id"));
  if (!id) return { ok: false, error: "id required" };
  const patch = {};
  ["color_notes", "qty_needed"].forEach(k => {
    const v = params.get(k);
    if (v !== null) patch[k] = k === "qty_needed" ? Number(v) : v;
  });
  if (!Object.keys(patch).length) return { ok: false, error: "Nothing to update" };
  const fields = Object.keys(patch).map(k => `${k} = ?`).join(", ");
  await env.DB.prepare(`UPDATE contract_items SET ${fields} WHERE id = ?`)
    .bind(...Object.values(patch), id).run();
  return { ok: true };
}

// ═══════════════════════════════════════════════════════════
// PRODUCTION LOGS
// ═══════════════════════════════════════════════════════════

async function logProduction(env, params, who, ctx) {
  const role = ROLES[who];
  const crocheter      = who;
  const crochetersName = role?.label || who;
  const itemsJson      = params.get("items") || "[]";
  const notes          = params.get("notes") || "";
  let items;
  try { items = JSON.parse(itemsJson); } catch { return { ok: false, error: "Invalid items JSON" }; }
  if (!items.length) return { ok: false, error: "No items provided" };

  const contract = await env.DB.prepare(
    "SELECT * FROM contracts WHERE (crocheter = ? OR crocheter_name = ?) AND status = 'active' LIMIT 1"
  ).bind(crocheter, crochetersName).first();

  let contractItems = [];
  if (contract) {
    const { results } = await env.DB.prepare(
      "SELECT * FROM contract_items WHERE contract_id = ?"
    ).bind(contract.id).all();
    contractItems = results;
  }

  let payEstimated = 0;
  const enrichedItems = [];

  for (const item of items) {
    const qty = Number(item.qty) || 0;
    if (!qty) continue;
    const rate = await env.DB.prepare(
      "SELECT total_rate FROM piece_rates WHERE crocheter = ? AND item_name = ? COLLATE NOCASE"
    ).bind(crochetersName, item.item_name).first() ||
    await env.DB.prepare(
      "SELECT total_rate FROM piece_rates WHERE crocheter = ? AND item_name LIKE ? COLLATE NOCASE"
    ).bind(crochetersName, `%${item.item_name.split(" ")[0]}%`).first();
    const contractRate = contractItems.find(ci =>
  ci.item_name.toLowerCase().includes(item.item_name.toLowerCase()) ||
  item.item_name.toLowerCase().includes(ci.item_name.toLowerCase())
)?.piece_rate || 0;
const pieceRate = rate?.total_rate || contractRate || 0;
    payEstimated += pieceRate * qty;
    const contractItem = contractItems.find(ci =>
      ci.item_name.toLowerCase().includes(item.item_name.toLowerCase()) ||
      item.item_name.toLowerCase().includes(ci.item_name.toLowerCase())
    );
    enrichedItems.push({
      item_name:        item.item_name,
      qty_logged:       qty,
      is_contract:      contractItem ? 1 : (item.is_contract === false ? 0 : 1),
      contract_item_id: contractItem?.id || null,
      piece_rate:       pieceRate,
      color_notes:      item.color_notes || "",
      status:           "pending"
    });
  }

  const logResult = await env.DB.prepare(
    `INSERT INTO production_logs (crocheter, crocheter_name, contract_id, notes, pay_estimated, status)
     VALUES (?, ?, ?, ?, ?, 'pending')`
  ).bind(crocheter, crochetersName, contract?.id || null, notes, payEstimated).run();
  const logId = logResult.meta.last_row_id;

  for (const item of enrichedItems) {
    await env.DB.prepare(
      `INSERT INTO production_items (log_id, item_name, qty_logged, is_contract, contract_item_id, piece_rate, color_notes, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')`
    ).bind(logId, item.item_name, item.qty_logged, item.is_contract,
      item.contract_item_id, item.piece_rate, item.color_notes).run();
  }

  ctx.waitUntil(auditLog(env, {
    action: "production_logged", item: crochetersName,
    qty: enrichedItems.reduce((s, i) => s + i.qty_logged, 0),
    note: `Batch #${logId} logged. Est. pay: $${payEstimated.toFixed(2)}`
  }));
  return { ok: true, logId, payEstimated: payEstimated.toFixed(2), itemCount: enrichedItems.length };
}

async function getMyBatches(env, who) {
  const { results: logs } = await env.DB.prepare(
    "SELECT * FROM production_logs WHERE crocheter = ? ORDER BY created_at DESC LIMIT 20"
  ).bind(who).all();
  for (const log of logs) {
    const { results: items } = await env.DB.prepare(
      "SELECT * FROM production_items WHERE log_id = ?"
    ).bind(log.id).all();
    log.items = items;
    const qc = await env.DB.prepare(
      "SELECT id, submitted_at, name_signed FROM qc_submissions WHERE log_id = ?"
    ).bind(log.id).first();
    log.qc = qc || null;
  }
  return logs;
}

async function getAllPendingBatches(env) {
  const { results: logs } = await env.DB.prepare(
    `SELECT pl.*, c.due_date, c.margin_of_error
     FROM production_logs pl
     LEFT JOIN contracts c ON pl.contract_id = c.id
     ORDER BY pl.created_at DESC`
  ).all();
  for (const log of logs) {
    const { results: items } = await env.DB.prepare(
      "SELECT * FROM production_items WHERE log_id = ?"
    ).bind(log.id).all();
    log.items = items;
    const qc = await env.DB.prepare(
      "SELECT * FROM qc_submissions WHERE log_id = ?"
    ).bind(log.id).first();
    log.qc = qc || null;
  }
  return logs;
}

// ─────────────────────────────────────────────────────────
// ✅ PATCHED: approveBatch
//    Fix 4 — Exact inventory match first, then full-word Jaccard fuzzy
//             (never first-word-only LIKE). Removed the `%first_word%`
//             pattern that caused Mini Loaf Cat → wrong item.
//    Fix 5 — Only update qty_delivered on contract item when inventory
//             match is found. Previously it updated contract progress even
//             when inventory was silently skipped.
// ─────────────────────────────────────────────────────────
async function approveBatch(env, params, ctx) {
  const logId = Number(params.get("log_id"));
  if (!logId) return { ok: false, error: "log_id required" };

  const decisionsJson = params.get("decisions") || "[]";
  let decisions;
  try { decisions = JSON.parse(decisionsJson); } catch { return { ok: false, error: "Invalid decisions JSON" }; }

  const log = await env.DB.prepare("SELECT * FROM production_logs WHERE id = ?").bind(logId).first();
  if (!log) return { ok: false, error: "Batch not found" };

  let payApproved = 0;
  let allDone     = true;

  for (const d of decisions) {
    const itemId      = Number(d.item_id);
    const status      = d.status || "approved";
    const adjPct      = Number(d.adjustment_pct) || (status === "rejected" ? 0 : 100);
    const qtyApproved = Number(d.qty_approved) || 0;
    const reason      = d.rejection_reason || "";

    await env.DB.prepare(
      `UPDATE production_items SET status = ?, adjustment_pct = ?, qty_approved = ?,
       rejection_reason = ? WHERE id = ? AND log_id = ?`
    ).bind(status, adjPct, qtyApproved, reason, itemId, logId).run();

    const item = await env.DB.prepare("SELECT * FROM production_items WHERE id = ?").bind(itemId).first();
    if (item && status !== "rejected") {
      payApproved += item.piece_rate * qtyApproved * (adjPct / 100);
    }
    if (status === "pending") allDone = false;
  }

  // Process approved items
  const { results: approvedItems } = await env.DB.prepare(
    "SELECT * FROM production_items WHERE log_id = ? AND status != 'rejected'"
  ).bind(logId).all();

  const now = new Date().toISOString();

  for (const item of approvedItems) {
    const qtyToAdd = item.qty_approved || item.qty_logged;
    const normTarget = (item.item_name || "").toLowerCase().trim();

    // Step 1: exact normalized match
    let invItem = null;
    const { results: allActive } = await env.DB.prepare(
      "SELECT id, on_hand, name FROM items WHERE archived = 0"
    ).all();

    invItem = allActive.find(r => r.name.toLowerCase().trim() === normTarget) || null;

    // Step 2: Jaccard fuzzy (same logic as matchItem — no first-word-only)
    if (!invItem) {
      const sqWords = normTarget.split(/\s+/).filter(Boolean);
      let bestScore = 0;
      for (const r of allActive) {
        const dbNorm  = r.name.toLowerCase().trim();
        const dbWords = dbNorm.split(/\s+/).filter(Boolean);
        const sqSet   = new Set(sqWords);
        const dbSet   = new Set(dbWords);
        const intersect = [...sqSet].filter(w => dbSet.has(w)).length;
        const union     = new Set([...sqSet, ...dbSet]).size;
        const jaccard   = intersect / union;
        const containment = (dbNorm.includes(normTarget) || normTarget.includes(dbNorm)) ? 0.2 : 0;
        const score = jaccard + containment;
        const minWordsRequired = sqWords.length === 1 ? 1 : 2;
        if (intersect < minWordsRequired) continue;
        if (score > bestScore && score >= 0.5) { bestScore = score; invItem = r; }
      }
    }

    if (invItem) {
      // Inventory match found — update stock AND contract progress
      const newQty = invItem.on_hand + qtyToAdd;
      await env.DB.batch([
        env.DB.prepare("UPDATE items SET on_hand = ?, updated_at = ? WHERE id = ?")
          .bind(newQty, now, invItem.id),
        env.DB.prepare(
          `INSERT INTO sales_log (item_id, item_name, qty, type, note) VALUES (?, ?, ?, 'adjust', ?)`
        ).bind(invItem.id, item.item_name, qtyToAdd, `Approved batch #${logId}`)
      ]);

      // Fix 5: only credit contract delivery when inventory actually updated
      if (item.contract_item_id) {
        await env.DB.prepare(
          "UPDATE contract_items SET qty_delivered = qty_delivered + ? WHERE id = ?"
        ).bind(qtyToAdd, item.contract_item_id).run();
      }
    } else {
      // No match — audit it, do NOT update contract progress
      ctx.waitUntil(auditLog(env, {
        action: "batch_approve_no_inv_match",
        item: item.item_name,
        qty: qtyToAdd,
        note: `Batch #${logId}: no inventory item matched "${item.item_name}" — stock NOT updated, contract NOT credited`
      }));
    }

    // Fire delivery log regardless (records that crocheter produced it)
    ctx.waitUntil(logDelivery(env, {
      timestamp: now,
      crocheter: log.crocheter_name,
      item_name: item.item_name,
      qty: qtyToAdd,
      method: item.is_contract ? "batch" : "non-contract",
      contract_id: log.contract_id || "",
      notes: `Batch #${logId}${invItem ? "" : " ⚠️ no inv match"}`,
      contract_status: log.contract_id ? "active" : "",
      contract_due_date: log.due_date || ""
    }));
  }

  const newStatus = allDone ? "approved" : "partial";
  await env.DB.prepare(
    "UPDATE production_logs SET status = ?, pay_approved = ?, approved_at = ? WHERE id = ?"
  ).bind(newStatus, payApproved, now, logId).run();

  ctx.waitUntil(auditLog(env, {
    action: "batch_approved", item: log.crocheter_name, qty: approvedItems.length,
    note: `Batch #${logId} ${newStatus}. Pay: $${payApproved.toFixed(2)}`
  }));

  return { ok: true, status: newStatus, payApproved: payApproved.toFixed(2) };
}

// ═══════════════════════════════════════════════════════════
// QC
// ═══════════════════════════════════════════════════════════

async function submitQC(env, params, who) {
  const logId = Number(params.get("log_id"));
  if (!logId) return { ok: false, error: "log_id required" };
  const log = await env.DB.prepare("SELECT * FROM production_logs WHERE id = ?").bind(logId).first();
  if (!log) return { ok: false, error: "Batch not found" };
  if (log.crocheter !== who) return { ok: false, error: "Not your batch" };
  const checks = {
    fluff_stuff:        Number(params.get("fluff_stuff"))        || 0,
    perfectly_puffed:   Number(params.get("perfectly_puffed"))   || 0,
    shape_of_cuteness:  Number(params.get("shape_of_cuteness"))  || 0,
    smooth_as_butter:   Number(params.get("smooth_as_butter"))   || 0,
    hug_friendly:       Number(params.get("hug_friendly"))       || 0,
    snuggle_safe:       Number(params.get("snuggle_safe"))       || 0,
    color_pop:          Number(params.get("color_pop"))          || 0,
    durability_darling: Number(params.get("durability_darling")) || 0,
    kawaii_harmony:     Number(params.get("kawaii_harmony"))     || 0
  };
  const nameSigned    = params.get("name_signed")    || "";
  const dateSigned    = params.get("date_signed")    || "";
  const signatureData = params.get("signature_data") || "";
  await env.DB.prepare(
    `INSERT OR REPLACE INTO qc_submissions
     (log_id, crocheter, fluff_stuff, perfectly_puffed, shape_of_cuteness,
      smooth_as_butter, hug_friendly, snuggle_safe, color_pop, durability_darling,
      kawaii_harmony, name_signed, date_signed, signature_data)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(logId, who, checks.fluff_stuff, checks.perfectly_puffed, checks.shape_of_cuteness,
    checks.smooth_as_butter, checks.hug_friendly, checks.snuggle_safe, checks.color_pop,
    checks.durability_darling, checks.kawaii_harmony, nameSigned, dateSigned, signatureData).run();
  await env.DB.prepare("UPDATE production_logs SET qc_submitted = 1 WHERE id = ?").bind(logId).run();
  return { ok: true };
}

async function signQCClient(env, params) {
  const logId = Number(params.get("log_id"));
  if (!logId) return { ok: false, error: "log_id required" };
  await env.DB.prepare(
    `UPDATE qc_submissions SET client_name_signed = ?, client_date_signed = ?, client_signature_data = ?
     WHERE log_id = ?`
  ).bind(
    params.get("client_name_signed") || "",
    params.get("client_date_signed") || "",
    params.get("client_signature_data") || "",
    logId
  ).run();
  return { ok: true };
}

async function getQC(env, params) {
  const logId = Number(params.get("log_id"));
  if (!logId) return null;
  return await env.DB.prepare("SELECT * FROM qc_submissions WHERE log_id = ?").bind(logId).first();
}

// ═══════════════════════════════════════════════════════════
// MANUAL DELIVERY
// ═══════════════════════════════════════════════════════════

async function manualDelivery(env, params, ctx) {
  const contractItemId = Number(params.get("contract_item_id"));
  const qty   = Number(params.get("qty")) || 0;
  const notes = params.get("notes") || "";
  if (!contractItemId || !qty) return { ok: false, error: "contract_item_id and qty required" };

  const ci = await env.DB.prepare(
    "SELECT ci.*, c.crocheter_name, c.crocheter, c.id as cid FROM contract_items ci JOIN contracts c ON ci.contract_id = c.id WHERE ci.id = ?"
  ).bind(contractItemId).first();
  if (!ci) return { ok: false, error: "Contract item not found" };

  const now = new Date().toISOString();
  await env.DB.prepare("UPDATE contract_items SET qty_delivered = qty_delivered + ? WHERE id = ?")
    .bind(qty, contractItemId).run();

  const updateInventory = params.get("update_inventory") !== "0";

  // Exact match first, then Jaccard fuzzy — never first-word-only LIKE
  const normTarget = (ci.item_name || "").toLowerCase().trim();
  const { results: allActiveItems } = await env.DB.prepare(
    "SELECT id, on_hand, name FROM items WHERE archived = 0"
  ).all();
  let invItem = allActiveItems.find(r => r.name.toLowerCase().trim() === normTarget) || null;
  if (!invItem) {
    const sqWords = normTarget.split(/\s+/).filter(Boolean);
    let bestScore = 0;
    for (const r of allActiveItems) {
      const dbNorm  = r.name.toLowerCase().trim();
      const dbWords = dbNorm.split(/\s+/).filter(Boolean);
      const intersect = sqWords.filter(w => new Set(dbWords).has(w)).length;
      const union     = new Set([...sqWords, ...dbWords]).size;
      const jaccard   = intersect / union;
      const contain   = (dbNorm.includes(normTarget) || normTarget.includes(dbNorm)) ? 0.2 : 0;
      const score     = jaccard + contain;
      const minW      = sqWords.length === 1 ? 1 : 2;
      if (intersect < minW) continue;
      if (score > bestScore && score >= 0.5) { bestScore = score; invItem = r; }
    }
  }

  if (invItem && updateInventory) {
    const newQty = invItem.on_hand + qty;
    await env.DB.batch([
      env.DB.prepare("UPDATE items SET on_hand = ?, updated_at = ? WHERE id = ?").bind(newQty, now, invItem.id),
      env.DB.prepare("INSERT INTO sales_log (item_id, item_name, qty, type, note) VALUES (?, ?, ?, 'adjust', ?)")
        .bind(invItem.id, ci.item_name, qty, `Manual delivery — Contract #${ci.cid}${notes ? ": " + notes : ""}`)
    ]);
  }

  const contractInfo = ci.cid
    ? await env.DB.prepare("SELECT status, due_date FROM contracts WHERE id = ?").bind(ci.cid).first()
    : null;

  ctx.waitUntil(logDelivery(env, {
    timestamp: now, crocheter: ci.crocheter_name, item_name: ci.item_name, qty,
    method: "manual", contract_id: ci.cid, notes,
    contract_status: contractInfo?.status || "active",
    contract_due_date: contractInfo?.due_date || ""
  }));
  ctx.waitUntil(auditLog(env, {
    action: "manual_delivery", item: ci.item_name, qty,
    note: `Manual delivery by ${ci.crocheter_name}. Contract #${ci.cid}`
  }));
  return { ok: true, inventoryUpdated: !!invItem };
}

// ═══════════════════════════════════════════════════════════
// CONTRACT LIFECYCLE
// ═══════════════════════════════════════════════════════════

async function deleteContract(env, params, ctx) {
  const id = Number(params.get("id"));
  if (!id) return { ok: false, error: "id required" };
  const c = await env.DB.prepare("SELECT * FROM contracts WHERE id = ?").bind(id).first();
  if (!c) return { ok: false, error: "Contract not found" };
  await env.DB.prepare("DELETE FROM contracts WHERE id = ?").bind(id).run();
  ctx.waitUntil(auditLog(env, { action: "contract_deleted", item: c.crocheter_name, qty: 0, note: `Contract #${id} deleted` }));
  return { ok: true };
}

async function completeContract(env, params, ctx) {
  const id = Number(params.get("id"));
  if (!id) return { ok: false, error: "id required" };
  const now = new Date().toISOString();
  await env.DB.prepare("UPDATE contracts SET status = 'completed', completed_at = ? WHERE id = ?").bind(now, id).run();
  ctx.waitUntil(auditLog(env, { action: "contract_completed", item: "", qty: 0, note: `Contract #${id} marked complete` }));
  return { ok: true };
}

async function archiveContract(env, params, ctx) {
  const id = Number(params.get("id"));
  if (!id) return { ok: false, error: "id required" };
  const c = await env.DB.prepare("SELECT * FROM contracts WHERE id = ?").bind(id).first();
  if (!c) return { ok: false, error: "Contract not found" };
  const now = new Date().toISOString();
  await env.DB.prepare(
    `INSERT OR REPLACE INTO archived_contracts (original_id, crocheter, crocheter_name, total_items, total_value, hourly_rate, started_at, completed_at, archived_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, c.crocheter, c.crocheter_name, c.total_items, c.total_value,
    c.hourly_rate, c.uploaded_at, c.completed_at || now, now).run();
  await env.DB.prepare("DELETE FROM contracts WHERE id = ?").bind(id).run();
  ctx.waitUntil(auditLog(env, { action: "contract_archived", item: c.crocheter_name, qty: 0, note: `Contract #${id} archived` }));
  return { ok: true };
}

// ═══════════════════════════════════════════════════════════
// DELIVERY LOG
// ═══════════════════════════════════════════════════════════

async function logDelivery(env, entry) {
  if (!env.GAS_EMAIL_URL) return;
  try {
    await fetch(env.GAS_EMAIL_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ _delivery_log: true, ...entry })
    });
  } catch (e) { console.error("Delivery log failed:", e.message); }
}

// ─────────────────────────────────────────────────────────
// ✅ PATCHED: sweepUnmatched
//    Fix 6 — Per-iteration try/catch so a single failure doesn't
//             leave the DB half-updated and local on_hand stale
// ─────────────────────────────────────────────────────────
async function sweepUnmatched(env, squareName, squareCatalogId, itemId, ctx) {
  const { results: dupes } = await env.DB.prepare(
    `SELECT * FROM unmatched_sales
     WHERE status = 'pending'
     AND (
       (square_name = ? AND ? != '')
       OR (square_catalog_id = ? AND square_catalog_id != '' AND ? != '')
     )`
  ).bind(squareName, squareName, squareCatalogId || "", squareCatalogId || "").all();
  if (!dupes.length) return;

  // Re-fetch item fresh to get accurate on_hand after any prior updates
  let item = await env.DB.prepare("SELECT * FROM items WHERE id = ?").bind(itemId).first();
  if (!item) return;

  for (const dupe of dupes) {
    try {
      const qty    = dupe.qty || 1;
      const newQty = Math.max(0, item.on_hand - qty);

      await env.DB.batch([
        env.DB.prepare("UPDATE items SET on_hand = ?, updated_at = ? WHERE id = ?")
          .bind(newQty, new Date().toISOString(), itemId),
        env.DB.prepare(
          `INSERT INTO sales_log (item_id, item_name, qty, type, square_payment_id, note)
           VALUES (?, ?, ?, 'sale', ?, ?)`
        ).bind(itemId, item.name, qty, dupe.square_payment_id, "Auto-resolved from unmatched sweep"),
        env.DB.prepare(
          `UPDATE unmatched_sales SET status = 'resolved', resolution = 'Auto-swept', resolved_at = datetime('now') WHERE id = ?`
        ).bind(dupe.id)
      ]);

      // Re-fetch to keep on_hand accurate for next iteration
      item = await env.DB.prepare("SELECT * FROM items WHERE id = ?").bind(itemId).first();
      if (!item) break;

      if (squareCatalogId && !item.square_catalog_id) {
        await env.DB.prepare("UPDATE items SET square_catalog_id = ? WHERE id = ?")
          .bind(squareCatalogId, itemId).run();
        item = { ...item, square_catalog_id: squareCatalogId };
      }

      await auditLog(env, {
        action: "auto_sweep", item: item.name, qty: -qty,
        note: `Auto-resolved duplicate unmatched "${dupe.square_name}" → ${item.name}`
      });
    } catch (err) {
      // Log the failure but continue processing remaining dupes
      await auditLog(env, {
        action: "auto_sweep_error", item: item?.name || "unknown", qty: 0,
        note: `Sweep failed for unmatched #${dupe.id}: ${err.message}`
      });
    }
  }
}

// ═══════════════════════════════════════════════════════════
// SUPPLIERS
// ═══════════════════════════════════════════════════════════

async function getSuppliers(env) {
  const { results } = await env.DB.prepare("SELECT * FROM suppliers ORDER BY name").all();
  return results;
}

async function saveSupplier(env, params, ctx) {
  const name     = (params.get("name")    || "").trim();
  const category = params.get("category") || "";
  const contact  = params.get("contact")  || "";
  const notes    = params.get("notes")    || "";
  if (!name) return { ok: false, error: "Supplier name required" };
  const now = new Date().toISOString();
  const existing = await env.DB.prepare("SELECT id FROM suppliers WHERE name = ?").bind(name).first();
  if (existing) {
    await env.DB.prepare(
      "UPDATE suppliers SET category=?, contact=?, notes=?, updated_at=? WHERE id=?"
    ).bind(category, contact, notes, now, existing.id).run();
    return { ok: true, id: existing.id, updated: true };
  }
  const r = await env.DB.prepare(
    "INSERT INTO suppliers (name, category, contact, notes) VALUES (?,?,?,?)"
  ).bind(name, category, contact, notes).run();
  return { ok: true, id: r.meta.last_row_id, updated: false };
}

async function receiveSupplierOrder(env, params, ctx) {
  const supplierName = (params.get("supplier_name") || "").trim();
  const itemName     = (params.get("item_name")     || "").trim();
  const category     = params.get("category")       || "";
  const qty          = Number(params.get("qty"))     || 0;
  const itemCost     = Number(params.get("item_cost"))     || 0;
  const shippingCost = Number(params.get("shipping_cost")) || 0;
  const notes        = params.get("notes") || "";
  if (!supplierName) return { ok: false, error: "Supplier name required" };
  if (!itemName)     return { ok: false, error: "Item name required" };
  if (!qty)          return { ok: false, error: "Qty required" };

  const totalCost = itemCost + shippingCost;
  const unitCost  = qty > 0 ? totalCost / qty : 0;
  const now = new Date().toISOString();

  let supplier = await env.DB.prepare("SELECT * FROM suppliers WHERE name = ?").bind(supplierName).first();
  if (!supplier) {
    const r = await env.DB.prepare(
      "INSERT INTO suppliers (name, category) VALUES (?,?)"
    ).bind(supplierName, category).run();
    supplier = { id: r.meta.last_row_id, name: supplierName, balance_owed: 0, total_received: 0 };
  }

  await env.DB.prepare(
    `INSERT INTO supplier_deliveries
     (supplier_id, supplier_name, item_name, category, qty, item_cost, shipping_cost, total_cost, unit_cost, notes)
     VALUES (?,?,?,?,?,?,?,?,?,?)`
  ).bind(supplier.id, supplierName, itemName, category, qty,
    itemCost, shippingCost, totalCost, unitCost, notes).run();

  await env.DB.prepare(
    `UPDATE suppliers SET balance_owed = balance_owed + ?, total_received = total_received + ?, updated_at = ? WHERE id = ?`
  ).bind(totalCost, qty, now, supplier.id).run();

  const existingItem = await env.DB.prepare(
    "SELECT id, on_hand FROM items WHERE name = ? COLLATE NOCASE AND archived = 0"
  ).bind(itemName).first();

  let inventoryAction = "created";
  if (existingItem) {
    const newQty = existingItem.on_hand + qty;
    await env.DB.batch([
      env.DB.prepare("UPDATE items SET on_hand=?, cost=?, updated_at=? WHERE id=?")
        .bind(newQty, unitCost, now, existingItem.id),
      env.DB.prepare("INSERT INTO sales_log (item_id, item_name, qty, type, note) VALUES (?,?,?,'adjust',?)")
        .bind(existingItem.id, itemName, qty, `Supplier delivery: ${supplierName}`)
    ]);
    inventoryAction = "updated";
  } else {
    const ins = await env.DB.prepare(
      "INSERT INTO items (name, category, crocheter, on_hand, cost) VALUES (?,?,?,?,?)"
    ).bind(itemName, category, "Amioki", qty, unitCost).run();
    await env.DB.prepare("INSERT INTO sales_log (item_id, item_name, qty, type, note) VALUES (?,?,?,'adjust',?)")
      .bind(ins.meta.last_row_id, itemName, qty, `New item from supplier: ${supplierName}`).run();
  }

  ctx.waitUntil(logDelivery(env, {
    timestamp: now, crocheter: "Ami (Supplier)", item_name: itemName, qty,
    method: "supplier", contract_id: "",
    notes: `${supplierName} · $${unitCost.toFixed(2)}/unit`,
    contract_status: "non-contract", contract_due_date: ""
  }));
  ctx.waitUntil(auditLog(env, {
    action: "supplier_delivery", item: itemName, qty,
    note: `From ${supplierName}. Unit cost: $${unitCost.toFixed(2)}. Inventory ${inventoryAction}.`
  }));
  return { ok: true, unitCost: unitCost.toFixed(2), totalCost: totalCost.toFixed(2), inventoryAction };
}

async function getSupplierDeliveries(env, params) {
  const supplierId = params.get("supplier_id");
  if (supplierId) {
    const { results } = await env.DB.prepare(
      "SELECT * FROM supplier_deliveries WHERE supplier_id = ? ORDER BY received_at DESC LIMIT 50"
    ).bind(Number(supplierId)).all();
    return results;
  }
  const { results } = await env.DB.prepare(
    "SELECT * FROM supplier_deliveries ORDER BY received_at DESC LIMIT 100"
  ).all();
  return results;
}

async function paySupplier(env, params, ctx) {
  const supplierId = Number(params.get("supplier_id"));
  const amount     = Number(params.get("amount")) || 0;
  const method     = params.get("method") || "";
  const notes      = params.get("notes")  || "";
  if (!supplierId || !amount) return { ok: false, error: "supplier_id and amount required" };
  const now = new Date().toISOString();
  await env.DB.prepare(
    "INSERT INTO supplier_payments (supplier_id, amount, method, notes) VALUES (?,?,?,?)"
  ).bind(supplierId, amount, method, notes).run();
  await env.DB.prepare(
    "UPDATE suppliers SET balance_owed = MAX(0, balance_owed - ?), total_paid = total_paid + ?, updated_at = ? WHERE id = ?"
  ).bind(amount, amount, now, supplierId).run();
  const supplier = await env.DB.prepare("SELECT name FROM suppliers WHERE id=?").bind(supplierId).first();
  ctx.waitUntil(auditLog(env, {
    action: "supplier_payment", item: supplier?.name || "", qty: 0,
    note: `Paid $${amount.toFixed(2)} via ${method || "unspecified"}. ${notes}`
  }));
  return { ok: true };
}

// ═══════════════════════════════════════════════════════════
// BATCH DELETE
// ═══════════════════════════════════════════════════════════

async function deleteBatch(env, params, ctx) {
  const logId = Number(params.get("log_id"));
  if (!logId) return { ok: false, error: "log_id required" };
  const log = await env.DB.prepare("SELECT * FROM production_logs WHERE id = ?").bind(logId).first();
  if (!log) return { ok: false, error: "Batch not found" };
  await env.DB.prepare("DELETE FROM qc_submissions WHERE log_id = ?").bind(logId).run();
  await env.DB.prepare("DELETE FROM production_items WHERE log_id = ?").bind(logId).run();
  await env.DB.prepare("DELETE FROM production_logs WHERE id = ?").bind(logId).run();
  ctx.waitUntil(auditLog(env, {
    action: "batch_deleted", item: log.crocheter_name, qty: 0,
    note: `Batch #${logId} deleted`
  }));
  return { ok: true };
}

// ═══════════════════════════════════════════════════════════
// RESPONSE HELPER
// ═══════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════
// AMI GOALS
// ═══════════════════════════════════════════════════════════

async function getAmiGoals(env, who) {
  const { results: goals } = await env.DB.prepare(
    "SELECT * FROM ami_goals ORDER BY status ASC, deadline ASC, created_at DESC"
  ).all();
  for (const g of goals) {
    const { results: items } = await env.DB.prepare(
      "SELECT * FROM ami_goal_items WHERE goal_id = ? ORDER BY item_name"
    ).bind(g.id).all();
    g.items = items;
    // Auto-flag overdue
    if (g.status === "active" && g.deadline) {
      const daysLeft = (new Date(g.deadline).setHours(23,59,59) - Date.now()) / 86400000;
      if (daysLeft < 0) g.status = "overdue";
    }
  }
  return { ok: true, goals };
}

async function createAmiGoal(env, params, who) {
  const name      = (params.get("name") || "").trim();
  const deadline  = params.get("deadline") || null;
  const itemsJson = params.get("items") || "[]";
  if (!name) return { ok: false, error: "Name required" };
  let items;
  try { items = JSON.parse(itemsJson); } catch { return { ok: false, error: "Invalid items JSON" }; }
  if (!items.length) return { ok: false, error: "At least one item required" };

  const result = await env.DB.prepare(
    `INSERT INTO ami_goals (name, deadline, created_by) VALUES (?, ?, ?)`
  ).bind(name, deadline, who).run();
  const goalId = result.meta.last_row_id;

  for (const item of items) {
    if (!item.item_name || !item.qty_needed) continue;
    await env.DB.prepare(
      `INSERT INTO ami_goal_items (goal_id, item_name, qty_needed) VALUES (?, ?, ?)`
    ).bind(goalId, item.item_name, item.qty_needed).run();
  }
  return { ok: true, goalId };
}

async function logAmiGoalBatch(env, params, who, ctx) {
  const goalId     = Number(params.get("goal_id"));
  const itemsJson  = params.get("items") || "[]";
  const timesJson  = params.get("time_updates") || "[]";
  const notes      = params.get("notes") || "";
  if (!goalId) return { ok: false, error: "goal_id required" };

  let items, timeUpdates;
  try { items = JSON.parse(itemsJson); } catch { return { ok: false, error: "Invalid items JSON" }; }
  try { timeUpdates = JSON.parse(timesJson); } catch { timeUpdates = []; }
  if (!items.length) return { ok: false, error: "No items provided" };

  const goal = await env.DB.prepare("SELECT * FROM ami_goals WHERE id = ?").bind(goalId).first();
  if (!goal) return { ok: false, error: "Goal not found" };

  const now = new Date().toISOString();
  let totalQty = 0, invUpdated = 0;

  const logResult = await env.DB.prepare(
    `INSERT INTO ami_goal_logs (goal_id, notes, logged_at) VALUES (?, ?, ?)`
  ).bind(goalId, notes, now).run();
  const logId = logResult.meta.last_row_id;

  for (const entry of items) {
    const itemId  = Number(entry.goal_item_id);
    const qtyDone = Number(entry.qty_done) || 0;
    if (!itemId || qtyDone <= 0) continue;

    const goalItem = await env.DB.prepare(
      "SELECT * FROM ami_goal_items WHERE id = ? AND goal_id = ?"
    ).bind(itemId, goalId).first();
    if (!goalItem) continue;

    const newDone = (goalItem.qty_done || 0) + qtyDone;
    await env.DB.prepare(
      "UPDATE ami_goal_items SET qty_done = ? WHERE id = ?"
    ).bind(newDone, itemId).run();

    await env.DB.prepare(
      `INSERT INTO ami_goal_log_items (log_id, goal_item_id, item_name, qty_done) VALUES (?, ?, ?, ?)`
    ).bind(logId, itemId, goalItem.item_name, qtyDone).run();

    totalQty += qtyDone;

    // ── AUTO-UPDATE INVENTORY (no approval needed for Ami) ──
    const normTarget = goalItem.item_name.toLowerCase().trim();
    const { results: allActive } = await env.DB.prepare(
      "SELECT id, on_hand, name FROM items WHERE archived = 0"
    ).all();

    let invItem = allActive.find(r => r.name.toLowerCase().trim() === normTarget) || null;

    if (!invItem) {
      const sqWords = normTarget.split(/\s+/).filter(Boolean);
      let bestScore = 0;
      for (const r of allActive) {
        const dbNorm  = r.name.toLowerCase().trim();
        const dbWords = dbNorm.split(/\s+/).filter(Boolean);
        const intersect = sqWords.filter(w => new Set(dbWords).has(w)).length;
        const union     = new Set([...sqWords, ...dbWords]).size;
        const jaccard   = intersect / union;
        const contain   = (dbNorm.includes(normTarget) || normTarget.includes(dbNorm)) ? 0.2 : 0;
        const score     = jaccard + contain;
        const minW      = sqWords.length === 1 ? 1 : 2;
        if (intersect < minW) continue;
        if (score > bestScore && score >= 0.5) { bestScore = score; invItem = r; }
      }
    }

    if (invItem) {
      const newQty = invItem.on_hand + qtyDone;
      await env.DB.batch([
        env.DB.prepare("UPDATE items SET on_hand = ?, updated_at = ? WHERE id = ?")
          .bind(newQty, now, invItem.id),
        env.DB.prepare(
          `INSERT INTO sales_log (item_id, item_name, qty, type, note) VALUES (?, ?, ?, 'adjust', ?)`
        ).bind(invItem.id, goalItem.item_name, qtyDone, `Ami goal: ${goal.name}`)
      ]);
      invUpdated++;
    } else {
      ctx.waitUntil(auditLog(env, {
        action: "ami_goal_no_inv_match", item: goalItem.item_name, qty: qtyDone,
        note: `Goal "${goal.name}": no inventory match for "${goalItem.item_name}"`
      }));
    }
  }

  // ── UPDATE RATE CARD from time logs ──
  for (const tu of timeUpdates) {
    if (!tu.item_name || !tu.time_min_lo) continue;
    await upsertAmiRate(env, {
      item_name:   tu.item_name,
      time_min_lo: tu.time_min_lo,
      time_min_hi: tu.time_min_hi || tu.time_min_lo,
      sell_price:  null,
      from_log:    true
    });
  }

  // Check if goal is now fully complete
  const { results: goalItems } = await env.DB.prepare(
    "SELECT * FROM ami_goal_items WHERE goal_id = ?"
  ).bind(goalId).all();
  const allComplete = goalItems.every(i => (i.qty_done || 0) >= i.qty_needed);
  if (allComplete) {
    await env.DB.prepare(
      "UPDATE ami_goals SET status = 'completed', completed_at = ? WHERE id = ?"
    ).bind(now, goalId).run();
  }

  ctx.waitUntil(auditLog(env, {
    action: "ami_goal_logged", item: goal.name, qty: totalQty,
    note: `Logged ${totalQty} items. Inv updated: ${invUpdated}. ${allComplete ? "GOAL COMPLETE 🌸" : "in progress"}`
  }));

  return { ok: true, total_qty: totalQty, inv_updated: invUpdated, goal_complete: allComplete };
}

async function completeAmiGoal(env, params) {
  const goalId = Number(params.get("goal_id"));
  if (!goalId) return { ok: false, error: "goal_id required" };
  await env.DB.prepare(
    "UPDATE ami_goals SET status = 'completed', completed_at = ? WHERE id = ?"
  ).bind(new Date().toISOString(), goalId).run();
  return { ok: true };
}

async function deleteAmiGoal(env, params) {
  const goalId = Number(params.get("goal_id"));
  if (!goalId) return { ok: false, error: "goal_id required" };
  await env.DB.prepare("DELETE FROM ami_goal_log_items WHERE log_id IN (SELECT id FROM ami_goal_logs WHERE goal_id = ?)").bind(goalId).run();
  await env.DB.prepare("DELETE FROM ami_goal_logs WHERE goal_id = ?").bind(goalId).run();
  await env.DB.prepare("DELETE FROM ami_goal_items WHERE goal_id = ?").bind(goalId).run();
  await env.DB.prepare("DELETE FROM ami_goals WHERE id = ?").bind(goalId).run();
  return { ok: true };
}

async function getAmiGoalHistory(env, who) {
  const { results: logs } = await env.DB.prepare(
    `SELECT l.*, g.name as goal_name
     FROM ami_goal_logs l
     JOIN ami_goals g ON l.goal_id = g.id
     ORDER BY l.logged_at DESC LIMIT 50`
  ).all();
  for (const log of logs) {
    const { results: items } = await env.DB.prepare(
      "SELECT * FROM ami_goal_log_items WHERE log_id = ?"
    ).bind(log.id).all();
    log.items = items;
    log.total_qty = items.reduce((s, i) => s + (i.qty_done || 0), 0);
  }
  return { ok: true, logs };
}

// ═══════════════════════════════════════════════════════════
// AMI RATE CARD
// ═══════════════════════════════════════════════════════════

async function getAmiRates(env) {
  const { results } = await env.DB.prepare(
    "SELECT * FROM ami_rates ORDER BY item_name"
  ).all();
  return results;
}

async function saveAmiRate(env, params) {
  const item_name   = (params.get("item_name") || "").trim();
  const time_min_lo = Number(params.get("time_min_lo")) || 0;
  const time_min_hi = Number(params.get("time_min_hi")) || time_min_lo;
  const sell_price  = parseFloat(params.get("sell_price")) || 0;
  if (!item_name)   return { ok: false, error: "item_name required" };
  if (!time_min_lo) return { ok: false, error: "time_min_lo required" };
  if (!sell_price)  return { ok: false, error: "sell_price required" };
  await upsertAmiRate(env, { item_name, time_min_lo, time_min_hi, sell_price, from_log: false });
  return { ok: true };
}

async function upsertAmiRate(env, { item_name, time_min_lo, time_min_hi, sell_price, from_log }) {
  const now      = new Date().toISOString();
  const existing = await env.DB.prepare(
    "SELECT * FROM ami_rates WHERE LOWER(TRIM(item_name)) = LOWER(TRIM(?))"
  ).bind(item_name).first();

  if (existing) {
    const logs  = existing.logs_count || 1;
    // Weighted average blend for time
    const newLo = Math.round((existing.time_min_lo * logs + time_min_lo) / (logs + 1));
    const newHi = Math.round((existing.time_min_hi * logs + time_min_hi) / (logs + 1));
    // Only update sell price when explicitly provided (not from auto time log)
    const newPrice = (!from_log && sell_price) ? sell_price : existing.sell_price;
    await env.DB.prepare(
      `UPDATE ami_rates SET time_min_lo = ?, time_min_hi = ?, sell_price = ?,
       logs_count = ?, updated_at = ? WHERE id = ?`
    ).bind(newLo, newHi, newPrice, logs + 1, now, existing.id).run();
  } else {
    await env.DB.prepare(
      `INSERT INTO ami_rates (item_name, time_min_lo, time_min_hi, sell_price, logs_count)
       VALUES (?, ?, ?, ?, ?)`
    ).bind(item_name, time_min_lo, time_min_hi, sell_price || 0, 1).run();
  }
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status, headers: { "Content-Type": "application/json", ...CORS }
  });
}
