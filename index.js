  const express = require('express');
  const crypto = require('crypto');
  const fs = require('fs');
  const path = require('path');
  const http = require('http');
  const https = require('https');
  const tls = require('tls');
  const axios = require('axios');

  const app = express();

  //临时调试
  app.use((req, _res, next) => { console.log('IN', req.method, req.url); next(); });

  // 必须保留 raw body，用于和 Vercel 侧签名一致
  app.use(express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf.toString('utf8');
    }
  }));

  function hmacSha256Hex(secret, ts, rawBody) {
    return crypto.createHmac('sha256', secret).update(`${ts}.${rawBody}`).digest('hex');
  }

  function timingSafeEqualHex(a, b) {
    const aa = Buffer.from(String(a || ''), 'hex');
    const bb = Buffer.from(String(b || ''), 'hex');
    if (aa.length !== bb.length || aa.length === 0) return false;
    return crypto.timingSafeEqual(aa, bb);
  }

  function getExtraCaCandidates() {
    const candidates = new Set();
    const extra = [
      '/app/cert/ca.pem',
      '/app/cert/ca.crt',
      '/app/cert/rootca.pem',
      '/app/cert/rootca.crt',
      '/app/cert/cacert.pem',
      '/app/cert/cacert.crt',
      '/app/cert/tcloudbase-ca.pem',
      '/app/cert/tcloudbase-ca.crt',
    ];
    for (const p of extra) candidates.add(p);

    try {
      const dir = '/app/cert';
      if (fs.existsSync(dir) && fs.statSync(dir).isDirectory()) {
        for (const f of fs.readdirSync(dir)) {
          if (!f) continue;
          const lower = String(f).toLowerCase();
          if (!lower.endsWith('.pem') && !lower.endsWith('.crt') && !lower.endsWith('.cer')) continue;
          candidates.add(path.join(dir, f));
        }
      }
    } catch {
      // ignore
    }
    return Array.from(candidates);
  }

  function loadExtraCas() {
    const loaded = [];
    const candidates = getExtraCaCandidates();

    try {
      const fromEnv = process.env.WECHAT_EXTRA_CA_PEM;
      if (fromEnv && String(fromEnv).includes('BEGIN CERTIFICATE')) {
        loaded.push({ path: 'env:WECHAT_EXTRA_CA_PEM', pem: String(fromEnv) });
      }
    } catch {
      // ignore
    }

    for (const p of candidates) {
      try {
        if (!fs.existsSync(p)) continue;
        const stat = fs.statSync(p);
        if (!stat.isFile() || stat.size <= 0) continue;
        const pem = fs.readFileSync(p, 'utf8');
        if (pem && pem.includes('BEGIN CERTIFICATE')) {
          loaded.push({ path: p, pem });
        }
      } catch {
        // ignore
      }
    }
    return loaded;
  }

  const extraCas = loadExtraCas();
  const wxTrustedCas = tls.rootCertificates.concat(extraCas.map((x) => x.pem));
  const allowInsecureWechatTls = String(process.env.WECHAT_TLS_INSECURE || '') === '1';
  const wxHttpsAgent = new https.Agent({
    keepAlive: true,
    ca: wxTrustedCas,
    rejectUnauthorized: !allowInsecureWechatTls,
  });
  const wxHttpsAgentInsecure = new https.Agent({
    keepAlive: true,
    rejectUnauthorized: false,
  });

  // 微信云托管「开放接口服务」模式：
  // - 在云托管控制台开启“开放接口服务”，并在“微信令牌权限配置”里配置接口路径白名单
  // - 容器内调用形式与官方接口文档一致，但无需携带 access_token / cloudbase_access_token
  // - 建议默认走 HTTP（避免云托管拦截 HTTPS 产生 self-signed 证书错误）
  const openApiEnabled = String(process.env.WECHAT_OPENAPI_ENABLED || '') === '1';
  const openApiProtocol = (process.env.WECHAT_OPENAPI_PROTOCOL || (openApiEnabled ? 'http' : 'https')).toLowerCase();
  const wechatBaseUrl = `${openApiProtocol === 'http' ? 'http' : 'https'}://api.weixin.qq.com`;

  // WeChat OpenAPI requests:
  // - 禁用 env proxy（云环境可能注入 HTTP(S)_PROXY 导致 MITM/self-signed）
  // - 指定 CA（优先加载云托管 /app/cert 下的根证书）
  const wxHttp = axios.create({
    timeout: 10000,
    proxy: false,
    httpsAgent: wxHttpsAgent,
    headers: { 'User-Agent': 'wechat-official-gateway/1.0' },
  });

  function getProxyEnvSnapshot() {
    const getVal = (k) => process.env[k] || process.env[k.toLowerCase()] || '';
    const httpProxy = getVal('HTTP_PROXY');
    const httpsProxy = getVal('HTTPS_PROXY');
    const noProxy = getVal('NO_PROXY');
    return {
      HTTP_PROXY: httpProxy ? '[set]' : '',
      HTTPS_PROXY: httpsProxy ? '[set]' : '',
      NO_PROXY: noProxy ? String(noProxy).slice(0, 120) : '',
    };
  }

  function formatAxiosError(err) {
    const anyErr = err || {};
    const code = anyErr.code ? String(anyErr.code) : '';
    const message = anyErr.message ? String(anyErr.message) : String(err);
    const proxyEnv = {
      HTTP_PROXY: Boolean(process.env.HTTP_PROXY || process.env.http_proxy),
      HTTPS_PROXY: Boolean(process.env.HTTPS_PROXY || process.env.https_proxy),
      NO_PROXY: Boolean(process.env.NO_PROXY || process.env.no_proxy),
    };
    return `${code ? `${code} ` : ''}${message} (proxyEnv=${JSON.stringify(proxyEnv)})`.trim();
  }

  async function wxFetchJson(url, opts) {
    const u = new URL(url);
    const params = (opts && opts.params) || {};
    for (const [k, v] of Object.entries(params)) {
      if (v === undefined || v === null || v === '') continue;
      u.searchParams.set(k, String(v));
    }

    try {
      const res = await fetch(u.toString(), {
        method: (opts && opts.method) || 'GET',
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'wechat-official-gateway/1.0',
          ...((opts && opts.headers) || {}),
        },
        body: opts && opts.body ? JSON.stringify(opts.body) : undefined,
        signal: AbortSignal.timeout(10000),
      });

      const text = await res.text().catch(() => '');
      let data = null;
      try {
        data = text ? JSON.parse(text) : null;
      } catch {
        data = null;
      }

      if (!res.ok) {
        const msg = data && (data.errmsg || data.message) ? (data.errmsg || data.message) : text;
        throw new Error(`http ${res.status} ${String(msg || '').slice(0, 300)}`.trim());
      }
      return data;
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      const proxyEnv = getProxyEnvSnapshot();
      throw new Error(`wx fetch failed: ${msg} (proxyEnv=${JSON.stringify(proxyEnv)})`);
    }
  }

  let accessTokenCache = { token: '', expiresAt: 0 };

  async function getAccessToken() {
    if (openApiEnabled) {
      // 开放接口服务模式不需要 access_token
      return '';
    }
    if (accessTokenCache.token && Date.now() < accessTokenCache.expiresAt) return accessTokenCache.token;

    const appId = process.env.WECHAT_APP_ID;
    const secret = process.env.WECHAT_APP_SECRET;
    if (!appId || !secret) throw new Error('WECHAT_APP_ID / WECHAT_APP_SECRET 未配置');

    // 先用 Node fetch（不吃 env proxy），失败再回退 axios（便于对比诊断）
    let data = null;
    try {
      data = await wxFetchJson(`${wechatBaseUrl}/cgi-bin/token`, {
        params: { grant_type: 'client_credential', appid: appId, secret },
      });
    } catch (e) {
      try {
        const out = await wxHttp.get(`${wechatBaseUrl}/cgi-bin/token`, {
          params: { grant_type: 'client_credential', appid: appId, secret }
        });
        data = out.data;
      } catch (e2) {
        const msg1 = e instanceof Error ? e.message : String(e);
        throw new Error(`get access_token http failed: ${msg1}; axiosFallback=${formatAxiosError(e2)}`);
      }
    }

    if (!data?.access_token) {
      throw new Error(`get access_token failed: ${data?.errcode || ''} ${data?.errmsg || ''}`.trim());
    }

    const expiresIn = typeof data.expires_in === 'number' ? data.expires_in : 7000;
    accessTokenCache = { token: data.access_token, expiresAt: Date.now() + (expiresIn - 300) * 1000 };
    return accessTokenCache.token;
  }

  app.get('/healthz', (_req, res) =>
    res.json({
      ok: true,
      node: process.version,
      proxyEnv: getProxyEnvSnapshot(),
      extraCaFiles: extraCas.map((x) => x.path),
      wechatTlsInsecure: allowInsecureWechatTls,
      openApiEnabled,
      openApiProtocol,
      wechatBaseUrl,
      now: new Date().toISOString(),
    }),
  );

  // 诊断：直接测试与 api.weixin.qq.com 的 TLS 握手与证书信息（不依赖 access_token）
  app.get('/debug/wechat-tls', async (_req, res) => {
    const proxyEnv = getProxyEnvSnapshot();
    try {
      const result = await new Promise((resolve, reject) => {
        const req = https.request(
          {
            hostname: 'api.weixin.qq.com',
            port: 443,
            path: '/',
            method: 'GET',
            timeout: 10000,
            agent: wxHttpsAgent,
          },
          (r) => {
            const socket = r.socket;
            const cert = socket && socket.getPeerCertificate ? socket.getPeerCertificate(true) : null;
            r.resume();
            resolve({
              statusCode: r.statusCode || 0,
              cert: cert
                ? {
                    subject: cert.subject,
                    issuer: cert.issuer,
                    subjectaltname: cert.subjectaltname,
                    valid_from: cert.valid_from,
                    valid_to: cert.valid_to,
                    fingerprint256: cert.fingerprint256,
                    serialNumber: cert.serialNumber,
                  }
                : null,
            });
          },
        );
        req.on('error', reject);
        req.on('timeout', () => req.destroy(new Error('timeout')));
        req.end();
      });

      return res.json({ ok: true, proxyEnv, ...result });
    } catch (e) {
      return res.json({
        ok: false,
        proxyEnv,
        extraCaFiles: extraCas.map((x) => x.path),
        error: e instanceof Error ? e.message : String(e),
        code: e && e.code ? String(e.code) : '',
      });
    }
  });

  // 诊断：测试 HTTP 直连（开放接口服务推荐默认用 HTTP，避免证书问题）
  app.get('/debug/wechat-http', async (_req, res) => {
    try {
      const result = await new Promise((resolve, reject) => {
        const req = http.request(
          {
            hostname: 'api.weixin.qq.com',
            port: 80,
            path: '/',
            method: 'GET',
            timeout: 10000,
          },
          (r) => {
            r.resume();
            resolve({ statusCode: r.statusCode || 0, headers: r.headers || {} });
          },
        );
        req.on('error', reject);
        req.on('timeout', () => req.destroy(new Error('timeout')));
        req.end();
      });
      return res.json({ ok: true, ...result });
    } catch (e) {
      return res.json({ ok: false, error: e instanceof Error ? e.message : String(e) });
    }
  });

  // 诊断：开放接口服务是否真正生效（无需签名；用于检查“开关/权限配置/资源复用”）
  // 预期：
  // - 若“开放接口服务”未开启：通常返回 access_token missing（如 41001）
  // - 若已开启但“微信令牌权限配置”没加：通常返回 api unauthorized
  // - 若已开启且配置正确：返回 { errcode:0, ticket:..., expires_in:... }
  app.get('/debug/openapi-ticket', async (_req, res) => {
    try {
      const data = await wxFetchJson(`${wechatBaseUrl}/cgi-bin/ticket/getticket`, {
        params: openApiEnabled ? { type: 'jsapi' } : { type: 'jsapi' },
      });
      return res.json({ ok: true, openApiEnabled, openApiProtocol, wechatBaseUrl, data });
    } catch (e) {
      return res.json({
        ok: false,
        openApiEnabled,
        openApiProtocol,
        wechatBaseUrl,
        error: e instanceof Error ? e.message : String(e),
      });
    }
  });

  function certToPem(cert) {
    if (!cert || !cert.raw) return '';
    const b64 = Buffer.from(cert.raw).toString('base64');
    const lines = b64.match(/.{1,64}/g) || [];
    return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;
  }

  // 诊断（不校验证书）：用于导出云环境返回的证书链，便于定位是谁在 MITM
  app.get('/debug/wechat-tls-insecure', async (_req, res) => {
    const proxyEnv = getProxyEnvSnapshot();
    try {
      const result = await new Promise((resolve, reject) => {
        const req = https.request(
          {
            hostname: 'api.weixin.qq.com',
            port: 443,
            path: '/',
            method: 'GET',
            timeout: 10000,
            agent: wxHttpsAgentInsecure,
          },
          (r) => {
            const socket = r.socket;
            const cert = socket && socket.getPeerCertificate ? socket.getPeerCertificate(true) : null;
            r.resume();
            resolve({
              statusCode: r.statusCode || 0,
              cert: cert
                ? {
                    subject: cert.subject,
                    issuer: cert.issuer,
                    subjectaltname: cert.subjectaltname,
                    valid_from: cert.valid_from,
                    valid_to: cert.valid_to,
                    fingerprint256: cert.fingerprint256,
                    serialNumber: cert.serialNumber,
                    pem: certToPem(cert),
                  }
                : null,
            });
          },
        );
        req.on('error', reject);
        req.on('timeout', () => req.destroy(new Error('timeout')));
        req.end();
      });

      return res.json({ ok: true, proxyEnv, ...result });
    } catch (e) {
      return res.json({
        ok: false,
        proxyEnv,
        error: e instanceof Error ? e.message : String(e),
        code: e && e.code ? String(e.code) : '',
      });
    }
  });

  // Vercel -> 网关：发送订阅通知
  app.post('/wechat/subscribe-send', async (req, res) => {
    try {
      const secret = process.env.WECHAT_GATEWAY_SECRET;
      if (!secret) return res.status(500).json({ success: false, error: 'WECHAT_GATEWAY_SECRET 未配置' });

      const ts = req.header('x-wechat-gateway-ts');
      const sig = req.header('x-wechat-gateway-signature');
      const rawBody = req.rawBody || '';

      if (!ts || !sig) return res.status(401).json({ success: false, error: 'missing signature headers' });

      // 防重放：5分钟窗口
      const now = Math.floor(Date.now() / 1000);
      const tsNum = Number(ts);
      if (!Number.isFinite(tsNum) || Math.abs(now - tsNum) > 300) {
        return res.status(401).json({ success: false, error: 'signature timestamp expired' });
      }

      const expected = hmacSha256Hex(secret, ts, rawBody);
      if (!timingSafeEqualHex(expected, sig)) {
        return res.status(401).json({ success: false, error: 'invalid signature' });
      }

      const { openId, templateId, data, url } = req.body || {};
      if (!openId || !templateId || !data) {
        return res.status(400).json({ success: false, error: 'missing openId/templateId/data' });
      }

      // 服务号一次性订阅通知：/cgi-bin/message/subscribe/bizsend
      // 按你的要求：把跳转链接放到 page 字段（而不是 url）。
      const wxUrl = openApiEnabled
        ? `${wechatBaseUrl}/cgi-bin/message/subscribe/bizsend`
        : `${wechatBaseUrl}/cgi-bin/message/subscribe/bizsend?access_token=${encodeURIComponent(await getAccessToken())}`;

      const body = {
        touser: openId,
        template_id: templateId,
        data,
        ...(url ? { page: url } : {}),
      };

      let wxOut;
      try {
        wxOut = await wxFetchJson(wxUrl, { method: 'POST', body });
      } catch (e) {
        return res.status(502).json({
          success: false,
          error: `wechat bizsend http failed: ${e instanceof Error ? e.message : String(e)}`,
          hint: openApiEnabled ? '若提示 api unauthorized，请在云托管控制台-云调用-微信令牌权限配置中添加 /cgi-bin/message/subscribe/bizsend' : undefined,
        });
      }

      if (wxOut?.errcode && wxOut.errcode !== 0) {
        return res.status(502).json({ success: false, error: `wechat bizsend failed: ${wxOut.errcode} ${wxOut.errmsg ||
  ''}`.trim() });
      }

      return res.json({ success: true });
    } catch (e) {
      return res.status(500).json({ success: false, error: e instanceof Error ? e.message : String(e) });
    }
  });

  // ===== JS-SDK 签名：网关接口 =====
  let jsapiTicketCache = { ticket: '', expiresAt: 0 };

  async function getJsApiTicket() {
    if (jsapiTicketCache.ticket && Date.now() < jsapiTicketCache.expiresAt) return jsapiTicketCache.ticket;

    const accessToken = await getAccessToken();
    const url = `${wechatBaseUrl}/cgi-bin/ticket/getticket`;

    try {
      const data = await wxFetchJson(url, {
        params: openApiEnabled ? { type: 'jsapi' } : { access_token: accessToken, type: 'jsapi' },
      });

      if (!data || data.errcode !== 0 || !data.ticket) {
        throw new Error(`get jsapi_ticket failed: ${data?.errcode || ''} ${data?.errmsg || ''}`.trim());
      }

      const expiresIn = typeof data.expires_in === 'number' ? data.expires_in : 7000;
      jsapiTicketCache = { ticket: data.ticket, expiresAt: Date.now() + (expiresIn - 300) * 1000 };
      return jsapiTicketCache.ticket;
    } catch (e) {
      throw new Error(`get jsapi_ticket http failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  function nonceStr(len = 16) {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let out = '';
    for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
    return out;
  }

  function sha1(input) {
    return crypto.createHash('sha1').update(input).digest('hex');
  }

  app.post('/wechat/js-sdk-config', async (req, res) => {
    try {
      // 1) 验签（和 /wechat/subscribe-send 一样）
      const secret = process.env.WECHAT_GATEWAY_SECRET;
      if (!secret) return res.status(500).json({ success: false, error: 'WECHAT_GATEWAY_SECRET 未配置' });

      const ts = req.header('x-wechat-gateway-ts');
      const sig = req.header('x-wechat-gateway-signature');
      const rawBody = req.rawBody || '';

      if (!ts || !sig) return res.status(401).json({ success: false, error: 'missing signature headers' });

      const now = Math.floor(Date.now() / 1000);
      const tsNum = Number(ts);
      if (!Number.isFinite(tsNum) || Math.abs(now - tsNum) > 300) {
        return res.status(401).json({ success: false, error: 'signature timestamp expired' });
      }

      const expected = hmacSha256Hex(secret, ts, rawBody);
      if (!timingSafeEqualHex(expected, sig)) {
        return res.status(401).json({ success: false, error: 'invalid signature' });
      }

      // 2) 参数
      const appId = process.env.WECHAT_APP_ID;
      if (!appId) return res.status(500).json({ success: false, error: 'WECHAT_APP_ID 未配置' });

      const rawUrl = req.body?.url;
      if (!rawUrl || typeof rawUrl !== 'string') {
        return res.status(400).json({ success: false, error: 'missing url' });
      }

      // 必须去掉 hash
      const urlToSign = rawUrl.split('#')[0];

      // 3) 生成签名
      const ticket = await getJsApiTicket();
      const noncestr = nonceStr();
      const timestamp = Math.floor(Date.now() / 1000);

      const plain =
        `jsapi_ticket=${ticket}` +
        `&noncestr=${noncestr}` +
        `&timestamp=${timestamp}` +
        `&url=${urlToSign}`;

      const signature = sha1(plain);

      return res.json({
        success: true,
        data: { appId, timestamp, nonceStr: noncestr, signature }
      });
    } catch (e) {
      return res.status(500).json({ success: false, error: e instanceof Error ? e.message : String(e) });
    }
  });

  const port = Number(process.env.PORT || 80); 
  app.listen(port, '0.0.0.0');
