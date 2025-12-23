  const express = require('express');
  const crypto = require('crypto');
  const https = require('https');
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

  // WeChat OpenAPI requests:
  // - 禁用 env proxy（云环境可能注入 HTTP(S)_PROXY 导致 MITM/self-signed）
  // - 强制使用 https agent（避免某些环境自动代理/证书链异常）
  const wxHttp = axios.create({
    timeout: 10000,
    proxy: false,
    httpsAgent: new https.Agent({ keepAlive: true }),
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
    if (accessTokenCache.token && Date.now() < accessTokenCache.expiresAt) return accessTokenCache.token;

    const appId = process.env.WECHAT_APP_ID;
    const secret = process.env.WECHAT_APP_SECRET;
    if (!appId || !secret) throw new Error('WECHAT_APP_ID / WECHAT_APP_SECRET 未配置');

    // 先用 Node fetch（不吃 env proxy），失败再回退 axios（便于对比诊断）
    let data = null;
    try {
      data = await wxFetchJson('https://api.weixin.qq.com/cgi-bin/token', {
        params: { grant_type: 'client_credential', appid: appId, secret },
      });
    } catch (e) {
      try {
        const out = await wxHttp.get('https://api.weixin.qq.com/cgi-bin/token', {
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

      const { openId, templateId, data, url, scene } = req.body || {};
      if (!openId || !templateId || !data) {
        return res.status(400).json({ success: false, error: 'missing openId/templateId/data' });
      }

      const accessToken = await getAccessToken();
      const wxUrl = `https://api.weixin.qq.com/cgi-bin/message/subscribe/bizsend?access_token=${encodeURIComponent(accessToken)}`;

      const body = {
        touser: openId,
        template_id: templateId,
        data,
        ...(url ? { url } : {}),
        ...(typeof scene === 'number' ? { scene } : {})
      };

      let wxOut;
      try {
        wxOut = await wxFetchJson(wxUrl, { method: 'POST', body });
      } catch (e) {
        return res.status(502).json({ success: false, error: `wechat bizsend http failed: ${e instanceof Error ? e.message : String(e)}` });
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
    const url = 'https://api.weixin.qq.com/cgi-bin/ticket/getticket';

    try {
      const data = await wxFetchJson(url, {
        params: { access_token: accessToken, type: 'jsapi' },
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
