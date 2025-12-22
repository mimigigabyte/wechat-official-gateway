  const express = require('express');
  const crypto = require('crypto');
  const axios = require('axios');

  const app = express();

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

  let accessTokenCache = { token: '', expiresAt: 0 };

  async function getAccessToken() {
    if (accessTokenCache.token && Date.now() < accessTokenCache.expiresAt) return accessTokenCache.token;

    const appId = process.env.WECHAT_APP_ID;
    const secret = process.env.WECHAT_APP_SECRET;
    if (!appId || !secret) throw new Error('WECHAT_APP_ID / WECHAT_APP_SECRET 未配置');

    const url = 'https://api.weixin.qq.com/cgi-bin/token';
    const { data } = await axios.get(url, {
      params: { grant_type: 'client_credential', appid: appId, secret }
    });

    if (!data?.access_token) {
      throw new Error(`get access_token failed: ${data?.errcode || ''} ${data?.errmsg || ''}`.trim());
    }

    const expiresIn = typeof data.expires_in === 'number' ? data.expires_in : 7000;
    accessTokenCache = { token: data.access_token, expiresAt: Date.now() + (expiresIn - 300) * 1000 };
    return accessTokenCache.token;
  }

  app.get('/healthz', (_req, res) => res.json({ ok: true }));

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
      const wxUrl = `https://api.weixin.qq.com/cgi-bin/message/subscribe/bizsend?
  access_token=${encodeURIComponent(accessToken)}`;

      const body = {
        touser: openId,
        template_id: templateId,
        data,
        ...(url ? { url } : {}),
        ...(typeof scene === 'number' ? { scene } : {})
      };

      const { data: wxOut } = await axios.post(wxUrl, body, {
        headers: { 'Content-Type': 'application/json' }
      });

      if (wxOut?.errcode && wxOut.errcode !== 0) {
        return res.status(502).json({ success: false, error: `wechat bizsend failed: ${wxOut.errcode} ${wxOut.errmsg ||
  ''}`.trim() });
      }

      return res.json({ success: true });
    } catch (e) {
      return res.status(500).json({ success: false, error: e instanceof Error ? e.message : String(e) });
    }
  });

  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`wechat gateway listening on ${port}`));