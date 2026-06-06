// S3 Proxy Worker — 通用 S3 兼容代理
//   GET/HEAD 公开访问，Cloudflare 边缘缓存加速
//   写操作验证 AWS SigV4 签名（或 IP 白名单），拒绝未授权请求

const EMPTY_SHA256_HEX = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const method = request.method;

    if (method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, HEAD, PUT, DELETE, POST, OPTIONS',
          'Access-Control-Allow-Headers': '*',
          'Access-Control-Max-Age': '86400',
        },
      });
    }

    if (method === 'GET' && url.pathname === '/health') {
      return new Response(JSON.stringify({ status: 'ok', timestamp: new Date().toISOString() }), {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      });
    }

    if (!env.S3_ENDPOINT || !env.S3_REGION || !env.S3_ACCESS_KEY || !env.S3_SECRET_KEY) {
      return new Response(JSON.stringify({ error: 'Missing S3 configuration' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // ── 鉴权 ──
    // 写操作（PUT/DELETE/POST）必须通过签名验证或 IP 白名单
    if (method !== 'GET' && method !== 'HEAD') {
      const clientIp = request.headers.get('cf-connecting-ip');
      const allowedIp = env.S3_MASTODON_IP;

      const signatureValid = await verifySigV4(request, env);
      const ipValid = allowedIp && clientIp === allowedIp;

      if (!signatureValid && !ipValid) {
        return new Response(JSON.stringify({ error: 'Forbidden' }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }

    try {
      return await proxyToS3(request, env);
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 502,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  },
};

// ── SigV4 签名验证 ─────────────────────────────────

async function verifySigV4(request, env) {
  const authHeader = request.headers.get('authorization');
  if (!authHeader) return false;

  const m = authHeader.match(
    /^AWS4-HMAC-SHA256\s+Credential=([^,\s]+),\s*SignedHeaders=([^,\s]+),\s*Signature=([^,\s]+)$/,
  );
  if (!m) return false;

  const signingKey = m[1]; // accessKey/dateStamp/region/s3/aws4_request
  const signedHeadersStr = m[2];
  const claimedSig = m[3];
  const signedHeaders = signedHeadersStr.split(';');

  const amzDate = request.headers.get('x-amz-date');
  const claimedBodyHash = request.headers.get('x-amz-content-sha256');
  if (!amzDate || !claimedBodyHash) return false;

  const dateStamp = amzDate.slice(0, 8);
  const url = new URL(request.url);

  // 验证 Credential 中的 accessKey 匹配
  if (!signingKey.startsWith(env.S3_ACCESS_KEY + '/')) return false;

  // 重建 CanonicalRequest
  const canonicalHeaders = {};
  for (const h of signedHeaders) {
    const val = request.headers.get(h);
    if (val === null) return false;
    canonicalHeaders[h] = val.trim().replace(/\s+/g, ' ');
  }

  const canonicalHeaderStr = signedHeaders.map(k => `${k}:${canonicalHeaders[k]}\n`).join('');
  const canonicalRequest = [
    request.method,
    url.pathname || '/',
    url.search.replace(/^\?/, ''),
    canonicalHeaderStr,
    signedHeadersStr,
    claimedBodyHash,
  ].join('\n');

  const canonicalHash = await sha256Hex(canonicalRequest);
  const credentialScope = `${dateStamp}/${env.S3_REGION}/s3/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, credentialScope, canonicalHash].join('\n');

  const sigKey = await getSigningKey(env.S3_SECRET_KEY, dateStamp, env.S3_REGION);
  const expectedSig = bytesToHex(await hmacSha256(sigKey, stringToSign));

  return expectedSig === claimedSig;
}

// ── 代理到 COS ─────────────────────────────────────

async function proxyToS3(request, env) {
  const url = new URL(request.url);
  const s3Endpoint = env.S3_ENDPOINT.replace(/\/+$/, '');
  // Mastodon SDK uses path-style: /<bucket>/key. Strip bucket prefix for COS.
  let pathname = url.pathname;
  const bucketPrefix = '/' + env.S3_BUCKET;
  if (env.S3_BUCKET && pathname.startsWith(bucketPrefix + '/')) {
    pathname = pathname.slice(bucketPrefix.length);
  }
  const upstreamUrl = s3Endpoint + pathname + url.search;

  let bodyBuffer = null;
  let bodyHash;

  if (request.body && (request.method === 'PUT' || request.method === 'POST')) {
    bodyBuffer = await request.arrayBuffer();
    bodyHash = await sha256Hex(bodyBuffer);
  } else {
    bodyHash = EMPTY_SHA256_HEX;
  }

  const headers = new Headers();
  headers.set('host', new URL(upstreamUrl).hostname);
  headers.set('x-amz-date', toAmzDate(new Date()));
  headers.set('x-amz-content-sha256', bodyHash);
  headers.set('user-agent', 'Cloudflare-S3-Proxy/1.0');

  const forwardHeaders = [
    'content-type',
    'content-md5',
    'cache-control',
    'content-disposition',
    'content-encoding',
    'content-language',
    'expect',
    'if-match',
    'if-modified-since',
    'if-none-match',
    'if-unmodified-since',
    'range',
    'x-amz-acl',
    'x-amz-copy-source',
    'x-amz-copy-source-range',
    'x-amz-copy-source-if-match',
    'x-amz-copy-source-if-none-match',
    'x-amz-copy-source-if-modified-since',
    'x-amz-copy-source-if-unmodified-since',
    'x-amz-metadata-directive',
    'x-amz-tagging',
    'x-amz-storage-class',
    'x-amz-server-side-encryption',
    'x-amz-server-side-encryption-aws-kms-key-id',
    'x-amz-request-payer',
    'x-amz-expected-bucket-owner',
  ];

  for (const h of forwardHeaders) {
    const val = request.headers.get(h);
    if (val) headers.set(h.toLowerCase(), val);
  }

  for (const [key, val] of request.headers) {
    if (key.toLowerCase().startsWith('x-amz-meta-') && !headers.has(key.toLowerCase())) {
      headers.set(key.toLowerCase(), val);
    }
  }

  const signedHeaders = await signAwsV4(
    request.method, upstreamUrl, headers, bodyHash,
    env.S3_REGION, env.S3_ACCESS_KEY, env.S3_SECRET_KEY,
  );

  const upstreamRequest = new Request(upstreamUrl, {
    method: request.method,
    headers: signedHeaders,
    body: bodyBuffer || null,
    redirect: 'manual',
  });

  const response = await fetch(upstreamRequest);

  const responseHeaders = new Headers(response.headers);
  responseHeaders.set('access-control-allow-origin', '*');
  responseHeaders.set('x-proxy-by', 'Cloudflare-S3-Proxy');

  if (request.method === 'GET' || request.method === 'HEAD') {
    responseHeaders.set('Content-Disposition', 'inline');
    if (response.status === 200 && !url.search) {
      responseHeaders.set('Cache-Control', 'public, max-age=31536000, immutable');
    }
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders,
  });
}

// ── AWS Signature V4 ────────────────────────────────

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256Hex(input) {
  const data = typeof input === 'string' ? new TextEncoder().encode(input) : input;
  const hash = await crypto.subtle.digest('SHA-256', data);
  return bytesToHex(new Uint8Array(hash));
}

async function hmacSha256(key, message) {
  const keyMaterial = typeof key === 'string' ? new TextEncoder().encode(key) : key;
  const cryptoKey = await crypto.subtle.importKey('raw', keyMaterial, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(message));
  return new Uint8Array(sig);
}

async function getSigningKey(secretKey, dateStamp, region, service = 's3') {
  const kDate = await hmacSha256('AWS4' + secretKey, dateStamp);
  const kRegion = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, service);
  return await hmacSha256(kService, 'aws4_request');
}

function toAmzDate(date) {
  return date.toISOString().replace(/[:-]/g, '').replace(/\.\d{3}Z$/, 'Z');
}

async function signAwsV4(method, urlStr, headers, bodyHash, region, accessKey, secretKey, service = 's3') {
  const url = new URL(urlStr);
  const pathname = url.pathname || '/';
  const querystring = url.search.replace(/^\?/, '');

  const canonicalHeaders = {};
  for (const [key, value] of headers.entries()) {
    canonicalHeaders[key.toLowerCase()] = value.trim().replace(/\s+/g, ' ');
  }
  const sortedKeys = Object.keys(canonicalHeaders).sort((a, b) => a.localeCompare(b));
  const signedHeadersStr = sortedKeys.join(';');
  const canonicalHeaderEntries = sortedKeys.map(k => `${k}:${canonicalHeaders[k]}\n`).join('');

  const canonicalRequest = [method, pathname, querystring, canonicalHeaderEntries, signedHeadersStr, bodyHash].join('\n');

  const algorithm = 'AWS4-HMAC-SHA256';
  const amzDate = canonicalHeaders['x-amz-date'];
  const dateStamp = amzDate.slice(0, 8);
  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const canonicalRequestHash = await sha256Hex(canonicalRequest);
  const stringToSign = [algorithm, amzDate, credentialScope, canonicalRequestHash].join('\n');

  const signingKey = await getSigningKey(secretKey, dateStamp, region, service);
  const signature = bytesToHex(await hmacSha256(signingKey, stringToSign));

  const authorization = `${algorithm} Credential=${accessKey}/${credentialScope}, SignedHeaders=${signedHeadersStr}, Signature=${signature}`;

  const finalHeaders = new Headers();
  for (const [key, value] of headers.entries()) {
    finalHeaders.set(key, value);
  }
  finalHeaders.set('Authorization', authorization);
  return finalHeaders;
}
