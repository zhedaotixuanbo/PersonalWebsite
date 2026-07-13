const GITHUB_API = 'https://api.github.com';
const ADMIN_SESSION_COOKIE = 'admin_session';
const ADMIN_SESSION_MAX_AGE = 60 * 60 * 12;

function json(data, status = 200, extraHeaders = {}) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            'Content-Type': 'application/json; charset=utf-8',
            ...extraHeaders
        }
    });
}

function getConfig(env) {
    return {
        githubToken: env.GITHUB_TOKEN || '',
        githubOwner: env.GITHUB_OWNER || 'zhedaotixuanbo',
        githubRepo: env.GITHUB_REPO || 'PersonalWebsite',
        adminPasswordHash: env.ADMIN_PASSWORD_HASH || '',
        adminSessionSecret: env.ADMIN_SESSION_SECRET || env.GITHUB_TOKEN || env.ADMIN_PASSWORD_HASH || ''
    };
}

async function sha256(text) {
    const data = new TextEncoder().encode(text || '');
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(hashBuffer))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
}

async function hmacSha256(secret, text) {
    const key = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(secret),
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(String(text)));
    return Array.from(new Uint8Array(signature))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
}

function safeEqual(a, b) {
    if (!a || !b || a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
}

function parseCookies(cookieHeader = '') {
    return Object.fromEntries(
        cookieHeader
            .split(';')
            .map(item => item.trim())
            .filter(Boolean)
            .map(item => {
                const index = item.indexOf('=');
                if (index === -1) return [item, ''];
                return [
                    decodeURIComponent(item.slice(0, index)),
                    decodeURIComponent(item.slice(index + 1))
                ];
            })
    );
}

async function buildSessionCookie(config) {
    const timestamp = Date.now();
    const signature = await hmacSha256(config.adminSessionSecret, timestamp);
    return `${timestamp}.${signature}`;
}

async function setAdminSessionCookie(request, config) {
    const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
    const value = await buildSessionCookie(config);
    return `${ADMIN_SESSION_COOKIE}=${encodeURIComponent(value)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${ADMIN_SESSION_MAX_AGE}${secure}`;
}

function clearAdminSessionCookie() {
    return `${ADMIN_SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`;
}

async function verifyAdminSession(request, config) {
    if (!config.adminSessionSecret) return false;

    const cookies = parseCookies(request.headers.get('Cookie') || '');
    const value = cookies[ADMIN_SESSION_COOKIE];
    if (!value) return false;

    const [timestampText, signature] = value.split('.');
    const timestamp = Number(timestampText);
    if (!timestamp || !signature) return false;

    const age = Date.now() - timestamp;
    if (age < 0 || age > ADMIN_SESSION_MAX_AGE * 1000) return false;

    const expected = await hmacSha256(config.adminSessionSecret, timestamp);
    return safeEqual(expected, signature);
}

async function readBody(request) {
    try {
        return await request.json();
    } catch {
        return {};
    }
}

async function verifyAdmin(config, body) {
    if (!config.adminPasswordHash) {
        return { ok: false, status: 500, message: '服务器未配置 ADMIN_PASSWORD_HASH' };
    }

    const actualHash = await sha256(body.password || '');
    if (!safeEqual(actualHash, config.adminPasswordHash)) {
        return { ok: false, status: 401, message: '管理员密码错误' };
    }

    return { ok: true };
}

async function githubRequest(config, path, options = {}) {
    const method = options.method || 'GET';
    const needsToken = method !== 'GET' || options.requireAuth;

    if (needsToken && !config.githubToken) {
        const err = new Error('服务器未配置 GITHUB_TOKEN');
        err.status = 500;
        throw err;
    }

    const headers = {
        'Accept': 'application/vnd.github.v3+json',
        'Content-Type': 'application/json',
        'User-Agent': 'personal-website-cloudflare-worker'
    };

    if (config.githubToken) {
        headers['Authorization'] = `Bearer ${config.githubToken}`;
    }

    const resp = await fetch(`${GITHUB_API}${path}`, {
        method,
        headers,
        body: options.body ? JSON.stringify(options.body) : undefined
    });

    const text = await resp.text();
    let data = null;
    try {
        data = text ? JSON.parse(text) : null;
    } catch {
        data = { message: text };
    }

    if (!resp.ok) {
        const err = new Error(data?.message || `GitHub API 请求失败: ${resp.status}`);
        err.status = resp.status;
        err.data = data;
        throw err;
    }

    return data;
}

function mapPosts(issues) {
    return issues
        .filter(issue => !issue.pull_request && !issue.labels?.some(label => label.name === 'avatar'))
        .map(issue => {
            let date = '';
            if (issue.labels && issue.labels.length > 0) {
                for (const label of issue.labels) {
                    if (label.name && label.name.startsWith('date:')) {
                        date = label.name.replace('date:', '');
                        break;
                    }
                }
            }
            if (!date) {
                date = new Date(issue.created_at).toISOString().split('T')[0];
            }

            return {
                objectId: issue.id.toString(),
                number: issue.number,
                title: issue.title || '无标题',
                body: issue.body || '',
                date,
                created_at: issue.created_at
            };
        });
}

async function getAvatar(config) {
    const issues = await githubRequest(config, `/repos/${config.githubOwner}/${config.githubRepo}/issues?labels=avatar&state=all&per_page=1`);
    if (!issues || issues.length === 0) return { avatarUrl: null };

    const issue = issues[0];
    const bodyMatch = (issue.body || '').match(/!\[.*?\]\((.*?)\)/);
    if (bodyMatch) return { avatarUrl: bodyMatch[1] };

    const comments = await githubRequest(config, `/repos/${config.githubOwner}/${config.githubRepo}/issues/${issue.number}/comments?per_page=20`);
    for (const comment of comments) {
        const commentMatch = (comment.body || '').match(/!\[.*?\]\((.*?)\)/);
        if (commentMatch) return { avatarUrl: commentMatch[1] };
    }

    return { avatarUrl: null };
}

async function uploadAvatar(config, imageDataUrl) {
    if (!imageDataUrl || !imageDataUrl.startsWith('data:image')) {
        const err = new Error('头像数据无效');
        err.status = 400;
        throw err;
    }

    const issues = await githubRequest(config, `/repos/${config.githubOwner}/${config.githubRepo}/issues?labels=avatar&state=all&per_page=1`);
    const body = `# 头像\n\n![头像](${imageDataUrl})\n\n> 此 Issue 用于存储头像，请勿删除或修改。`;

    if (issues && issues.length > 0) {
        await githubRequest(config, `/repos/${config.githubOwner}/${config.githubRepo}/issues/${issues[0].number}`, {
            method: 'PATCH',
            body: { body, labels: ['avatar'] }
        });
        return { ok: true, issueNumber: issues[0].number };
    }

    const created = await githubRequest(config, `/repos/${config.githubOwner}/${config.githubRepo}/issues`, {
        method: 'POST',
        body: { title: '头像存储', body, labels: ['avatar'] }
    });
    return { ok: true, issueNumber: created.number };
}

export async function onRequest(context) {
    const { request, env } = context;
    const config = getConfig(env);

    try {
        const url = new URL(request.url);
        const action = url.searchParams.get('action') || 'posts';
        const method = request.method.toUpperCase();
        const body = method === 'GET' ? {} : await readBody(request);

        if (action === 'verify' && method === 'POST') {
            const admin = await verifyAdmin(config, body);
            if (!admin.ok) return json({ ok: false, message: admin.message }, admin.status);
            return json({ ok: true }, 200, {
                'Set-Cookie': await setAdminSessionCookie(request, config)
            });
        }

        if (action === 'logout' && method === 'POST') {
            return json({ ok: true }, 200, {
                'Set-Cookie': clearAdminSessionCookie()
            });
        }

        if (action === 'posts' && method === 'GET') {
            const issues = await githubRequest(config, `/repos/${config.githubOwner}/${config.githubRepo}/issues?state=open&sort=created&direction=desc&per_page=50`);
            return json({ posts: mapPosts(issues) });
        }

        if (action === 'avatar' && method === 'GET') {
            return json(await getAvatar(config));
        }

        const protectedActions = ['uploadAvatar', 'createPost', 'updatePost', 'deletePost'];
        if (protectedActions.includes(action)) {
            if (!await verifyAdminSession(request, config)) {
                return json({ ok: false, message: '管理员登录已过期，请重新登录' }, 401);
            }
        }

        if (action === 'uploadAvatar' && method === 'POST') {
            return json(await uploadAvatar(config, body.imageDataUrl));
        }

        if (action === 'createPost' && method === 'POST') {
            const created = await githubRequest(config, `/repos/${config.githubOwner}/${config.githubRepo}/issues`, {
                method: 'POST',
                body: { title: body.title, body: body.body, labels: [`date:${body.date}`] }
            });
            return json(created);
        }

        if (action === 'updatePost' && method === 'PATCH') {
            const updated = await githubRequest(config, `/repos/${config.githubOwner}/${config.githubRepo}/issues/${body.issueNumber}`, {
                method: 'PATCH',
                body: { title: body.title, body: body.body, labels: [`date:${body.date}`] }
            });
            return json(updated);
        }

        if (action === 'deletePost' && method === 'PATCH') {
            const deleted = await githubRequest(config, `/repos/${config.githubOwner}/${config.githubRepo}/issues/${body.issueNumber}`, {
                method: 'PATCH',
                body: { state: 'closed' }
            });
            return json(deleted);
        }

        return json({ ok: false, message: '接口不存在' }, 404);
    } catch (err) {
        console.error(err);
        return json({
            ok: false,
            message: err.message || '服务器错误',
            detail: err.data || null
        }, err.status || 500);
    }
}
