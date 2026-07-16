const crypto = require('crypto');

const GITHUB_API = 'https://api.github.com';
const GITHUB_OWNER = process.env.GITHUB_OWNER || 'zhedaotixuanbo';
const GITHUB_REPO = process.env.GITHUB_REPO || 'PersonalWebsite';
const ADMIN_SESSION_COOKIE = 'admin_session';
const ADMIN_SESSION_MAX_AGE = 60 * 60 * 12;

function sendJson(res, statusCode, data) {
    res.statusCode = statusCode;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify(data));
}

function getAction(req) {
    const url = new URL(req.url, 'http://localhost');
    return url.searchParams.get('action') || 'posts';
}

function sha256(text) {
    return crypto.createHash('sha256').update(text || '', 'utf8').digest('hex');
}

function safeEqual(a, b) {
    if (!a || !b || a.length !== b.length) return false;
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
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

function getSessionSecret() {
    return process.env.ADMIN_SESSION_SECRET || process.env.GITHUB_TOKEN || process.env.ADMIN_PASSWORD_HASH || '';
}

function signSession(timestamp) {
    return crypto
        .createHmac('sha256', getSessionSecret())
        .update(String(timestamp))
        .digest('hex');
}

function buildSessionCookie() {
    const timestamp = Date.now();
    const signature = signSession(timestamp);
    return `${timestamp}.${signature}`;
}

function setAdminSessionCookie(res) {
    const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
    res.setHeader(
        'Set-Cookie',
        `${ADMIN_SESSION_COOKIE}=${encodeURIComponent(buildSessionCookie())}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${ADMIN_SESSION_MAX_AGE}${secure}`
    );
}

function clearAdminSessionCookie(res) {
    res.setHeader(
        'Set-Cookie',
        `${ADMIN_SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`
    );
}

function verifyAdminSession(req) {
    const secret = getSessionSecret();
    if (!secret) return false;

    const cookies = parseCookies(req.headers.cookie || '');
    const value = cookies[ADMIN_SESSION_COOKIE];
    if (!value) return false;

    const [timestampText, signature] = value.split('.');
    const timestamp = Number(timestampText);
    if (!timestamp || !signature) return false;

    const age = Date.now() - timestamp;
    if (age < 0 || age > ADMIN_SESSION_MAX_AGE * 1000) return false;

    return safeEqual(signSession(timestamp), signature);
}

async function readBody(req) {
    if (req.body && typeof req.body === 'object') return req.body;
    if (typeof req.body === 'string') {
        try {
            return JSON.parse(req.body);
        } catch {
            return {};
        }
    }

    const chunks = [];
    for await (const chunk of req) {
        chunks.push(chunk);
    }
    const raw = Buffer.concat(chunks).toString('utf8');
    if (!raw) return {};
    try {
        return JSON.parse(raw);
    } catch {
        return {};
    }
}

async function verifyAdmin(req, body) {
    const expectedHash = process.env.ADMIN_PASSWORD_HASH;
    if (!expectedHash) {
        return { ok: false, status: 500, message: '服务器未配置 ADMIN_PASSWORD_HASH' };
    }

    const password = body.password || req.headers['x-admin-password'] || '';
    const actualHash = sha256(password);
    if (!safeEqual(actualHash, expectedHash)) {
        return { ok: false, status: 401, message: '管理员密码错误' };
    }

    return { ok: true };
}

async function githubRequest(path, options = {}) {
    const token = process.env.GITHUB_TOKEN;
    if (!token) {
        const err = new Error('服务器未配置 GITHUB_TOKEN');
        err.status = 500;
        throw err;
    }

    const resp = await fetch(`${GITHUB_API}${path}`, {
        method: options.method || 'GET',
        headers: {
            'Accept': 'application/vnd.github.v3+json',
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
            'User-Agent': 'personal-website-api'
        },
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

async function getAvatar() {
    const issues = await githubRequest(`/repos/${GITHUB_OWNER}/${GITHUB_REPO}/issues?labels=avatar&state=all&per_page=1`);
    if (!issues || issues.length === 0) return { avatarUrl: null };

    const issue = issues[0];
    const bodyMatch = (issue.body || '').match(/!\[.*?\]\((.*?)\)/);
    if (bodyMatch) return { avatarUrl: bodyMatch[1] };

    const comments = await githubRequest(`/repos/${GITHUB_OWNER}/${GITHUB_REPO}/issues/${issue.number}/comments?per_page=20`);
    for (const comment of comments) {
        const commentMatch = (comment.body || '').match(/!\[.*?\]\((.*?)\)/);
        if (commentMatch) return { avatarUrl: commentMatch[1] };
    }

    return { avatarUrl: null };
}

async function uploadAvatar(imageDataUrl) {
    if (!imageDataUrl || !imageDataUrl.startsWith('data:image')) {
        const err = new Error('头像数据无效');
        err.status = 400;
        throw err;
    }

    const issues = await githubRequest(`/repos/${GITHUB_OWNER}/${GITHUB_REPO}/issues?labels=avatar&state=all&per_page=1`);
    const body = `# 头像\n\n![头像](${imageDataUrl})\n\n> 此 Issue 用于存储头像，请勿删除或修改。`;

    if (issues && issues.length > 0) {
        await githubRequest(`/repos/${GITHUB_OWNER}/${GITHUB_REPO}/issues/${issues[0].number}`, {
            method: 'PATCH',
            body: { body, labels: ['avatar'] }
        });
        return { ok: true, issueNumber: issues[0].number };
    }

    const created = await githubRequest(`/repos/${GITHUB_OWNER}/${GITHUB_REPO}/issues`, {
        method: 'POST',
        body: { title: '头像存储', body, labels: ['avatar'] }
    });
    return { ok: true, issueNumber: created.number };
}

module.exports = async function handler(req, res) {
    try {
        const action = getAction(req);
        const body = await readBody(req);

        if (action === 'verify') {
            const admin = await verifyAdmin(req, body);
            if (!admin.ok) return sendJson(res, admin.status, { ok: false, message: admin.message });
            setAdminSessionCookie(res);
            return sendJson(res, 200, { ok: true });
        }

        if (action === 'logout') {
            clearAdminSessionCookie(res);
            return sendJson(res, 200, { ok: true });
        }

        if (action === 'posts' && req.method === 'GET') {
            const issues = await githubRequest(`/repos/${GITHUB_OWNER}/${GITHUB_REPO}/issues?state=open&sort=created&direction=desc&per_page=50`);
            return sendJson(res, 200, { posts: mapPosts(issues) });
        }

        if (action === 'avatar' && req.method === 'GET') {
            return sendJson(res, 200, await getAvatar());
        }

        const protectedActions = ['uploadAvatar', 'createPost', 'updatePost', 'deletePost'];
        if (protectedActions.includes(action)) {
            if (!verifyAdminSession(req)) {
                return sendJson(res, 401, { ok: false, message: '管理员登录已过期，请重新登录' });
            }
        }

        if (action === 'uploadAvatar' && req.method === 'POST') {
            return sendJson(res, 200, await uploadAvatar(body.imageDataUrl));
        }

        if (action === 'createPost' && req.method === 'POST') {
            const created = await githubRequest(`/repos/${GITHUB_OWNER}/${GITHUB_REPO}/issues`, {
                method: 'POST',
                body: { title: body.title, body: body.body, labels: [`date:${body.date}`] }
            });
            return sendJson(res, 200, created);
        }

        if (action === 'updatePost' && req.method === 'PATCH') {
            const updated = await githubRequest(`/repos/${GITHUB_OWNER}/${GITHUB_REPO}/issues/${body.issueNumber}`, {
                method: 'PATCH',
                body: { title: body.title, body: body.body, labels: [`date:${body.date}`] }
            });
            return sendJson(res, 200, updated);
        }

        if (action === 'deletePost' && req.method === 'PATCH') {
            const deleted = await githubRequest(`/repos/${GITHUB_OWNER}/${GITHUB_REPO}/issues/${body.issueNumber}`, {
                method: 'PATCH',
                body: { state: 'closed' }
            });
            return sendJson(res, 200, deleted);
        }

        return sendJson(res, 404, { ok: false, message: '接口不存在' });
    } catch (err) {
        console.error(err);
        return sendJson(res, err.status || 500, {
            ok: false,
            message: err.message || '服务器错误',
            detail: err.data || null
        });
    }
};
