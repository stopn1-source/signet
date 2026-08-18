// 시그넷(Signet) 백엔드 — Cloudflare Worker
//
// 주요 action:
//  - signup / login (로그인 불필요)
//  - save_favorite / list_favorites / remove_favorite / update_checklist
//  - save_history / list_history / clear_history
//  - submit_feedback / change_password / change_username / get_usage / consume_usage / set_avatar
//  - check_username (로그인 불필요, 아이디 중복확인)
//  - create_post / list_posts / delete_post / reply_to_post / delete_reply / report_content
//  - 그 외(action 없음): AI 주제 추천 요청 처리
//  (아래 항목 제외하고는 모두 로그인 필요)
//
// 신고(report_content)된 글은 자동으로 삭제되지 않아요. report: 로 시작하는
// KV 키를 대시보드에서 직접 확인하고, 필요하면 posts 키 안의 해당 글/답글을
// 수동으로 지워주세요 (지금은 별도 관리자 화면이 없어요).
//
// === 배포 전 꼭 필요한 설정 ===
//
// 1) KV 네임스페이스 생성 및 연결
//    Cloudflare 대시보드 → Workers & Pages → Worker 선택 → Settings → Bindings
//    → Add binding → KV Namespace → 새로 만들기(이름 예: signet-users)
//    → 변수 이름(Variable name)은 정확히 APP_KV 로 입력
//
// 2) 환경 변수(Secret)
//    ANTHROPIC_API_KEY = Anthropic에서 발급받은 API 키
//
// APP_SECRET(예전 방식)은 더 이상 필요 없어요 — 이제 진짜 로그인으로 보호돼요.

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const salt = saltHex ? hexToBytes(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial, 256
  );
  return { hash: bytesToHex(new Uint8Array(bits)), salt: bytesToHex(salt) };
}

function jsonResponse(obj, status, corsHeaders) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}

export default {
  async fetch(request, env) {
    // 무료/유료 등급별 하루 사용량 한도 (원시 API 호출 기준 — 주제 추천 1번에 보통 4~5회 호출됨)
    // 나중에 실제 가격/정책 정하시면 이 숫자만 바꾸면 돼요.
    const FREE_DAILY_LIMIT = 30;
    const PAID_DAILY_LIMIT = 300;

    // 카카오/네이버 로그인 완료 후 사용자를 돌려보낼 프론트엔드(Cloudflare Pages) 주소.
    // 실제 Pages 주소로 꼭 바꿔주세요 (예: https://your-pages-site.pages.dev).
    const PAGES_URL = "https://lingering-sun-b4f9.stopn1.workers.dev";

    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    // 바인딩 이름에 실수로 공백이 섞여 있어도 찾아내기 위한 방어 코드
    const kvKey = Object.keys(env).find(k => k.trim() === "APP_KV");
    const APP_KV = kvKey ? env[kvKey] : null;

    if (!APP_KV) {
      return jsonResponse({ error: "서버에 저장소(KV)가 연결되지 않았어요. Settings → Bindings에서 APP_KV를 추가해주세요.", debug_env_keys: Object.keys(env) }, 500, corsHeaders);
    }

    // ===== 카카오/네이버 로그인 콜백 (GET, 브라우저가 카카오/네이버에서 돌아올 때) =====
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/oauth/kakao/callback") {
      return await handleOAuthCallback("kakao", url, env, APP_KV, PAGES_URL);
    }
    if (request.method === "GET" && url.pathname === "/oauth/naver/callback") {
      return await handleOAuthCallback("naver", url, env, APP_KV, PAGES_URL);
    }

    if (request.method !== "POST") {
      return new Response("이 서버는 POST 요청만 받아요.", { status: 405, headers: corsHeaders });
    }

    let body;
    try {
      body = await request.json();
    } catch (e) {
      return jsonResponse({ error: "요청 형식이 올바르지 않아요." }, 400, corsHeaders);
    }

    // 이 아래부터는 예상 못한 오류가 나더라도(예: 저장된 데이터 손상) 항상
    // CORS 헤더가 붙은 JSON으로 응답한다. 그래야 브라우저에서 원인 모를
    // "Failed to fetch"가 아니라 실제 오류 메시지를 볼 수 있다.
    try {
      return await handleAction(body, request, env, APP_KV, corsHeaders, FREE_DAILY_LIMIT, PAID_DAILY_LIMIT);
    } catch (err) {
      return jsonResponse({ error: "예상하지 못한 서버 오류가 발생했어요: " + err.message }, 500, corsHeaders);
    }
  },
};

async function handleAction(body, request, env, APP_KV, corsHeaders, FREE_DAILY_LIMIT, PAID_DAILY_LIMIT) {
    // ===== 회원가입 =====
    if (body.action === "signup") {
      const username = (body.username || "").trim();
      const password = body.password || "";
      const birthdate = (body.birthdate || "").trim();
      const PASSWORD_RULE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;
      if (username.length < 2 || username.length > 30) {
        return jsonResponse({ error: "아이디는 2~30자로 입력해주세요." }, 400, corsHeaders);
      }
      if (!PASSWORD_RULE.test(password)) {
        return jsonResponse({ error: "비밀번호는 영문 대문자·소문자·숫자·특수문자를 각각 1개 이상 포함해서 8자 이상이어야 해요." }, 400, corsHeaders);
      }
      if (!/^\d{4}-\d{2}-\d{2}$/.test(birthdate) || new Date(birthdate) > new Date()) {
        return jsonResponse({ error: "생년월일을 올바르게 입력해주세요." }, 400, corsHeaders);
      }
      const existing = await APP_KV.get("user:" + username);
      if (existing) {
        return jsonResponse({ error: "이미 사용 중인 아이디예요. 다른 아이디를 입력해주세요." }, 409, corsHeaders);
      }
      const { hash, salt } = await hashPassword(password);
      await APP_KV.put("user:" + username, JSON.stringify({ hash, salt, birthdate, plan: "free", createdAt: Date.now() }));
      return jsonResponse({ success: true }, 200, corsHeaders);
    }

    // ===== 아이디 중복확인 =====
    if (body.action === "check_username") {
      const checkUsername = (body.username || "").trim();
      if (checkUsername.length < 2 || checkUsername.length > 30) {
        return jsonResponse({ error: "아이디는 2~30자로 입력해주세요." }, 400, corsHeaders);
      }
      const existing = await APP_KV.get("user:" + checkUsername);
      return jsonResponse({ success: true, available: !existing }, 200, corsHeaders);
    }

    // ===== 로그인 =====
    if (body.action === "login") {
      const username = (body.username || "").trim();
      const password = body.password || "";
      const record = await APP_KV.get("user:" + username);
      if (!record) {
        return jsonResponse({ error: "아이디 또는 비밀번호가 올바르지 않아요." }, 401, corsHeaders);
      }
      const userObj = JSON.parse(record);
      const { hash: storedHash, salt } = userObj;
      const { hash: attemptHash } = await hashPassword(password, salt);
      if (attemptHash !== storedHash) {
        return jsonResponse({ error: "아이디 또는 비밀번호가 올바르지 않아요." }, 401, corsHeaders);
      }
      const token = crypto.randomUUID();
      await APP_KV.put("session:" + token, username, { expirationTtl: 2592000 }); // 30일
      return jsonResponse({ success: true, token, username, plan: userObj.plan || "free" }, 200, corsHeaders);
    }

    // ===== 그 외: 로그인이 필요한 요청들 =====
    const authHeader = request.headers.get("Authorization") || "";
    const token = authHeader.replace(/^Bearer\s+/i, "").trim();
    if (!token) {
      return jsonResponse({ error: "로그인이 필요해요." }, 401, corsHeaders);
    }
    const username = await APP_KV.get("session:" + token);
    if (!username) {
      return jsonResponse({ error: "로그인이 만료됐어요. 다시 로그인해주세요." }, 401, corsHeaders);
    }

    // ===== 찜하기 =====
    if (body.action === "save_favorite") {
      const topic = body.topic;
      if (!topic || !topic.title) {
        return jsonResponse({ error: "저장할 주제 정보가 없어요." }, 400, corsHeaders);
      }
      const listRaw = await APP_KV.get("fav:" + username);
      const list = listRaw ? JSON.parse(listRaw) : [];
      if (list.length >= 50) {
        return jsonResponse({ error: "찜은 최대 50개까지 저장할 수 있어요. 몇 개 지우고 다시 시도해주세요." }, 400, corsHeaders);
      }
      const entry = { ...topic, id: crypto.randomUUID(), savedAt: Date.now() };
      list.unshift(entry);
      await APP_KV.put("fav:" + username, JSON.stringify(list));
      return jsonResponse({ success: true, id: entry.id }, 200, corsHeaders);
    }

    // ===== 찜 목록 보기 =====
    if (body.action === "list_favorites") {
      const listRaw = await APP_KV.get("fav:" + username);
      const list = listRaw ? JSON.parse(listRaw) : [];
      return jsonResponse({ success: true, favorites: list }, 200, corsHeaders);
    }

    // ===== 찜 삭제 =====
    if (body.action === "remove_favorite") {
      const listRaw = await APP_KV.get("fav:" + username);
      const list = listRaw ? JSON.parse(listRaw) : [];
      const filtered = list.filter(f => f.id !== body.id);
      await APP_KV.put("fav:" + username, JSON.stringify(filtered));
      return jsonResponse({ success: true }, 200, corsHeaders);
    }

    // ===== 찜한 주제의 탐구 진행 체크리스트 업데이트 =====
    if (body.action === "update_checklist") {
      if (!Array.isArray(body.checklist)) {
        return jsonResponse({ error: "체크리스트 형식이 올바르지 않아요." }, 400, corsHeaders);
      }
      const listRaw = await APP_KV.get("fav:" + username);
      const list = listRaw ? JSON.parse(listRaw) : [];
      const target = list.find(f => f.id === body.favoriteId);
      if (!target) {
        return jsonResponse({ error: "찜한 주제를 찾을 수 없어요." }, 404, corsHeaders);
      }
      target.checklist = body.checklist.slice(0, 20).map(Boolean);
      await APP_KV.put("fav:" + username, JSON.stringify(list));
      return jsonResponse({ success: true }, 200, corsHeaders);
    }

    // ===== 전체 기록 저장 (자동, 학생이 볼 때마다) =====
    if (body.action === "save_history") {
      const topic = body.topic;
      if (!topic || !topic.title) {
        return jsonResponse({ error: "저장할 주제 정보가 없어요." }, 400, corsHeaders);
      }
      const listRaw = await APP_KV.get("hist:" + username);
      const list = listRaw ? JSON.parse(listRaw) : [];
      const entry = { ...topic, id: crypto.randomUUID(), savedAt: Date.now() };
      list.unshift(entry);
      const trimmed = list.slice(0, 100); // 최근 100개까지만 보관
      await APP_KV.put("hist:" + username, JSON.stringify(trimmed));
      return jsonResponse({ success: true }, 200, corsHeaders);
    }

    // ===== 전체 기록 보기 =====
    if (body.action === "list_history") {
      const listRaw = await APP_KV.get("hist:" + username);
      const list = listRaw ? JSON.parse(listRaw) : [];
      return jsonResponse({ success: true, history: list }, 200, corsHeaders);
    }

    // ===== 전체 기록 비우기 =====
    if (body.action === "clear_history") {
      await APP_KV.delete("hist:" + username);
      return jsonResponse({ success: true }, 200, corsHeaders);
    }

    // ===== 피드백 보내기 =====
    if (body.action === "submit_feedback") {
      const message = (body.message || "").trim();
      if (!message) {
        return jsonResponse({ error: "내용을 입력해주세요." }, 400, corsHeaders);
      }
      if (message.length > 2000) {
        return jsonResponse({ error: "내용이 너무 길어요. 2000자 이내로 줄여주세요." }, 400, corsHeaders);
      }
      const key = "feedback:" + Date.now() + "-" + crypto.randomUUID().slice(0, 8);
      await APP_KV.put(key, JSON.stringify({ username, message, submittedAt: Date.now() }));
      return jsonResponse({ success: true }, 200, corsHeaders);
    }

    // ===== 아바타 설정 =====
    if (body.action === "set_avatar") {
      const ALLOWED_AVATARS = ["🦊","🐱","🐰","🐻","🐼","🦉","🐨","🐯","🦁","🐸","🐧","🦄","🐶","🐹","🐢","🦋","🐺","🦝","🦔","🦓","🐮","🐷","🐵","🦒","🐘","🦥","🦦","🦩","🐬","🦅","🐴","🦌"];
      const avatar = body.avatar || "";
      if (!ALLOWED_AVATARS.includes(avatar)) {
        return jsonResponse({ error: "선택할 수 없는 아바타예요." }, 400, corsHeaders);
      }
      const record = await APP_KV.get("user:" + username);
      if (!record) {
        return jsonResponse({ error: "계정 정보를 찾을 수 없어요." }, 404, corsHeaders);
      }
      const userObj = JSON.parse(record);
      await APP_KV.put("user:" + username, JSON.stringify({ ...userObj, avatar }));
      return jsonResponse({ success: true, avatar }, 200, corsHeaders);
    }

    // ===== Q&A 게시판: 글쓰기 =====
    if (body.action === "create_post") {
      const title = (body.title || "").trim();
      const postBody = (body.body || "").trim();
      const room = (body.room || "").trim().slice(0, 30) || "자유";
      if (!title || !postBody) {
        return jsonResponse({ error: "제목과 내용을 모두 입력해주세요." }, 400, corsHeaders);
      }
      if (title.length > 100) {
        return jsonResponse({ error: "제목은 100자 이내로 써주세요." }, 400, corsHeaders);
      }
      if (postBody.length > 2000) {
        return jsonResponse({ error: "내용은 2000자 이내로 써주세요." }, 400, corsHeaders);
      }
      const userRecord = await APP_KV.get("user:" + username);
      const avatar = userRecord ? (JSON.parse(userRecord).avatar || "👤") : "👤";
      const listRaw = await APP_KV.get("posts");
      const list = listRaw ? JSON.parse(listRaw) : [];
      const entry = {
        id: crypto.randomUUID(), username, avatar, title, body: postBody, room,
        createdAt: Date.now(), replies: []
      };
      list.unshift(entry);
      const trimmed = list.slice(0, 300);
      await APP_KV.put("posts", JSON.stringify(trimmed));
      return jsonResponse({ success: true, id: entry.id }, 200, corsHeaders);
    }

    // ===== Q&A 게시판: 목록 보기 =====
    if (body.action === "list_posts") {
      const listRaw = await APP_KV.get("posts");
      const list = listRaw ? JSON.parse(listRaw) : [];
      return jsonResponse({ success: true, posts: list.slice(0, 50) }, 200, corsHeaders);
    }

    // ===== Q&A 게시판: 글 삭제 (본인 글만) =====
    if (body.action === "delete_post") {
      const listRaw = await APP_KV.get("posts");
      const list = listRaw ? JSON.parse(listRaw) : [];
      const target = list.find(p => p.id === body.postId);
      if (!target) {
        return jsonResponse({ error: "이미 삭제된 글이에요." }, 404, corsHeaders);
      }
      if (target.username !== username) {
        return jsonResponse({ error: "본인이 쓴 글만 삭제할 수 있어요." }, 403, corsHeaders);
      }
      const filtered = list.filter(p => p.id !== body.postId);
      await APP_KV.put("posts", JSON.stringify(filtered));
      return jsonResponse({ success: true }, 200, corsHeaders);
    }

    // ===== Q&A 게시판: 답글 달기 =====
    if (body.action === "reply_to_post") {
      const replyBody = (body.body || "").trim();
      if (!replyBody) {
        return jsonResponse({ error: "답글 내용을 입력해주세요." }, 400, corsHeaders);
      }
      if (replyBody.length > 1000) {
        return jsonResponse({ error: "답글은 1000자 이내로 써주세요." }, 400, corsHeaders);
      }
      const userRecord = await APP_KV.get("user:" + username);
      const avatar = userRecord ? (JSON.parse(userRecord).avatar || "👤") : "👤";
      const listRaw = await APP_KV.get("posts");
      const list = listRaw ? JSON.parse(listRaw) : [];
      const target = list.find(p => p.id === body.postId);
      if (!target) {
        return jsonResponse({ error: "글을 찾을 수 없어요." }, 404, corsHeaders);
      }
      if (!target.replies) target.replies = [];
      target.replies.push({ id: crypto.randomUUID(), username, avatar, body: replyBody, createdAt: Date.now() });
      await APP_KV.put("posts", JSON.stringify(list));
      return jsonResponse({ success: true }, 200, corsHeaders);
    }

    // ===== Q&A 게시판: 답글 삭제 (본인 답글만) =====
    if (body.action === "delete_reply") {
      const listRaw = await APP_KV.get("posts");
      const list = listRaw ? JSON.parse(listRaw) : [];
      const target = list.find(p => p.id === body.postId);
      if (!target || !target.replies) {
        return jsonResponse({ error: "글을 찾을 수 없어요." }, 404, corsHeaders);
      }
      const reply = target.replies.find(r => r.id === body.replyId);
      if (!reply) {
        return jsonResponse({ error: "이미 삭제된 답글이에요." }, 404, corsHeaders);
      }
      if (reply.username !== username) {
        return jsonResponse({ error: "본인이 쓴 답글만 삭제할 수 있어요." }, 403, corsHeaders);
      }
      target.replies = target.replies.filter(r => r.id !== body.replyId);
      await APP_KV.put("posts", JSON.stringify(list));
      return jsonResponse({ success: true }, 200, corsHeaders);
    }

    // ===== Q&A 게시판: 신고 (제작자가 수동으로 검토) =====
    if (body.action === "report_content") {
      const reason = (body.reason || "").trim().slice(0, 500);
      const key = "report:" + Date.now() + "-" + crypto.randomUUID().slice(0, 8);
      await APP_KV.put(key, JSON.stringify({
        reportedBy: username,
        postId: body.postId || null,
        replyId: body.replyId || null,
        reason,
        reportedAt: Date.now()
      }));
      return jsonResponse({ success: true }, 200, corsHeaders);
    }

    // ===== 아이디 변경 (찜/기록/과제/게시글까지 함께 옮긴다) =====
    if (body.action === "change_username") {
      const newUsername = (body.newUsername || "").trim();
      const currentPassword = body.currentPassword || "";
      if (newUsername.length < 2 || newUsername.length > 30) {
        return jsonResponse({ error: "아이디는 2~30자로 입력해주세요." }, 400, corsHeaders);
      }
      if (newUsername === username) {
        return jsonResponse({ error: "지금 아이디랑 같아요." }, 400, corsHeaders);
      }
      const existingNew = await APP_KV.get("user:" + newUsername);
      if (existingNew) {
        return jsonResponse({ error: "이미 사용 중인 아이디예요." }, 409, corsHeaders);
      }
      const record = await APP_KV.get("user:" + username);
      if (!record) {
        return jsonResponse({ error: "계정 정보를 찾을 수 없어요." }, 404, corsHeaders);
      }
      const userObj = JSON.parse(record);
      const { hash: attemptHash } = await hashPassword(currentPassword, userObj.salt);
      if (attemptHash !== userObj.hash) {
        return jsonResponse({ error: "비밀번호가 올바르지 않아요." }, 401, corsHeaders);
      }

      // 계정 정보 이전
      await APP_KV.put("user:" + newUsername, JSON.stringify(userObj));
      await APP_KV.delete("user:" + username);

      // 찜 / 전체기록 / 과제 이전
      for (const prefix of ["fav:", "hist:", "assign:"]) {
        const dataRaw = await APP_KV.get(prefix + username);
        if (dataRaw) {
          await APP_KV.put(prefix + newUsername, dataRaw);
          await APP_KV.delete(prefix + username);
        }
      }

      // 커뮤니티 글/답글 안의 작성자 이름도 이전
      const postsRaw = await APP_KV.get("posts");
      if (postsRaw) {
        const posts = JSON.parse(postsRaw);
        posts.forEach(p => {
          if (p.username === username) p.username = newUsername;
          (p.replies || []).forEach(r => {
            if (r.username === username) r.username = newUsername;
          });
        });
        await APP_KV.put("posts", JSON.stringify(posts));
      }

      // 지금 로그인된 세션은 새 아이디로 계속 이어지게 갱신
      await APP_KV.put("session:" + token, newUsername, { expirationTtl: 2592000 });

      return jsonResponse({ success: true, newUsername }, 200, corsHeaders);
    }

    // ===== 비밀번호 변경 =====
    if (body.action === "change_password") {
      const currentPassword = body.currentPassword || "";
      const newPassword = body.newPassword || "";
      const PASSWORD_RULE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;
      const record = await APP_KV.get("user:" + username);
      if (!record) {
        return jsonResponse({ error: "계정 정보를 찾을 수 없어요." }, 404, corsHeaders);
      }
      const userObj = JSON.parse(record);
      const { hash: attemptHash } = await hashPassword(currentPassword, userObj.salt);
      if (attemptHash !== userObj.hash) {
        return jsonResponse({ error: "현재 비밀번호가 올바르지 않아요." }, 401, corsHeaders);
      }
      if (!PASSWORD_RULE.test(newPassword)) {
        return jsonResponse({ error: "새 비밀번호는 영문 대문자·소문자·숫자·특수문자를 각각 1개 이상 포함해서 8자 이상이어야 해요." }, 400, corsHeaders);
      }
      const { hash, salt } = await hashPassword(newPassword);
      await APP_KV.put("user:" + username, JSON.stringify({ ...userObj, hash, salt }));
      return jsonResponse({ success: true }, 200, corsHeaders);
    }

    // ===== 과제 추가 =====
    if (body.action === "add_assignment") {
      const title = (body.title || "").trim();
      const dueDate = (body.dueDate || "").trim();
      const memo = (body.memo || "").trim();
      if (!title) {
        return jsonResponse({ error: "과제 이름을 입력해주세요." }, 400, corsHeaders);
      }
      if (!/^\d{4}-\d{2}-\d{2}$/.test(dueDate)) {
        return jsonResponse({ error: "마감일을 올바르게 입력해주세요." }, 400, corsHeaders);
      }
      const listRaw = await APP_KV.get("assign:" + username);
      const list = listRaw ? JSON.parse(listRaw) : [];
      if (list.length >= 50) {
        return jsonResponse({ error: "과제는 최대 50개까지 등록할 수 있어요. 다 끝난 것부터 지워주세요." }, 400, corsHeaders);
      }
      const entry = { id: crypto.randomUUID(), title, dueDate, memo, createdAt: Date.now() };
      list.push(entry);
      await APP_KV.put("assign:" + username, JSON.stringify(list));
      return jsonResponse({ success: true, id: entry.id }, 200, corsHeaders);
    }

    // ===== 과제 목록 (마감일 가까운 순) =====
    if (body.action === "list_assignments") {
      const listRaw = await APP_KV.get("assign:" + username);
      const list = listRaw ? JSON.parse(listRaw) : [];
      list.sort((a, b) => a.dueDate.localeCompare(b.dueDate));
      return jsonResponse({ success: true, assignments: list }, 200, corsHeaders);
    }

    // ===== 과제 삭제 =====
    if (body.action === "delete_assignment") {
      const listRaw = await APP_KV.get("assign:" + username);
      const list = listRaw ? JSON.parse(listRaw) : [];
      const filtered = list.filter(a => a.id !== body.id);
      await APP_KV.put("assign:" + username, JSON.stringify(filtered));
      return jsonResponse({ success: true }, 200, corsHeaders);
    }

    // ===== 사용량 조회 (무료/유료 한도, 오늘 사용량, 계정 정보) =====
    if (body.action === "get_usage") {
      const userRecord = await APP_KV.get("user:" + username);
      const userObj = userRecord ? JSON.parse(userRecord) : {};
      const plan = userObj.plan || "free";
      const today = new Date().toISOString().slice(0, 10);
      const userUsageKey = "usage:" + username + ":" + today;
      const used = parseInt((await APP_KV.get(userUsageKey)) || "0", 10);
      const limit = plan === "paid" ? PAID_DAILY_LIMIT : FREE_DAILY_LIMIT;
      return jsonResponse({ success: true, plan, used, limit, remaining: Math.max(0, limit - used), createdAt: userObj.createdAt || null, avatar: userObj.avatar || "👤" }, 200, corsHeaders);
    }

    // ===== 사용량 1회 차감 (버튼 하나를 눌러 시작하는 "행동" 단위로 딱 1회만 차감) =====
    // 프론트엔드가 주제찾기/예상질문/탐구연계/용어사전 등 "생성" 버튼을 누를 때
    // 딱 한 번 호출한다. 그 뒤로 탭을 열어보거나 내부적으로 API를 여러 번 호출해도
    // 여기서 더 깎지 않는다 — 사용자 입장에서 "버튼 한 번 = 1회"가 되도록.
    if (body.action === "consume_usage") {
      const userRecord = await APP_KV.get("user:" + username);
      const plan = userRecord ? (JSON.parse(userRecord).plan || "free") : "free";
      const today = new Date().toISOString().slice(0, 10);
      const userUsageKey = "usage:" + username + ":" + today;
      const used = parseInt((await APP_KV.get(userUsageKey)) || "0", 10);
      const limit = plan === "paid" ? PAID_DAILY_LIMIT : FREE_DAILY_LIMIT;
      if (used >= limit) {
        return jsonResponse({ error: "오늘 무료 사용 횟수를 다 쓰셨어요. 내일 다시 이용해주시거나, 곧 열릴 유료 플랜을 기다려주세요!", plan, limitReached: true }, 429, corsHeaders);
      }
      await APP_KV.put(userUsageKey, String(used + 1), { expirationTtl: 172800 });
      return jsonResponse({ success: true, used: used + 1, limit, remaining: Math.max(0, limit - used - 1) }, 200, corsHeaders);
    }

    // ===== 그 외: AI 요청 처리 =====
    if (!env.ANTHROPIC_API_KEY) {
      return jsonResponse({ error: "서버에 API 키가 설정되지 않았어요. Settings에서 ANTHROPIC_API_KEY를 추가해주세요." }, 500, corsHeaders);
    }

    // 전체 하루 사용량 상한 (모든 사용자 합산, 계정 도용/폭주 방지용 최후 안전장치)
    // 이건 개별 사용자 한도와 별개로, 서버 전체를 지키는 최후 방어선이라 계속 원시 호출마다 확인한다
    const today = new Date().toISOString().slice(0, 10);
    const usageKey = "count:" + today;
    const current = parseInt((await APP_KV.get(usageKey)) || "0", 10);
    const GLOBAL_DAILY_LIMIT = 1000;
    if (current >= GLOBAL_DAILY_LIMIT) {
      return jsonResponse({ error: "오늘 전체 사용량 한도를 넘었어요. 내일 다시 시도해주세요." }, 429, corsHeaders);
    }

    try {
      const anthropicBody = {
        model: body.model || "claude-sonnet-5",
        max_tokens: body.max_tokens || 1000,
        messages: body.messages,
      };
      // 실제 데이터가 필요한 요청(그래프용 데이터 등)은 검색 도구를 켜서
      // AI가 없는 데이터를 지어내지 않고 실제 자료를 찾아보게 한다
      if (body.enableSearch) {
        anthropicBody.tools = [{ type: "web_search_20250305", name: "web_search" }];
      }
      const anthropicResponse = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": env.ANTHROPIC_API_KEY,
          "anthropic-version": "2023-06-01",
          "user-agent": "signet-worker/1.0 (Cloudflare Workers)",
        },
        body: JSON.stringify(anthropicBody),
      });
      // 전체 상한 카운트는 여기서 계속 관리한다 (사용자별 한도는 consume_usage에서 별도 처리)
      if (anthropicResponse.ok) {
        await APP_KV.put(usageKey, String(current + 1), { expirationTtl: 172800 });
      }
      const data = await anthropicResponse.text();
      return new Response(data, {
        status: anthropicResponse.status,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    } catch (err) {
      return jsonResponse({ error: err.message }, 500, corsHeaders);
    }
}

// ============================================================
// 카카오/네이버 소셜 로그인
//
// 필요한 Secrets (Cloudflare Worker Settings → Variables and Secrets):
//   KAKAO_CLIENT_ID, KAKAO_CLIENT_SECRET (카카오 디벨로퍼스에서 발급, 시크릿은 선택이지만 등록 권장)
//   NAVER_CLIENT_ID, NAVER_CLIENT_SECRET (네이버 디벨로퍼스에서 발급)
//
// 각 플랫폼에 등록해야 하는 정확한 Redirect URI:
//   카카오: https://jinwon.stopn1.workers.dev/oauth/kakao/callback
//   네이버: https://jinwon.stopn1.workers.dev/oauth/naver/callback
// (Worker 주소가 바뀌면 이 문서 상단 주석과 콘솔 등록 URI를 함께 바꿔주세요)
// ============================================================

async function handleOAuthCallback(provider, url, env, APP_KV, PAGES_URL) {
  const code = url.searchParams.get("code");
  const errorParam = url.searchParams.get("error");

  if (errorParam || !code) {
    return Response.redirect(PAGES_URL + "/#oauth_error=" + encodeURIComponent(provider + "_denied"), 302);
  }

  try {
    const redirectUri = "https://jinwon.stopn1.workers.dev/oauth/" + provider + "/callback";
    let profile;
    if (provider === "kakao") {
      profile = await fetchKakaoProfile(code, redirectUri, env);
    } else {
      profile = await fetchNaverProfile(code, redirectUri, env);
    }

    if (!profile || !profile.id) {
      return Response.redirect(PAGES_URL + "/#oauth_error=" + encodeURIComponent(provider + "_profile_failed"), 302);
    }

    const username = await findOrCreateOAuthUser(provider, String(profile.id), profile.nickname, APP_KV);
    const token = crypto.randomUUID();
    await APP_KV.put("session:" + token, username, { expirationTtl: 2592000 }); // 30일

    return Response.redirect(
      PAGES_URL + "/#oauth_token=" + encodeURIComponent(token) + "&oauth_username=" + encodeURIComponent(username),
      302
    );
  } catch (err) {
    return Response.redirect(PAGES_URL + "/#oauth_error=" + encodeURIComponent(err.message || "unknown"), 302);
  }
}

async function fetchKakaoProfile(code, redirectUri, env) {
  const tokenParams = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: env.KAKAO_CLIENT_ID || "",
    redirect_uri: redirectUri,
    code: code,
  });
  if (env.KAKAO_CLIENT_SECRET) {
    tokenParams.set("client_secret", env.KAKAO_CLIENT_SECRET);
  }
  const tokenRes = await fetch("https://kauth.kakao.com/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: tokenParams.toString(),
  });
  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) {
    throw new Error("카카오 토큰 발급 실패: " + (tokenData.error_description || tokenData.error || "알 수 없는 오류"));
  }

  const profileRes = await fetch("https://kapi.kakao.com/v2/user/me", {
    headers: { Authorization: "Bearer " + tokenData.access_token },
  });
  const profileData = await profileRes.json();
  const nickname = profileData.kakao_account && profileData.kakao_account.profile
    ? profileData.kakao_account.profile.nickname
    : null;
  return { id: profileData.id, nickname };
}

async function fetchNaverProfile(code, redirectUri, env) {
  const tokenParams = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: env.NAVER_CLIENT_ID || "",
    client_secret: env.NAVER_CLIENT_SECRET || "",
    redirect_uri: redirectUri,
    code: code,
  });
  const tokenRes = await fetch("https://nid.naver.com/oauth2.0/token?" + tokenParams.toString(), {
    method: "GET",
  });
  const tokenData = await tokenRes.json();
  if (!tokenData.access_token) {
    throw new Error("네이버 토큰 발급 실패: " + (tokenData.error_description || tokenData.error || "알 수 없는 오류"));
  }

  const profileRes = await fetch("https://openapi.naver.com/v1/nid/me", {
    headers: { Authorization: "Bearer " + tokenData.access_token },
  });
  const profileData = await profileRes.json();
  const info = profileData.response || {};
  return { id: info.id, nickname: info.nickname };
}

// 소셜 로그인 최초 1회면 새 계정을 만들고, 이미 연결된 적 있으면 그 계정으로 바로 로그인시킨다
async function findOrCreateOAuthUser(provider, socialId, nicknameHint, APP_KV) {
  const linkKey = "oauth:" + provider + ":" + socialId;
  const existingUsername = await APP_KV.get(linkKey);
  if (existingUsername) {
    return existingUsername;
  }

  // 닉네임 기반으로 아이디를 만들어보고, 이미 있으면 무작위 뒷자리를 붙인다
  const base = (nicknameHint || provider)
    .replace(/[^a-zA-Z0-9가-힣]/g, "")
    .slice(0, 20) || provider;
  let username = base;
  let attempt = 0;
  while (await APP_KV.get("user:" + username)) {
    attempt++;
    username = base + "_" + crypto.randomUUID().slice(0, 4);
    if (attempt > 5) break; // 극히 드문 무한루프 방지
  }

  await APP_KV.put(
    "user:" + username,
    JSON.stringify({ hash: null, salt: null, plan: "free", createdAt: Date.now(), oauthProvider: provider })
  );
  await APP_KV.put(linkKey, username);
  return username;
}
