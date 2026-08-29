// 시그넷(Signet) 백엔드 — Render(Node.js/Express) + Upstash Redis 버전
// Cloudflare Worker 버전(signet-worker.js)과 기능은 완전히 동일해요.
// 바뀐 건 "어디서 도는지"뿐이에요 (Cloudflare Workers → Render, KV → Upstash Redis).
//
// === 배포 전 꼭 필요한 설정 (Render 대시보드 → Environment) ===
//   ANTHROPIC_API_KEY        Anthropic에서 발급받은 API 키
//   UPSTASH_REDIS_REST_URL   Upstash 대시보드에서 복사
//   UPSTASH_REDIS_REST_TOKEN Upstash 대시보드에서 복사
//   KAKAO_CLIENT_ID / KAKAO_CLIENT_SECRET   (카카오 로그인 쓸 때)
//   NAVER_CLIENT_ID / NAVER_CLIENT_SECRET   (네이버 로그인 쓸 때)
//   PAGES_URL                 프론트엔드(Cloudflare Pages) 주소
//   BACKEND_URL                이 서버 자신의 Render 주소 (카카오/네이버 redirect_uri 계산용)
//
// 신고(report_content)된 글은 자동으로 삭제되지 않아요. Upstash 콘솔에서
// report: 로 시작하는 키를 직접 확인하고, 필요하면 posts 키 안의 해당 글/답글을
// 수동으로 지워주세요 (지금은 별도 관리자 화면이 없어요).

const express = require("express");
const cors = require("cors");
const { Redis } = require("@upstash/redis");
const nodeCrypto = require("crypto");
const subtle = nodeCrypto.webcrypto.subtle;
const getRandomValues = nodeCrypto.webcrypto.getRandomValues.bind(nodeCrypto.webcrypto);

const FREE_DAILY_LIMIT = 30;
const PAID_DAILY_LIMIT = 300;
const GLOBAL_DAILY_LIMIT = 1000;

const PAGES_URL = process.env.PAGES_URL || "https://lingering-sun-b4f9.stopn1.workers.dev";
const BACKEND_URL = process.env.BACKEND_URL || "https://signet-kswi.onrender.com";

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

// Cloudflare KV랑 똑같이 쓸 수 있도록 만든 얇은 래퍼 (get/put/delete)
const APP_KV = {
  async get(key) {
    const val = await redis.get(key);
    if (val === null || val === undefined) return null;
    return typeof val === "string" ? val : JSON.stringify(val);
  },
  async put(key, value, opts) {
    if (opts && opts.expirationTtl) {
      await redis.set(key, value, { ex: opts.expirationTtl });
    } else {
      await redis.set(key, value);
    }
  },
  async delete(key) {
    await redis.del(key);
  },
};

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
  const salt = saltHex ? hexToBytes(saltHex) : getRandomValues(new Uint8Array(16));
  const keyMaterial = await subtle.importKey(
    "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]
  );
  const bits = await subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial, 256
  );
  return { hash: bytesToHex(new Uint8Array(bits)), salt: bytesToHex(salt) };
}

function sendJson(res, obj, status) {
  res.status(status || 200).json(obj);
}

const app = express();
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));
app.use(express.json());

// ===== 카카오/네이버 로그인 콜백 (GET, 브라우저가 카카오/네이버에서 돌아올 때) =====
app.get("/oauth/kakao/callback", async (req, res) => {
  await handleOAuthCallback("kakao", req, res);
});
app.get("/oauth/naver/callback", async (req, res) => {
  await handleOAuthCallback("naver", req, res);
});

app.get("/", (req, res) => {
  res.send("시그넷 백엔드가 돌아가는 중이에요.");
});

// ===== 그 외 모든 요청(POST) =====
app.post("/", async (req, res) => {
  const body = req.body || {};
  try {
    await handleAction(body, req, res);
  } catch (err) {
    if (!res.headersSent) {
      sendJson(res, { error: "예상하지 못한 서버 오류가 발생했어요: " + err.message }, 500);
    }
  }
});

async function handleAction(body, req, res) {
    // ===== 회원가입 =====
    if (body.action === "signup") {
      const username = (body.username || "").trim();
      const password = body.password || "";
      const birthdate = (body.birthdate || "").trim();
      const PASSWORD_RULE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;
      if (username.length < 2 || username.length > 30) {
        return sendJson(res, { error: "아이디는 2~30자로 입력해주세요." }, 400);
      }
      if (!PASSWORD_RULE.test(password)) {
        return sendJson(res, { error: "비밀번호는 영문 대문자·소문자·숫자·특수문자를 각각 1개 이상 포함해서 8자 이상이어야 해요." }, 400);
      }
      if (!/^\d{4}-\d{2}-\d{2}$/.test(birthdate) || new Date(birthdate) > new Date()) {
        return sendJson(res, { error: "생년월일을 올바르게 입력해주세요." }, 400);
      }
      const existing = await APP_KV.get("user:" + username);
      if (existing) {
        return sendJson(res, { error: "이미 사용 중인 아이디예요. 다른 아이디를 입력해주세요." }, 409);
      }
      const { hash, salt } = await hashPassword(password);
      await APP_KV.put("user:" + username, JSON.stringify({ hash, salt, birthdate, plan: "free", createdAt: Date.now() }));
      return sendJson(res, { success: true }, 200);
    }

    // ===== 아이디 중복확인 =====
    if (body.action === "check_username") {
      const checkUsername = (body.username || "").trim();
      if (checkUsername.length < 2 || checkUsername.length > 30) {
        return sendJson(res, { error: "아이디는 2~30자로 입력해주세요." }, 400);
      }
      const existing = await APP_KV.get("user:" + checkUsername);
      return sendJson(res, { success: true, available: !existing }, 200);
    }

    // ===== 로그인 =====
    if (body.action === "login") {
      const username = (body.username || "").trim();
      const password = body.password || "";
      const record = await APP_KV.get("user:" + username);
      if (!record) {
        return sendJson(res, { error: "아이디 또는 비밀번호가 올바르지 않아요." }, 401);
      }
      const userObj = JSON.parse(record);
      const { hash: storedHash, salt } = userObj;
      const { hash: attemptHash } = await hashPassword(password, salt);
      if (attemptHash !== storedHash) {
        return sendJson(res, { error: "아이디 또는 비밀번호가 올바르지 않아요." }, 401);
      }
      const token = nodeCrypto.randomUUID();
      await APP_KV.put("session:" + token, username, { expirationTtl: 2592000 }); // 30일
      return sendJson(res, { success: true, token, username, plan: userObj.plan || "free" }, 200);
    }

    // ===== 그 외: 로그인이 필요한 요청들 =====
    const authHeader = req.headers.authorization || "";
    const token = authHeader.replace(/^Bearer\s+/i, "").trim();
    if (!token) {
      return sendJson(res, { error: "로그인이 필요해요." }, 401);
    }
    const username = await APP_KV.get("session:" + token);
    if (!username) {
      return sendJson(res, { error: "로그인이 만료됐어요. 다시 로그인해주세요." }, 401);
    }

    // ===== 찜하기 =====
    if (body.action === "save_favorite") {
      const topic = body.topic;
      if (!topic || !topic.title) {
        return sendJson(res, { error: "저장할 주제 정보가 없어요." }, 400);
      }
      const listRaw = await APP_KV.get("fav:" + username);
      const list = listRaw ? JSON.parse(listRaw) : [];
      if (list.length >= 50) {
        return sendJson(res, { error: "찜은 최대 50개까지 저장할 수 있어요. 몇 개 지우고 다시 시도해주세요." }, 400);
      }
      const entry = { ...topic, id: nodeCrypto.randomUUID(), savedAt: Date.now() };
      list.unshift(entry);
      await APP_KV.put("fav:" + username, JSON.stringify(list));
      return sendJson(res, { success: true, id: entry.id }, 200);
    }

    // ===== 찜 목록 보기 =====
    if (body.action === "list_favorites") {
      const listRaw = await APP_KV.get("fav:" + username);
      const list = listRaw ? JSON.parse(listRaw) : [];
      return sendJson(res, { success: true, favorites: list }, 200);
    }

    // ===== 찜 삭제 =====
    if (body.action === "remove_favorite") {
      const listRaw = await APP_KV.get("fav:" + username);
      const list = listRaw ? JSON.parse(listRaw) : [];
      const filtered = list.filter(f => f.id !== body.id);
      await APP_KV.put("fav:" + username, JSON.stringify(filtered));
      return sendJson(res, { success: true }, 200);
    }

    // ===== 찜한 주제의 탐구 진행 체크리스트 업데이트 =====
    if (body.action === "update_checklist") {
      if (!Array.isArray(body.checklist)) {
        return sendJson(res, { error: "체크리스트 형식이 올바르지 않아요." }, 400);
      }
      const listRaw = await APP_KV.get("fav:" + username);
      const list = listRaw ? JSON.parse(listRaw) : [];
      const target = list.find(f => f.id === body.favoriteId);
      if (!target) {
        return sendJson(res, { error: "찜한 주제를 찾을 수 없어요." }, 404);
      }
      target.checklist = body.checklist.slice(0, 20).map(Boolean);
      await APP_KV.put("fav:" + username, JSON.stringify(list));
      return sendJson(res, { success: true }, 200);
    }

    // ===== 전체 기록 저장 (자동, 학생이 볼 때마다) =====
    if (body.action === "save_history") {
      const topic = body.topic;
      if (!topic || !topic.title) {
        return sendJson(res, { error: "저장할 주제 정보가 없어요." }, 400);
      }
      const listRaw = await APP_KV.get("hist:" + username);
      const list = listRaw ? JSON.parse(listRaw) : [];
      const entry = { ...topic, id: nodeCrypto.randomUUID(), savedAt: Date.now() };
      list.unshift(entry);
      const trimmed = list.slice(0, 100); // 최근 100개까지만 보관
      await APP_KV.put("hist:" + username, JSON.stringify(trimmed));
      return sendJson(res, { success: true }, 200);
    }

    // ===== 전체 기록 보기 =====
    if (body.action === "list_history") {
      const listRaw = await APP_KV.get("hist:" + username);
      const list = listRaw ? JSON.parse(listRaw) : [];
      return sendJson(res, { success: true, history: list }, 200);
    }

    // ===== 전체 기록 비우기 =====
    if (body.action === "clear_history") {
      await APP_KV.delete("hist:" + username);
      return sendJson(res, { success: true }, 200);
    }

    // ===== 피드백 보내기 =====
    if (body.action === "submit_feedback") {
      const message = (body.message || "").trim();
      if (!message) {
        return sendJson(res, { error: "내용을 입력해주세요." }, 400);
      }
      if (message.length > 2000) {
        return sendJson(res, { error: "내용이 너무 길어요. 2000자 이내로 줄여주세요." }, 400);
      }
      const key = "feedback:" + Date.now() + "-" + nodeCrypto.randomUUID().slice(0, 8);
      await APP_KV.put(key, JSON.stringify({ username, message, submittedAt: Date.now() }));
      return sendJson(res, { success: true }, 200);
    }

    // ===== 아바타 설정 =====
    if (body.action === "set_avatar") {
      const ALLOWED_AVATARS = ["🦊","🐱","🐰","🐻","🐼","🦉","🐨","🐯","🦁","🐸","🐧","🦄","🐶","🐹","🐢","🦋","🐺","🦝","🦔","🦓","🐮","🐷","🐵","🦒","🐘","🦥","🦦","🦩","🐬","🦅","🐴","🦌"];
      const avatar = body.avatar || "";
      if (!ALLOWED_AVATARS.includes(avatar)) {
        return sendJson(res, { error: "선택할 수 없는 아바타예요." }, 400);
      }
      const record = await APP_KV.get("user:" + username);
      if (!record) {
        return sendJson(res, { error: "계정 정보를 찾을 수 없어요." }, 404);
      }
      const userObj = JSON.parse(record);
      await APP_KV.put("user:" + username, JSON.stringify({ ...userObj, avatar }));
      return sendJson(res, { success: true, avatar }, 200);
    }

    // ===== 커뮤니티: 글쓰기 =====
    if (body.action === "create_post") {
      const title = (body.title || "").trim();
      const postBody = (body.body || "").trim();
      const room = (body.room || "").trim().slice(0, 30) || "자유";
      if (!title || !postBody) {
        return sendJson(res, { error: "제목과 내용을 모두 입력해주세요." }, 400);
      }
      if (title.length > 100) {
        return sendJson(res, { error: "제목은 100자 이내로 써주세요." }, 400);
      }
      if (postBody.length > 2000) {
        return sendJson(res, { error: "내용은 2000자 이내로 써주세요." }, 400);
      }
      const userRecord = await APP_KV.get("user:" + username);
      const avatar = userRecord ? (JSON.parse(userRecord).avatar || "👤") : "👤";
      const listRaw = await APP_KV.get("posts");
      const list = listRaw ? JSON.parse(listRaw) : [];
      const entry = {
        id: nodeCrypto.randomUUID(), username, avatar, title, body: postBody, room,
        createdAt: Date.now(), replies: []
      };
      list.unshift(entry);
      const trimmed = list.slice(0, 300);
      await APP_KV.put("posts", JSON.stringify(trimmed));
      return sendJson(res, { success: true, id: entry.id }, 200);
    }

    // ===== 커뮤니티: 목록 보기 =====
    if (body.action === "list_posts") {
      const listRaw = await APP_KV.get("posts");
      const list = listRaw ? JSON.parse(listRaw) : [];
      return sendJson(res, { success: true, posts: list.slice(0, 50) }, 200);
    }

    // ===== 커뮤니티: 글 삭제 (본인 글만) =====
    if (body.action === "delete_post") {
      const listRaw = await APP_KV.get("posts");
      const list = listRaw ? JSON.parse(listRaw) : [];
      const target = list.find(p => p.id === body.postId);
      if (!target) {
        return sendJson(res, { error: "이미 삭제된 글이에요." }, 404);
      }
      if (target.username !== username) {
        return sendJson(res, { error: "본인이 쓴 글만 삭제할 수 있어요." }, 403);
      }
      const filtered = list.filter(p => p.id !== body.postId);
      await APP_KV.put("posts", JSON.stringify(filtered));
      return sendJson(res, { success: true }, 200);
    }

    // ===== 커뮤니티: 답글 달기 =====
    if (body.action === "reply_to_post") {
      const replyBody = (body.body || "").trim();
      if (!replyBody) {
        return sendJson(res, { error: "답글 내용을 입력해주세요." }, 400);
      }
      if (replyBody.length > 1000) {
        return sendJson(res, { error: "답글은 1000자 이내로 써주세요." }, 400);
      }
      const userRecord = await APP_KV.get("user:" + username);
      const avatar = userRecord ? (JSON.parse(userRecord).avatar || "👤") : "👤";
      const listRaw = await APP_KV.get("posts");
      const list = listRaw ? JSON.parse(listRaw) : [];
      const target = list.find(p => p.id === body.postId);
      if (!target) {
        return sendJson(res, { error: "글을 찾을 수 없어요." }, 404);
      }
      if (!target.replies) target.replies = [];
      target.replies.push({ id: nodeCrypto.randomUUID(), username, avatar, body: replyBody, createdAt: Date.now() });
      await APP_KV.put("posts", JSON.stringify(list));
      return sendJson(res, { success: true }, 200);
    }

    // ===== 커뮤니티: 답글 삭제 (본인 답글만) =====
    if (body.action === "delete_reply") {
      const listRaw = await APP_KV.get("posts");
      const list = listRaw ? JSON.parse(listRaw) : [];
      const target = list.find(p => p.id === body.postId);
      if (!target || !target.replies) {
        return sendJson(res, { error: "글을 찾을 수 없어요." }, 404);
      }
      const reply = target.replies.find(r => r.id === body.replyId);
      if (!reply) {
        return sendJson(res, { error: "이미 삭제된 답글이에요." }, 404);
      }
      if (reply.username !== username) {
        return sendJson(res, { error: "본인이 쓴 답글만 삭제할 수 있어요." }, 403);
      }
      target.replies = target.replies.filter(r => r.id !== body.replyId);
      await APP_KV.put("posts", JSON.stringify(list));
      return sendJson(res, { success: true }, 200);
    }

    // ===== 커뮤니티: 신고 (제작자가 수동으로 검토) =====
    if (body.action === "report_content") {
      const reason = (body.reason || "").trim().slice(0, 500);
      const key = "report:" + Date.now() + "-" + nodeCrypto.randomUUID().slice(0, 8);
      await APP_KV.put(key, JSON.stringify({
        reportedBy: username,
        postId: body.postId || null,
        replyId: body.replyId || null,
        reason,
        reportedAt: Date.now()
      }));
      return sendJson(res, { success: true }, 200);
    }

    // ===== 아이디 변경 (찜/기록/과제/게시글까지 함께 옮긴다) =====
    if (body.action === "change_username") {
      const newUsername = (body.newUsername || "").trim();
      const currentPassword = body.currentPassword || "";
      if (newUsername.length < 2 || newUsername.length > 30) {
        return sendJson(res, { error: "아이디는 2~30자로 입력해주세요." }, 400);
      }
      if (newUsername === username) {
        return sendJson(res, { error: "지금 아이디랑 같아요." }, 400);
      }
      const existingNew = await APP_KV.get("user:" + newUsername);
      if (existingNew) {
        return sendJson(res, { error: "이미 사용 중인 아이디예요." }, 409);
      }
      const record = await APP_KV.get("user:" + username);
      if (!record) {
        return sendJson(res, { error: "계정 정보를 찾을 수 없어요." }, 404);
      }
      const userObj = JSON.parse(record);
      // 소셜 로그인(카카오/네이버) 계정은 시그넷에 저장된 비밀번호가 없다(hash가 null).
      // 이미 로그인 토큰으로 본인 확인이 끝난 상태라, 비밀번호 검사는 건너뛴다.
      if (userObj.hash) {
        const { hash: attemptHash } = await hashPassword(currentPassword, userObj.salt);
        if (attemptHash !== userObj.hash) {
          return sendJson(res, { error: "비밀번호가 올바르지 않아요." }, 401);
        }
      }

      await APP_KV.put("user:" + newUsername, JSON.stringify(userObj));
      await APP_KV.delete("user:" + username);

      for (const prefix of ["fav:", "hist:", "assign:"]) {
        const dataRaw = await APP_KV.get(prefix + username);
        if (dataRaw) {
          await APP_KV.put(prefix + newUsername, dataRaw);
          await APP_KV.delete(prefix + username);
        }
      }

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

      await APP_KV.put("session:" + token, newUsername, { expirationTtl: 2592000 });

      return sendJson(res, { success: true, newUsername }, 200);
    }

    // ===== 비밀번호 변경 =====
    if (body.action === "change_password") {
      const currentPassword = body.currentPassword || "";
      const newPassword = body.newPassword || "";
      const PASSWORD_RULE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/;
      const record = await APP_KV.get("user:" + username);
      if (!record) {
        return sendJson(res, { error: "계정 정보를 찾을 수 없어요." }, 404);
      }
      const userObj = JSON.parse(record);
      const { hash: attemptHash } = await hashPassword(currentPassword, userObj.salt);
      if (attemptHash !== userObj.hash) {
        return sendJson(res, { error: "현재 비밀번호가 올바르지 않아요." }, 401);
      }
      if (!PASSWORD_RULE.test(newPassword)) {
        return sendJson(res, { error: "새 비밀번호는 영문 대문자·소문자·숫자·특수문자를 각각 1개 이상 포함해서 8자 이상이어야 해요." }, 400);
      }
      const { hash, salt } = await hashPassword(newPassword);
      await APP_KV.put("user:" + username, JSON.stringify({ ...userObj, hash, salt }));
      return sendJson(res, { success: true }, 200);
    }

    // ===== 과제 추가 =====
    if (body.action === "add_assignment") {
      const title = (body.title || "").trim();
      const dueDate = (body.dueDate || "").trim();
      const memo = (body.memo || "").trim();
      if (!title) {
        return sendJson(res, { error: "과제 이름을 입력해주세요." }, 400);
      }
      if (!/^\d{4}-\d{2}-\d{2}$/.test(dueDate)) {
        return sendJson(res, { error: "마감일을 올바르게 입력해주세요." }, 400);
      }
      const listRaw = await APP_KV.get("assign:" + username);
      const list = listRaw ? JSON.parse(listRaw) : [];
      if (list.length >= 50) {
        return sendJson(res, { error: "과제는 최대 50개까지 등록할 수 있어요. 다 끝난 것부터 지워주세요." }, 400);
      }
      const entry = { id: nodeCrypto.randomUUID(), title, dueDate, memo, createdAt: Date.now() };
      list.push(entry);
      await APP_KV.put("assign:" + username, JSON.stringify(list));
      return sendJson(res, { success: true, id: entry.id }, 200);
    }

    // ===== 과제 목록 (마감일 가까운 순) =====
    if (body.action === "list_assignments") {
      const listRaw = await APP_KV.get("assign:" + username);
      const list = listRaw ? JSON.parse(listRaw) : [];
      list.sort((a, b) => a.dueDate.localeCompare(b.dueDate));
      return sendJson(res, { success: true, assignments: list }, 200);
    }

    // ===== 과제 삭제 =====
    if (body.action === "delete_assignment") {
      const listRaw = await APP_KV.get("assign:" + username);
      const list = listRaw ? JSON.parse(listRaw) : [];
      const filtered = list.filter(a => a.id !== body.id);
      await APP_KV.put("assign:" + username, JSON.stringify(filtered));
      return sendJson(res, { success: true }, 200);
    }

    // ===== 사용량 조회 =====
    if (body.action === "get_usage") {
      const userRecord = await APP_KV.get("user:" + username);
      const userObj = userRecord ? JSON.parse(userRecord) : {};
      const plan = userObj.plan || "free";
      const today = new Date().toISOString().slice(0, 10);
      const userUsageKey = "usage:" + username + ":" + today;
      const used = parseInt((await APP_KV.get(userUsageKey)) || "0", 10);
      const limit = plan === "paid" ? PAID_DAILY_LIMIT : FREE_DAILY_LIMIT;
      return sendJson(res, { success: true, plan, used, limit, remaining: Math.max(0, limit - used), createdAt: userObj.createdAt || null, avatar: userObj.avatar || "👤" }, 200);
    }

    // ===== 사용량 1회 차감 =====
    if (body.action === "consume_usage") {
      const userRecord = await APP_KV.get("user:" + username);
      const plan = userRecord ? (JSON.parse(userRecord).plan || "free") : "free";
      const today = new Date().toISOString().slice(0, 10);
      const userUsageKey = "usage:" + username + ":" + today;
      const used = parseInt((await APP_KV.get(userUsageKey)) || "0", 10);
      const limit = plan === "paid" ? PAID_DAILY_LIMIT : FREE_DAILY_LIMIT;
      if (used >= limit) {
        return sendJson(res, { error: "오늘 무료 사용 횟수를 다 쓰셨어요. 내일 다시 이용해주시거나, 곧 열릴 유료 플랜을 기다려주세요!", plan, limitReached: true }, 429);
      }
      await APP_KV.put(userUsageKey, String(used + 1), { expirationTtl: 172800 });
      return sendJson(res, { success: true, used: used + 1, limit, remaining: Math.max(0, limit - used - 1) }, 200);
    }

    // ===== 그 외: AI 요청 처리 =====
    if (!process.env.ANTHROPIC_API_KEY) {
      return sendJson(res, { error: "서버에 API 키가 설정되지 않았어요. Environment에서 ANTHROPIC_API_KEY를 추가해주세요." }, 500);
    }

    const today = new Date().toISOString().slice(0, 10);
    const usageKey = "count:" + today;
    const current = parseInt((await APP_KV.get(usageKey)) || "0", 10);
    if (current >= GLOBAL_DAILY_LIMIT) {
      return sendJson(res, { error: "오늘 전체 사용량 한도를 넘었어요. 내일 다시 시도해주세요." }, 429);
    }

    try {
      const anthropicBody = {
        model: body.model || "claude-sonnet-5",
        max_tokens: body.max_tokens || 1000,
        messages: body.messages,
      };
      if (body.enableSearch) {
        // max_uses로 검색 횟수를 제한해둔다. 안 걸어두면 AI가 데이터를 찾으려고
        // 검색을 여러 번 반복하면서 응답이 몇 분씩 걸리는 원인이 될 수 있다.
        anthropicBody.tools = [{ type: "web_search_20250305", name: "web_search", max_uses: 3 }];
      }
      const anthropicResponse = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-api-key": process.env.ANTHROPIC_API_KEY,
          "anthropic-version": "2023-06-01",
          "user-agent": "signet-backend/1.0 (Render)",
        },
        body: JSON.stringify(anthropicBody),
      });
      if (anthropicResponse.ok) {
        await APP_KV.put(usageKey, String(current + 1), { expirationTtl: 172800 });
      }
      const data = await anthropicResponse.text();
      res.status(anthropicResponse.status).type("application/json").send(data);
      return;
    } catch (err) {
      return sendJson(res, { error: err.message }, 500);
    }
}

// ============================================================
// 카카오/네이버 소셜 로그인
// ============================================================

async function handleOAuthCallback(provider, req, res) {
  const code = req.query.code;
  const errorParam = req.query.error;

  if (errorParam || !code) {
    return res.redirect(302, PAGES_URL + "/#oauth_error=" + encodeURIComponent(provider + "_denied"));
  }

  try {
    const redirectUri = BACKEND_URL + "/oauth/" + provider + "/callback";
    let profile;
    if (provider === "kakao") {
      profile = await fetchKakaoProfile(code, redirectUri);
    } else {
      profile = await fetchNaverProfile(code, redirectUri);
    }

    if (!profile || !profile.id) {
      return res.redirect(302, PAGES_URL + "/#oauth_error=" + encodeURIComponent(provider + "_profile_failed"));
    }

    const username = await findOrCreateOAuthUser(provider, String(profile.id), profile.nickname);
    const token = nodeCrypto.randomUUID();
    await APP_KV.put("session:" + token, username, { expirationTtl: 2592000 });

    return res.redirect(
      302,
      PAGES_URL + "/#oauth_token=" + encodeURIComponent(token) + "&oauth_username=" + encodeURIComponent(username)
    );
  } catch (err) {
    return res.redirect(302, PAGES_URL + "/#oauth_error=" + encodeURIComponent(err.message || "unknown"));
  }
}

async function fetchKakaoProfile(code, redirectUri) {
  const tokenParams = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: process.env.KAKAO_CLIENT_ID || "",
    redirect_uri: redirectUri,
    code: code,
  });
  if (process.env.KAKAO_CLIENT_SECRET) {
    tokenParams.set("client_secret", process.env.KAKAO_CLIENT_SECRET);
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

async function fetchNaverProfile(code, redirectUri) {
  const tokenParams = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: process.env.NAVER_CLIENT_ID || "",
    client_secret: process.env.NAVER_CLIENT_SECRET || "",
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

async function findOrCreateOAuthUser(provider, socialId, nicknameHint) {
  const linkKey = "oauth:" + provider + ":" + socialId;
  const existingUsername = await APP_KV.get(linkKey);
  if (existingUsername) {
    return existingUsername;
  }

  const base = (nicknameHint || provider)
    .replace(/[^a-zA-Z0-9가-힣]/g, "")
    .slice(0, 20) || provider;
  let username = base;
  let attempt = 0;
  while (await APP_KV.get("user:" + username)) {
    attempt++;
    username = base + "_" + nodeCrypto.randomUUID().slice(0, 4);
    if (attempt > 5) break;
  }

  await APP_KV.put(
    "user:" + username,
    JSON.stringify({ hash: null, salt: null, plan: "free", createdAt: Date.now(), oauthProvider: provider })
  );
  await APP_KV.put(linkKey, username);
  return username;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("시그넷 백엔드 실행 중 · 포트 " + PORT);
});
