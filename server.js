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
  // 카운터 전용 원자 연산.
  // 예전에는 get → +1 → put 방식이라, 동시에 요청이 몰리면 전부 같은 값을 읽고
  // 전부 한도를 통과해버렸다(사실상 한도가 없는 것과 같았다).
  // INCR은 레디스가 한 번에 처리해줘서 몇 개가 동시에 들어와도 정확히 세어진다.
  // 반환값이 "이번 요청까지 포함한 누적 횟수"라, 이 값으로 바로 한도를 판정한다.
  async incr(key, ttlSeconds) {
    const next = await redis.incr(key);
    // 키가 막 만들어진 첫 요청에만 만료시간을 걸어둔다(매번 걸면 만료가 계속 밀린다)
    if (next === 1 && ttlSeconds) {
      await redis.expire(key, ttlSeconds);
    }
    return next;
  },
  // "아직 없을 때만" 값을 넣는다. 성공하면 true.
  // 아이디 변경에서 새 아이디를 선점할 때 쓴다 — 조회 후 저장 방식이면
  // 두 사람이 동시에 같은 아이디로 바꿀 때 둘 다 통과해서 한쪽 계정이 사라진다.
  async setIfAbsent(key, value) {
    const ok = await redis.set(key, value, { nx: true });
    return ok !== null;
  },
  // 한 사용자의 로그인 세션 토큰 목록. 로그아웃·아이디 변경·회원 탈퇴에서
  // "이 사람의 모든 기기 세션"을 다뤄야 해서 따로 모아둔다.
  async addSession(username, token) {
    await redis.sadd("sessions:" + username, token);
  },
  async listSessions(username) {
    const arr = await redis.smembers("sessions:" + username);
    return Array.isArray(arr) ? arr : [];
  },
  async dropSessionIndex(username) {
    await redis.del("sessions:" + username);
  },
};

// ===== AI 호출 안전장치 =====
// 프론트엔드가 실제로 쓰는 모델만 허용한다. 사용자가 body.model로 비싼 모델을
// 지정해서 요금을 태우는 걸 막기 위해, 목록에 없으면 무조건 기본 모델로 되돌린다.
const ALLOWED_MODELS = ["claude-sonnet-5"];
const DEFAULT_MODEL = "claude-sonnet-5";
// 한 번의 호출에서 만들 수 있는 최대 분량. 프론트가 제일 크게 쓰는 값이 7000이라
// 그보다 약간 여유를 둔 상한으로 자른다.
const MAX_TOKENS_CAP = 8000;
// 사용자 1명이 하루에 보낼 수 있는 원시 AI 호출 수.
// "생성 버튼 1번"이 내부적으로 4~6번 호출되므로, 버튼 한도(FREE_DAILY_LIMIT)에
// 넉넉히 곱한 값으로 잡는다. 정상 사용으로는 닿지 않고, 스크립트 악용만 걸린다.
const RAW_CALL_DAILY_CAP = parseInt(process.env.RAW_CALL_DAILY_CAP || "250", 10);

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
    // 아이디/비밀번호 회원가입·로그인은 없앴다(네이버/카카오 소셜 로그인만 사용).
    // 화면에서만 지우고 서버에 남겨두면, 화면을 거치지 않고 서버로 직접 요청해서
    // 계정을 무한정 만들 수 있다 — 소셜 로그인만 받는 의미가 사라지므로 여기서도 제거한다.
    // 아이디 중복확인(check_username)은 마이페이지의 "아이디 변경"에서만 쓰므로,
    // 아래 로그인 확인을 통과한 뒤에 처리한다(가입자 명단이 밖으로 새지 않도록).

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

    // ===== 로그아웃 =====
    // 예전에는 브라우저에 저장된 토큰만 지웠고 서버의 세션은 30일간 그대로 살아있었다.
    // 학교 컴퓨터 같은 공용 기기에서는 그 토큰이 계속 유효해서 위험하다.
    if (body.action === "logout") {
      await APP_KV.delete("session:" + token);
      const rest = (await APP_KV.listSessions(username)).filter(t => t !== token);
      await APP_KV.dropSessionIndex(username);
      for (const t of rest) {
        await APP_KV.addSession(username, t);
      }
      return sendJson(res, { success: true }, 200);
    }

    // ===== 회원 탈퇴 (계정과 관련 데이터를 모두 지운다) =====
    // 개인정보 파기 요구를 위해서도 필요하고, 사용자가 스스로 정리할 수 있어야 한다.
    if (body.action === "delete_account") {
      const record = await APP_KV.get("user:" + username);
      const userObj = record ? JSON.parse(record) : {};

      // 게시판 글·답글은 먼저 지운다(남겨두면 탈퇴한 사람 이름이 계속 노출된다)
      const postsRaw = await APP_KV.get("posts");
      if (postsRaw) {
        let posts = JSON.parse(postsRaw);
        posts = posts.filter(p => p.username !== username);
        posts.forEach(p => {
          p.replies = (p.replies || []).filter(r => r.username !== username);
        });
        await APP_KV.put("posts", JSON.stringify(posts));
      }

      // 소셜 로그인 연결고리 삭제 — 안 지우면 같은 소셜 계정으로 다시 로그인했을 때
      // 사라진 옛 아이디로 연결되어 버린다
      if (userObj.oauthProvider && userObj.oauthId) {
        await APP_KV.delete("oauth:" + userObj.oauthProvider + ":" + userObj.oauthId);
      }

      // 모든 기기의 세션 무효화
      for (const t of await APP_KV.listSessions(username)) {
        await APP_KV.delete("session:" + t);
      }
      await APP_KV.delete("session:" + token);
      await APP_KV.dropSessionIndex(username);

      // 개인 데이터 삭제
      const todayForDelete = new Date().toISOString().slice(0, 10);
      for (const key of [
        "fav:" + username,
        "hist:" + username,
        "assign:" + username,
        "roadmap:" + username,
        "usage:" + username + ":" + todayForDelete,
        "apicalls:" + username + ":" + todayForDelete,
        "user:" + username,
      ]) {
        await APP_KV.delete(key);
      }

      return sendJson(res, { success: true }, 200);
    }

    // ===== 아이디 중복확인 (로그인한 사용자만) =====
    if (body.action === "check_username") {
      const checkUsername = (body.username || "").trim();
      if (checkUsername.length < 2 || checkUsername.length > 30) {
        return sendJson(res, { error: "아이디는 2~30자로 입력해주세요." }, 400);
      }
      const existing = await APP_KV.get("user:" + checkUsername);
      return sendJson(res, { success: true, available: !existing }, 200);
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

      // 소셜 계정인데 oauthId가 없으면(예전에 가입한 계정) 지금 아이디를 바꾸면
      // oauth 연결고리가 옛 이름을 가리킨 채 남아서, 다음 로그인 때 계정이 통째로
      // 사라진 것처럼 보인다. 그래서 바꾸지 않고, 다시 로그인하도록 안내한다.
      // (다시 로그인하면 oauthId가 자동으로 채워져서 그 뒤엔 정상 동작한다)
      if (userObj.oauthProvider && !userObj.oauthId) {
        return sendJson(res, { error: "계정 정보를 갱신해야 해요. 로그아웃했다가 다시 로그인한 뒤에 시도해주세요." }, 409);
      }

      // 새 아이디는 "없을 때만 넣기"로 선점한다. 조회 후 저장 방식이면 두 사람이
      // 동시에 같은 아이디로 바꿀 때 둘 다 통과해서 한쪽 계정이 덮어써진다.
      const claimed = await APP_KV.setIfAbsent("user:" + newUsername, JSON.stringify(userObj));
      if (!claimed) {
        return sendJson(res, { error: "이미 사용 중인 아이디예요." }, 409);
      }
      await APP_KV.delete("user:" + username);

      for (const prefix of ["fav:", "hist:", "assign:", "roadmap:"]) {
        const dataRaw = await APP_KV.get(prefix + username);
        if (dataRaw) {
          await APP_KV.put(prefix + newUsername, dataRaw);
          await APP_KV.delete(prefix + username);
        }
      }

      // 오늘 쓴 사용량도 같이 옮긴다. 안 옮기면 아이디만 바꿔서 한도를 초기화할 수 있다.
      const todayForMove = new Date().toISOString().slice(0, 10);
      for (const usageKeyName of ["usage:", "apicalls:"]) {
        const oldKey = usageKeyName + username + ":" + todayForMove;
        const val = await APP_KV.get(oldKey);
        if (val) {
          await APP_KV.put(usageKeyName + newUsername + ":" + todayForMove, val, { expirationTtl: 172800 });
          await APP_KV.delete(oldKey);
        }
      }

      // 소셜 로그인 연결고리를 새 아이디로 옮긴다.
      // 이걸 빠뜨리면 다음 로그인 때 사라진 옛 아이디로 로그인되어 데이터가 안 보이고,
      // 비워진 옛 아이디를 다른 사람이 차지하면 그 사람 계정으로 들어가버린다.
      if (userObj.oauthProvider && userObj.oauthId) {
        await APP_KV.put("oauth:" + userObj.oauthProvider + ":" + userObj.oauthId, newUsername);
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

      // 다른 기기에 남아있는 세션들도 새 아이디를 가리키게 한다.
      // 안 그러면 그 기기들은 사라진 옛 아이디로 요청하게 된다.
      const myTokens = await APP_KV.listSessions(username);
      const allTokens = myTokens.includes(token) ? myTokens : myTokens.concat([token]);
      for (const t of allTokens) {
        await APP_KV.put("session:" + t, newUsername, { expirationTtl: 2592000 });
        await APP_KV.addSession(newUsername, t);
      }
      await APP_KV.dropSessionIndex(username);

      return sendJson(res, { success: true, newUsername }, 200);
    }

    // 비밀번호 변경(change_password)도 제거했다. 소셜 로그인만 받으므로 시그넷이
    // 보관하는 비밀번호 자체가 없고(hash가 null), 화면에서도 이미 걷어냈다.

    // ===== 생기부 로드맵 저장 =====
    // 로드맵은 사용자당 하나만 둔다. 여러 개를 관리하게 하면 오히려 복잡해지고,
    // 학생 입장에서도 "내 생기부 계획"은 하나인 게 자연스럽다.
    if (body.action === "save_roadmap") {
      const roadmap = body.roadmap;
      if (!roadmap || !roadmap.thread || !Array.isArray(roadmap.subjects)) {
        return sendJson(res, { error: "저장할 로드맵 정보가 없어요." }, 400);
      }
      // 통째로 받은 걸 그대로 저장하지 않고, 쓸 항목만 골라 담는다.
      // 안 그러면 임의의 큰 데이터가 그대로 저장될 수 있다.
      const clean = {
        career: String(roadmap.career || "").slice(0, 100),
        track: String(roadmap.track || "").slice(0, 100),
        interest: String(roadmap.interest || "").slice(0, 100),
        grade: String(roadmap.grade || "").slice(0, 20),
        thread: {
          title: String((roadmap.thread || {}).title || "").slice(0, 200),
          why: String((roadmap.thread || {}).why || "").slice(0, 1000)
        },
        sequence: (roadmap.sequence || []).slice(0, 6).map(sq => ({
          phase: String(sq.phase || "").slice(0, 60),
          what: String(sq.what || "").slice(0, 600)
        })),
        subjects: roadmap.subjects.slice(0, 12).map((sub, idx) => ({
          id: String(sub.id || ("s" + idx)).slice(0, 40),
          subject: String(sub.subject || "").slice(0, 60),
          // 한눈에 보기 도형에 들어가는 값들 — 어느 시기 칸에 놓을지, 칸 안에 뭐라고 쓸지
          phaseNo: Math.min(9, Math.max(0, parseInt(sub.phaseNo, 10) || 0)),
          phase: String(sub.phase || "").slice(0, 60),
          short: String(sub.short || "").slice(0, 40),
          angle: String(sub.angle || "").slice(0, 600),
          topicIdea: String(sub.topicIdea || "").slice(0, 600),
          connectsTo: String(sub.connectsTo || "").slice(0, 400),
          status: ["todo", "doing", "done"].includes(sub.status) ? sub.status : "todo"
        })),
        updatedAt: Date.now()
      };
      await APP_KV.put("roadmap:" + username, JSON.stringify(clean));
      return sendJson(res, { success: true, roadmap: clean }, 200);
    }

    // ===== 생기부 로드맵 불러오기 =====
    if (body.action === "get_roadmap") {
      const raw = await APP_KV.get("roadmap:" + username);
      return sendJson(res, { success: true, roadmap: raw ? JSON.parse(raw) : null }, 200);
    }

    // ===== 로드맵 항목 진행 상태 변경 =====
    if (body.action === "update_roadmap_status") {
      const itemId = String(body.itemId || "");
      const status = body.status;
      if (!["todo", "doing", "done"].includes(status)) {
        return sendJson(res, { error: "상태 값이 올바르지 않아요." }, 400);
      }
      const raw = await APP_KV.get("roadmap:" + username);
      if (!raw) {
        return sendJson(res, { error: "저장된 로드맵이 없어요." }, 404);
      }
      const roadmap = JSON.parse(raw);
      const target = (roadmap.subjects || []).find(sub => sub.id === itemId);
      if (!target) {
        return sendJson(res, { error: "해당 항목을 찾을 수 없어요." }, 404);
      }
      target.status = status;
      await APP_KV.put("roadmap:" + username, JSON.stringify(roadmap));
      return sendJson(res, { success: true }, 200);
    }

    // ===== 생기부 로드맵 삭제 =====
    if (body.action === "delete_roadmap") {
      await APP_KV.delete("roadmap:" + username);
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
      const limit = plan === "paid" ? PAID_DAILY_LIMIT : FREE_DAILY_LIMIT;
      // 여기도 원자적 증가로 바꿨다. 예전 방식(읽고→+1→쓰기)은 탭 두 개에서 동시에
      // 누르면 한 번만 차감되어 한도를 넘겨 쓸 수 있었다.
      const used = await APP_KV.incr(userUsageKey, 172800);
      if (used > limit) {
        return sendJson(res, { error: "오늘 사용 횟수를 다 쓰셨어요. 내일 다시 이용해주세요.", plan, limitReached: true }, 429);
      }
      return sendJson(res, { success: true, used, limit, remaining: Math.max(0, limit - used) }, 200);
    }

    // ===== 그 외: AI 요청 처리 =====
    if (!process.env.ANTHROPIC_API_KEY) {
      return sendJson(res, { error: "서버에 API 키가 설정되지 않았어요. Environment에서 ANTHROPIC_API_KEY를 추가해주세요." }, 500);
    }

    // 요청 형태부터 검증한다. messages가 이상하면 Anthropic에 보낼 필요도 없다.
    if (!Array.isArray(body.messages) || body.messages.length === 0 || body.messages.length > 4) {
      return sendJson(res, { error: "요청 형식이 올바르지 않아요." }, 400);
    }
    const totalChars = body.messages.reduce((sum, m) => sum + String((m && m.content) || "").length, 0);
    if (totalChars > 60000) {
      return sendJson(res, { error: "요청이 너무 길어요." }, 400);
    }

    const today = new Date().toISOString().slice(0, 10);

    // (1) 사용자별 원시 호출 한도.
    // 예전에는 이 분기에 사용자별 검사가 아예 없어서, consume_usage를 건너뛰고
    // 여기로 직접 요청하면 무한정 호출할 수 있었다(요금이 그대로 새는 구멍).
    // 이제는 호출 "전에" 원자적으로 1 올리고, 그 결과로 한도를 판정한다.
    const rawCallKey = "apicalls:" + username + ":" + today;
    const myCalls = await APP_KV.incr(rawCallKey, 172800);
    if (myCalls > RAW_CALL_DAILY_CAP) {
      return sendJson(res, { error: "오늘 요청이 너무 많아요. 잠시 후나 내일 다시 시도해주세요.", limitReached: true }, 429);
    }

    // (2) 전체 한도. 마찬가지로 읽고-쓰기 대신 원자적 증가로 판정한다.
    // 예전 방식은 동시에 들어온 요청들이 전부 같은 값을 읽고 전부 통과해서,
    // 사실상 한도가 없는 것과 같았다.
    const usageKey = "count:" + today;
    const globalCalls = await APP_KV.incr(usageKey, 172800);
    if (globalCalls > GLOBAL_DAILY_LIMIT) {
      return sendJson(res, { error: "오늘 전체 사용량 한도를 넘었어요. 내일 다시 시도해주세요.", limitReached: true }, 429);
    }

    try {
      // 모델과 분량은 사용자가 정하게 두지 않는다.
      // 예전에는 body.model / body.max_tokens가 그대로 전달돼서, 비싼 모델에
      // max_tokens를 크게 걸어 요금을 태울 수 있었다.
      const requestedModel = typeof body.model === "string" ? body.model : "";
      const requestedTokens = parseInt(body.max_tokens, 10);
      const anthropicBody = {
        model: ALLOWED_MODELS.includes(requestedModel) ? requestedModel : DEFAULT_MODEL,
        max_tokens: Math.min(Number.isFinite(requestedTokens) && requestedTokens > 0 ? requestedTokens : 1000, MAX_TOKENS_CAP),
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
      // 카운터는 호출 "전에" 이미 올렸다. 실패한 호출도 세는 셈인데,
      // 실패해도 토큰 요금이 나가는 경우가 있어서 이쪽이 안전한 방향이다.
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
    // 이 사람의 세션 목록에도 넣어둔다(로그아웃·아이디 변경·탈퇴에서 필요)
    await APP_KV.addSession(username, token);

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
    // 예전에 가입한 계정에는 oauthId가 없다. 아이디를 바꿀 때 이 연결고리를
    // 같이 옮겨야 하는데, 없으면 계정이 깨지므로 로그인하는 김에 채워둔다.
    const recRaw = await APP_KV.get("user:" + existingUsername);
    if (recRaw) {
      const rec = JSON.parse(recRaw);
      if (!rec.oauthId) {
        await APP_KV.put("user:" + existingUsername, JSON.stringify({ ...rec, oauthProvider: provider, oauthId: socialId }));
      }
    }
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
    // oauthId까지 남겨야 나중에 아이디를 바꿀 때 oauth: 연결고리를 찾아 옮길 수 있다
    JSON.stringify({ hash: null, salt: null, plan: "free", createdAt: Date.now(), oauthProvider: provider, oauthId: socialId })
  );
  await APP_KV.put(linkKey, username);
  return username;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("시그넷 백엔드 실행 중 · 포트 " + PORT);
});
