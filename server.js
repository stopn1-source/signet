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
//   NAVER_SEARCH_CLIENT_ID / NAVER_SEARCH_CLIENT_SECRET
//                             (선택) 네이버 뉴스 검색 API. 넣으면 뉴스 탭이 Anthropic 웹검색 대신
//                             네이버 검색으로 기사를 찾아서 원가가 1/4로 줄어요. 없으면 예전 방식 그대로.
//                             2026-07부터 검색 API는 네이버 클라우드 "NAVER API HUB"에서 발급해요
//                             (콘솔 → NAVER API HUB → Application → 인증 정보의 Client ID / Client Secret).
//                             옛 개발자센터 키를 넣어도 돌아가게 두 주소를 차례로 시도해요.
//                             developers.naver.com → 내 애플리케이션 → 사용 API에 "검색" 추가
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
// 가벼운 호출(참고자료·교육과정·용어·면접·뉴스 정리)은 Haiku로 돌린다. Sonnet의 1/20 가격이다.
const ALLOWED_MODELS = ["claude-sonnet-5", "claude-haiku-5-5"];
const DEFAULT_MODEL = "claude-sonnet-5";
// 한 번의 호출에서 만들 수 있는 최대 분량. 프론트가 제일 크게 쓰는 값이 7000이라
// 그보다 약간 여유를 둔 상한으로 자른다.
const MAX_TOKENS_CAP = 8000;
// 사용자 1명이 하루에 보낼 수 있는 원시 AI 호출 수.
// "생성 버튼 1번"이 내부적으로 4~6번 호출되므로, 버튼 한도(FREE_DAILY_LIMIT)에
// 넉넉히 곱한 값으로 잡는다. 정상 사용으로는 닿지 않고, 스크립트 악용만 걸린다.
const RAW_CALL_DAILY_CAP = parseInt(process.env.RAW_CALL_DAILY_CAP || "250", 10);

// 검색 횟수 상한. 검색 결과가 통째로 입력 토큰에 실려서, 이 숫자가 원가에 직접 영향을 준다.
// 3 → 2로 낮추면 주제 1건당 60원쯤 줄어든다. Render 환경변수로 조절할 수 있게 빼둔다.
const WEB_SEARCH_MAX_USES = Math.min(5, Math.max(1, parseInt(process.env.WEB_SEARCH_MAX_USES || "3", 10)));

// ============================================================
// 응답 캐시 — 같은 질문에 같은 답이 나와야 정상인 호출만 재사용한다
//
// AI 호출은 쓸수록 돈이 나간다. 그런데 시그넷의 호출 중 상당수는
// "같은 입력이면 같은 답이 나와야 맞는" 것들이다.
//   · 화학공학과 안에 어떤 세부 분야가 있는지 → 학생마다 달라야 할 이유가 없다
//   · 이 주제가 교과서 어느 단원과 이어지는지 → 주제가 같으면 단원도 같다
//   · 관련 뉴스, 참고도서, 수식 설명          → 마찬가지
// 한 번 만들어두고 다시 쓰면 요금이 0원이고, 응답도 기다림 없이 바로 나간다.
//
// 반대로 절대 재사용하면 안 되는 것도 있다.
//   · 탐구 주제 추천 → 같은 조건의 두 학생에게 같은 주제가 나가면 생기부가 겹친다
//   · 3년 로드맵     → 친구랑 계획이 똑같으면 서비스를 믿지 않게 된다
//
// 그래서 캐시해도 되는 종류를 프론트가 cacheType으로 알려주고, 서버는 그 이름이
// 허용 목록에 있을 때만 여럿이 나눠 쓰는 캐시에 넣는다. 키는 서버가 프롬프트
// 내용으로 직접 만들기 때문에 클라이언트가 조작할 수 없다.
// ============================================================

const CACHE_TTL = {
  tracks:     60 * 60 * 24 * 180, // 학과 안의 세부 분야 — 학과 목록이 유한해서 곧 전부 캐시된다
  glossary:   60 * 60 * 24 * 90,  // 용어 풀이
  curriculum: 60 * 60 * 24 * 60,  // 교육과정 연계
  materials:  60 * 60 * 24 * 60,  // 참고자료(전공서적·교양서)
  formula:    60 * 60 * 24 * 60,  // 수식 설명
  graphs:     60 * 60 * 24 * 30,  // 수식표·그래프 (웹검색이 붙어 제일 비싼 호출)
  content:    60 * 60 * 24 * 30,  // 탐구내용 세 덩어리
  interview:  60 * 60 * 24 * 30,  // 면접 예상질문
  news:       60 * 60 * 24 * 7,   // 뉴스 연계 — 시의성이 있어 짧게
  briefguide: 60 * 60 * 24 * 30,  // 안내문 항목별 안내
};

// 프롬프트에 이 말이 들어 있으면 종류와 상관없이 캐시하지 않는다.
// 프론트가 실수로 cacheType을 잘못 붙여도 주제·로드맵이 재사용되는 사고를 막는다.
const NEVER_CACHE_MARKERS = [
  "이미 이전에 추천한 주제야",
  "정확히 1개만 추천",
  "3년 전체 계획",
  "관통하는",
];

const CACHE_MAX_CHARS = 200000; // 너무 큰 응답은 저장소만 잡아먹으니 건너뛴다

function aiCacheKey(anthropicBody) {
  const h = nodeCrypto.createHash("sha256").update(JSON.stringify({
    m: anthropicBody.model,
    t: anthropicBody.max_tokens,
    s: !!anthropicBody.tools,
    x: anthropicBody.messages,
  })).digest("hex");
  return h;
}

// 프롬프트에 재사용 금지 표시가 있는지
function isNeverCacheable(messages) {
  const text = messages.map(m => String((m && m.content) || "")).join("\n");
  return NEVER_CACHE_MARKERS.some(marker => text.includes(marker));
}

// 여럿이 나눠 쓰는 캐시의 보관 기간. null이면 공유 캐시를 쓰지 않는다.
function sharedCacheTtl(cacheType, messages) {
  const type = typeof cacheType === "string" ? cacheType : "";
  if (!Object.prototype.hasOwnProperty.call(CACHE_TTL, type)) return null;
  if (isNeverCacheable(messages)) return null;
  return CACHE_TTL[type];
}

// 토큰 사용량을 달 단위로 쌓아둔다.
// 지금까지 원가는 프롬프트 길이로 추정한 값이었다. 실측이 있어야 가격을 자신 있게
// 정할 수 있어서, 응답에 들어오는 usage를 그대로 기록한다.
// 기록이 실패해도 사용자 요청은 그대로 진행시킨다.
async function recordTokenUsage(username, payloadText, fromCache) {
  try {
    const month = new Date().toISOString().slice(0, 7);
    const parsed = JSON.parse(payloadText);
    const u = (parsed && parsed.usage) || {};
    const inTok = (u.input_tokens || 0) + (u.cache_read_input_tokens || 0) + (u.cache_creation_input_tokens || 0);
    const outTok = u.output_tokens || 0;
    const searches = ((u.server_tool_use) || {}).web_search_requests || 0;
    // 캐시로 아낀 양은 따로 센다 — 캐시가 실제로 얼마나 일하는지 보려고
    const fields = fromCache
      ? { hits: 1, saved_in: inTok, saved_out: outTok, saved_searches: searches }
      : { calls: 1, in: inTok, out: outTok, searches: searches };
    for (const [field, value] of Object.entries(fields)) {
      if (!value) continue;
      await redis.hincrby("tok:" + month, field, value);
      await redis.hincrby("tok:" + month + ":" + username, field, value);
    }
    await redis.expire("tok:" + month + ":" + username, 60 * 60 * 24 * 400);
  } catch (e) {
    // 사용량 기록은 부가 기능이라 조용히 넘어간다
  }
}

// 100만 토큰당 단가 (claude-sonnet-5 기준). 요금이 바뀌면 여기만 고치면 된다.
const PRICE_IN_PER_MTOK = 2;
const PRICE_OUT_PER_MTOK = 10;
const PRICE_PER_SEARCH = 0.01;


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
app.use(express.json({ limit: "12mb" }));

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
        "roadmaps:" + username,
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
      // id를 돌려줘야, 탭을 열어 내용이 채워졌을 때 이 항목을 찾아 갱신할 수 있다
      return sendJson(res, { success: true, id: entry.id }, 200);
    }

    // ===== 저장된 주제에 뒤늦게 받은 내용 채워 넣기 =====
    // 주제를 받은 직후에는 개요만 있고, 탐구내용·참고자료·뉴스는 탭을 열어야 만들어진다.
    // 그래서 저장은 개요만 된 채로 남아 있었고, 나중에 찜/기록에서 열면 텅 비어 보였다.
    // 탭이 열릴 때마다 여기로 보내서 저장된 항목을 채운다.
    if (body.action === "update_saved_topic") {
      const scope = body.scope === "favorite" ? "fav" : "hist";
      const id = String(body.id || "");
      const patch = body.patch;
      if (!id || !patch || typeof patch !== "object") {
        return sendJson(res, { error: "채워 넣을 내용이 없어요." }, 400);
      }
      // 아무 값이나 덮어쓰지 않도록, 뒤늦게 채워질 수 있는 항목만 받는다
      const ALLOWED = ["content", "motivation", "formulaPart", "curriculum", "materials", "raw", "news"];
      const clean = {};
      for (const key of ALLOWED) {
        if (patch[key] === undefined) continue;
        const val = patch[key];
        if (typeof val === "string") clean[key] = val.slice(0, 20000);
        else if (val && typeof val === "object") {
          const asText = JSON.stringify(val);
          if (asText.length <= 60000) clean[key] = val;
        }
      }
      if (!Object.keys(clean).length) {
        return sendJson(res, { error: "채워 넣을 내용이 없어요." }, 400);
      }
      const listRaw = await APP_KV.get(scope + ":" + username);
      const list = listRaw ? JSON.parse(listRaw) : [];
      const target = list.find(x => x.id === id);
      if (!target) {
        return sendJson(res, { error: "저장된 주제를 찾을 수 없어요." }, 404);
      }
      Object.assign(target, clean);
      await APP_KV.put(scope + ":" + username, JSON.stringify(list));
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

      for (const prefix of ["fav:", "hist:", "assign:", "roadmap:", "roadmaps:"]) {
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

    // ===== 생기부 로드맵 =====
    // 찜처럼 여러 개를 보관할 수 있게 한 배열에 담아둔다.
    // 키를 로드맵마다 따로 만들면 목록을 뽑을 때 키를 훑어야 해서, 한 키에 모아 두는 편이 단순하다.
    const RM_LIST_KEY = "roadmaps:" + username;
    const RM_MAX = 10;

    async function loadRoadmaps() {
      const raw = await APP_KV.get(RM_LIST_KEY);
      if (raw) {
        try { const arr = JSON.parse(raw); return Array.isArray(arr) ? arr : []; } catch (e) { return []; }
      }
      // 예전에는 사용자당 로드맵을 하나만 뒀다. 그때 저장한 게 있으면 목록으로 옮겨준다.
      const legacy = await APP_KV.get("roadmap:" + username);
      if (legacy) {
        try {
          const one = JSON.parse(legacy);
          one.id = one.id || ("rm" + Date.now().toString(36));
          return [one];
        } catch (e) { return []; }
      }
      return [];
    }

    async function saveRoadmaps(list) {
      await APP_KV.put(RM_LIST_KEY, JSON.stringify(list.slice(0, RM_MAX)));
    }

    // 목록 화면에 쓸 요약만 뽑는다 (본문까지 다 내려보내면 목록이 무거워진다)
    function roadmapSummary(rm) {
      const subs = rm.subjects || [];
      return {
        id: rm.id,
        title: (rm.thread || {}).title || "제목 없는 로드맵",
        career: rm.career || "",
        track: rm.track || (rm.trackBroad ? "전공 전체를 폭넓게" : ""),
        grade: rm.grade || "",
        subjectCount: subs.length,
        doneCount: subs.filter(x => x.status === "done").length,
        topicCount: subs.reduce((n, x) => n + ((x.topics || []).length), 0),
        pinned: !!rm.pinned,
        updatedAt: rm.updatedAt || 0
      };
    }

    if (body.action === "save_roadmap") {
      const roadmap = body.roadmap;
      if (!roadmap || !roadmap.thread || !Array.isArray(roadmap.subjects)) {
        return sendJson(res, { error: "저장할 로드맵 정보가 없어요." }, 400);
      }
      const list = await loadRoadmaps();
      const wantedId = String(roadmap.id || "").slice(0, 40);
      const existing = wantedId ? list.find(x => x.id === wantedId) : null;

      // 통째로 받은 걸 그대로 저장하지 않고, 쓸 항목만 골라 담는다.
      // 안 그러면 임의의 큰 데이터가 그대로 저장될 수 있다.
      const clean = {
        id: existing ? existing.id : ("rm" + Date.now().toString(36) + Math.random().toString(36).slice(2, 6)),
        career: String(roadmap.career || "").slice(0, 100),
        track: String(roadmap.track || "").slice(0, 100),
        // 학생이 일부러 "폭넓게"를 고른 것과, 그냥 안 적은 것은 다르게 다뤄야 해서 따로 기록한다
        trackBroad: !!roadmap.trackBroad,
        interest: String(roadmap.interest || "").slice(0, 100),
        // 이미 해둔 탐구·활동 (다시 만들 때 그대로 되살리려고 같이 보관해요)
        done: String(roadmap.done || "").slice(0, 600),
        grade: String(roadmap.grade || "").slice(0, 20),
        thread: {
          title: String((roadmap.thread || {}).title || "").slice(0, 200),
          why: String((roadmap.thread || {}).why || "").slice(0, 1000)
        },
        sequence: (roadmap.sequence || []).slice(0, 8).map(sq => ({
          phase: String(sq.phase || "").slice(0, 60),
          what: String(sq.what || "").slice(0, 600)
        })),
        // 찜은 사용자가 누른 값이라, 로드맵을 다시 만들어도 그대로 둔다
        pinned: existing ? !!existing.pinned : false,
        subjects: roadmap.subjects.slice(0, 18).map((sub, idx) => {
          // 이미 저장돼 있던 항목이면 거기 담아둔 주제들은 살려둔다
          const prev = existing ? (existing.subjects || []).find(x => x.id === sub.id) : null;
          return {
            id: String(sub.id || ("s" + idx)).slice(0, 40),
            subject: String(sub.subject || "").slice(0, 60),
            // 몇 학년 때 듣는 과목인지 (1/2/3, 모르면 0)
            year: Math.min(3, Math.max(0, parseInt(sub.year, 10) || 0)),
            // 한눈에 보기 도형에 들어가는 값들 — 어느 시기 칸에 놓을지, 칸 안에 뭐라고 쓸지
            phaseNo: Math.min(9, Math.max(0, parseInt(sub.phaseNo, 10) || 0)),
            phase: String(sub.phase || "").slice(0, 60),
            short: String(sub.short || "").slice(0, 40),
            angle: String(sub.angle || "").slice(0, 600),
            topicIdea: String(sub.topicIdea || "").slice(0, 600),
            connectsTo: String(sub.connectsTo || "").slice(0, 400),
            status: ["todo", "doing", "done"].includes(sub.status) ? sub.status : "todo",
            topics: prev ? (prev.topics || []) : []
          };
        }),
        updatedAt: Date.now()
      };

      const next = existing
        ? list.map(x => (x.id === clean.id ? clean : x))
        : [clean].concat(list).slice(0, RM_MAX);
      await saveRoadmaps(next);
      return sendJson(res, { success: true, roadmap: clean, roadmaps: next.map(roadmapSummary) }, 200);
    }

    // ===== 보관해둔 로드맵 목록 =====
    if (body.action === "list_roadmaps") {
      const list = await loadRoadmaps();
      return sendJson(res, { success: true, roadmaps: list.map(roadmapSummary) }, 200);
    }

    // ===== 로드맵 하나 불러오기 (id가 없으면 가장 최근 것) =====
    if (body.action === "get_roadmap") {
      const list = await loadRoadmaps();
      if (!list.length) return sendJson(res, { success: true, roadmap: null, roadmaps: [] }, 200);
      const wanted = String(body.id || "");
      const found = wanted ? list.find(x => x.id === wanted) : null;
      // 찜해둔 로드맵이 있으면 그게 먼저 열린다. 없으면 가장 최근에 손댄 것.
      const pinned = list.find(x => x.pinned);
      const latest = list.slice().sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0))[0];
      const pick = found || pinned || latest;
      return sendJson(res, { success: true, roadmap: pick || null, roadmaps: list.map(roadmapSummary) }, 200);
    }

    // ===== 로드맵 항목 진행 상태 변경 =====
    if (body.action === "update_roadmap_status") {
      const itemId = String(body.itemId || "");
      const status = body.status;
      if (!["todo", "doing", "done"].includes(status)) {
        return sendJson(res, { error: "상태 값이 올바르지 않아요." }, 400);
      }
      const list = await loadRoadmaps();
      const rm = String(body.id || "") ? list.find(x => x.id === body.id) : list[0];
      if (!rm) return sendJson(res, { error: "저장된 로드맵이 없어요." }, 404);
      const target = (rm.subjects || []).find(sub => sub.id === itemId);
      if (!target) return sendJson(res, { error: "해당 항목을 찾을 수 없어요." }, 404);
      target.status = status;
      rm.updatedAt = Date.now();
      await saveRoadmaps(list);
      return sendJson(res, { success: true }, 200);
    }

    // ===== 로드맵에 탐구 주제 담기 =====
    // 그 로드맵을 보고 받은 주제를 해당 과목 밑에 쌓아둬서, 나중에 로드맵 화면에서 한 번에 볼 수 있게 한다.
    if (body.action === "attach_roadmap_topic") {
      const itemId = String(body.itemId || "");
      const topic = body.topic || {};
      const title = String(topic.title || "").trim();
      if (!title) return sendJson(res, { error: "담을 주제가 없어요." }, 400);

      const list = await loadRoadmaps();
      const rm = String(body.id || "") ? list.find(x => x.id === body.id) : list[0];
      if (!rm) return sendJson(res, { error: "저장된 로드맵이 없어요." }, 404);
      const target = (rm.subjects || []).find(sub => sub.id === itemId);
      if (!target) return sendJson(res, { error: "해당 항목을 찾을 수 없어요." }, 404);

      target.topics = target.topics || [];
      if (target.topics.some(t => t.title === title.slice(0, 200))) {
        return sendJson(res, { success: true, already: true, roadmap: rm }, 200);
      }
      target.topics.unshift({
        topicId: "t" + Date.now().toString(36) + Math.random().toString(36).slice(2, 5),
        title: title.slice(0, 200),
        summary: String(topic.summary || "").slice(0, 400),
        savedAt: Date.now()
      });
      target.topics = target.topics.slice(0, 8);
      rm.updatedAt = Date.now();
      await saveRoadmaps(list);
      return sendJson(res, { success: true, roadmap: rm }, 200);
    }

    // ===== 로드맵에 담아둔 주제 빼기 =====
    if (body.action === "detach_roadmap_topic") {
      const itemId = String(body.itemId || "");
      const topicId = String(body.topicId || "");
      const list = await loadRoadmaps();
      const rm = String(body.id || "") ? list.find(x => x.id === body.id) : list[0];
      if (!rm) return sendJson(res, { error: "저장된 로드맵이 없어요." }, 404);
      const target = (rm.subjects || []).find(sub => sub.id === itemId);
      if (!target) return sendJson(res, { error: "해당 항목을 찾을 수 없어요." }, 404);
      target.topics = (target.topics || []).filter(t => t.topicId !== topicId);
      rm.updatedAt = Date.now();
      await saveRoadmaps(list);
      return sendJson(res, { success: true, roadmap: rm }, 200);
    }

    // ===== 로드맵 찜하기 =====
    // 여러 개를 보관하다 보면 "지금 내가 따라가는 계획"이 뭔지 흐려져요.
    // 찜해두면 로드맵 화면에 들어올 때 그게 먼저 열립니다. 찜은 하나만 됩니다.
    if (body.action === "pin_roadmap") {
      const wanted = String(body.id || "");
      const list = await loadRoadmaps();
      const target = list.find(x => x.id === wanted);
      if (!target) return sendJson(res, { error: "해당 로드맵을 찾을 수 없어요." }, 404);
      const turningOn = !target.pinned;
      list.forEach(x => { x.pinned = false; });
      target.pinned = turningOn;
      await saveRoadmaps(list);
      return sendJson(res, { success: true, pinned: turningOn, roadmaps: list.map(roadmapSummary) }, 200);
    }

    // ===== 생기부 로드맵 삭제 =====
    if (body.action === "delete_roadmap") {
      const wanted = String(body.id || "");
      const list = await loadRoadmaps();
      const next = wanted ? list.filter(x => x.id !== wanted) : [];
      await saveRoadmaps(next);
      // 예전 방식으로 저장돼 있던 것도 같이 지운다
      if (!next.length) await APP_KV.delete("roadmap:" + username);
      return sendJson(res, { success: true, roadmaps: next.map(roadmapSummary) }, 200);
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

    // ===== 뉴스 기사 찾기 (네이버 검색 API) =====
    // Claude에게 "검색해서 찾아봐"라고 시키면 검색 결과 본문이 통째로 입력 토큰에 실려서
    // 뉴스 탭 하나가 110원쯤 나간다. 대신 네이버가 기사 제목·요약·링크를 공짜로 주니까
    // 그걸 받아서 Claude에게는 "이 중에서 골라 정리해줘"만 시킨다. 링크가 진짜라는 보장도 생긴다.
    // 키가 없으면 {available:false}를 돌려주고, 프론트가 예전 방식으로 알아서 넘어간다.
    if (body.action === "news_search") {
      const cid = process.env.NAVER_SEARCH_CLIENT_ID, csec = process.env.NAVER_SEARCH_CLIENT_SECRET;
      if (!cid || !csec) return sendJson(res, { available: false, items: [] }, 200);
      const q = String(body.query || "").trim().slice(0, 80);
      if (!q) return sendJson(res, { error: "검색어가 비어 있어요." }, 400);
      const nkey = "news:" + nodeCrypto.createHash("sha256").update(q).digest("hex").slice(0, 32);
      const hit = await APP_KV.get(nkey);
      if (hit) { res.status(200).type("application/json").send(hit); return; }
      try {
        // 1순위: NAVER API HUB(네이버 클라우드). 키가 HUB 것이 아니면 401/403/404가 나니 그때만 옛 주소로 한 번 더.
        const qs = "?display=8&sort=sim&query=" + encodeURIComponent(q);
        let r = await fetch("https://naverapihub.apigw.ntruss.com/search/v1/news" + qs + "&format=json", {
          headers: { "X-NCP-APIGW-API-KEY-ID": cid, "X-NCP-APIGW-API-KEY": csec }
        });
        if (r.status === 401 || r.status === 403 || r.status === 404) {
          r = await fetch("https://openapi.naver.com/v1/search/news.json" + qs, {
            headers: { "X-Naver-Client-Id": cid, "X-Naver-Client-Secret": csec }
          });
        }
        if (!r.ok) {
          console.error("naver news_search failed:", r.status);
          return sendJson(res, { available: false, items: [], error: "naver " + r.status }, 200);
        }
        const data = await r.json();
        const strip = t => String(t || "").replace(/<[^>]+>/g, "").replace(/&quot;/g, '"').replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&#39;/g, "'");
        const items = (data.items || []).map(it => ({
          title: strip(it.title), summary: strip(it.description),
          link: it.originallink || it.link || "", date: String(it.pubDate || "").slice(0, 16)
        })).filter(it => it.title && /^https?:\/\//.test(it.link)).slice(0, 6);
        const payload = JSON.stringify({ available: true, items });
        await APP_KV.put(nkey, payload, { expirationTtl: 60 * 60 * 24 * 3 });   // 같은 검색어는 3일 재사용
        res.status(200).type("application/json").send(payload);
      } catch (err) {
        return sendJson(res, { available: false, items: [], error: err.message }, 200);
      }
      return;
    }

    // ===== 이번 달 토큰 사용량과 예상 요금 =====
    // 추정이 아니라 실제로 쓴 양을 보여준다. 캐시가 얼마나 아껴줬는지도 함께.
    if (body.action === "get_cost") {
      const month = new Date().toISOString().slice(0, 7);
      const mine = (await redis.hgetall("tok:" + month + ":" + username)) || {};
      const all = (await redis.hgetall("tok:" + month)) || {};
      const num = (o, k) => parseInt(o[k] || "0", 10);
      const cost = o =>
        num(o, "in") * PRICE_IN_PER_MTOK / 1e6 +
        num(o, "out") * PRICE_OUT_PER_MTOK / 1e6 +
        num(o, "searches") * PRICE_PER_SEARCH;
      const saved = o =>
        num(o, "saved_in") * PRICE_IN_PER_MTOK / 1e6 +
        num(o, "saved_out") * PRICE_OUT_PER_MTOK / 1e6 +
        num(o, "saved_searches") * PRICE_PER_SEARCH;
      return sendJson(res, {
        success: true,
        month,
        me: { calls: num(mine, "calls"), cacheHits: num(mine, "hits"), inputTokens: num(mine, "in"), outputTokens: num(mine, "out"), usd: +cost(mine).toFixed(4), savedUsd: +saved(mine).toFixed(4) },
        total: { calls: num(all, "calls"), cacheHits: num(all, "hits"), inputTokens: num(all, "in"), outputTokens: num(all, "out"), usd: +cost(all).toFixed(4), savedUsd: +saved(all).toFixed(4) },
      }, 200);
    }

    // ===== 그림 찾기 (위키미디어 공용) =====
    // 탐구내용 옆에 붙일 그림을 찾는다. 공용 저장소라 무료이고 출처·라이선스가 같이 온다.
    // 학생이 사진 출처를 적어야 하는 수행평가에 그대로 쓸 수 있다.
    if (body.action === "image_search") {
      const q = String(body.query || "").trim().slice(0, 80);
      if (!q) return sendJson(res, { error: "검색어가 비어 있어요." }, 400);
      const ikey = "img:" + nodeCrypto.createHash("sha256").update(q.toLowerCase()).digest("hex").slice(0, 32);
      const hit = await APP_KV.get(ikey);
      if (hit) { res.status(200).type("application/json").send(hit); return; }
      try {
        const url = "https://commons.wikimedia.org/w/api.php?action=query&format=json&generator=search&gsrnamespace=6&gsrlimit=8"
          + "&gsrsearch=" + encodeURIComponent(q + " filetype:bitmap|drawing") + "&prop=imageinfo&iiprop=url|mime|extmetadata&iiurlwidth=720";
        const r = await fetch(url, { headers: { "User-Agent": "signet-backend/1.0 (https://si9net.com)" } });
        if (!r.ok) return sendJson(res, { items: [] }, 200);
        const data = await r.json();
        const strip = t => String(t || "").replace(/<[^>]+>/g, "").trim();
        // 검색 순위대로 정렬하고, 다른 언어판 도식(… de.svg 같은 것)은 뒤로 보낸다
        const pages = Object.values((data.query && data.query.pages) || {}).sort((a, b) => (a.index || 0) - (b.index || 0));
        const foreign = t => /[ _-](de|es|pl|id|fr|ru|ja|zh|it|pt|tr|ku|nl|cs|uk|fa|ar|he|ko|vi|th)\d*\.(svg|png)$/i.test(t);
        pages.sort((a, b) => (foreign(a.title) ? 1 : 0) - (foreign(b.title) ? 1 : 0));
        const items = pages
          .map(pg => { const ii = (pg.imageinfo || [])[0] || {}; const md = ii.extmetadata || {}; return {
            title: String(pg.title || "").replace(/^File:/, ""),
            thumb: ii.thumburl || "", url: ii.url || "", page: ii.descriptionurl || "",
            mime: ii.mime || "",
            artist: strip((md.Artist || {}).value).slice(0, 80),
            license: strip((md.LicenseShortName || {}).value).slice(0, 40),
          }; })
          .filter(it => it.thumb && /^image\/(jpeg|png|svg\+xml|gif|webp)$/.test(it.mime))
          .slice(0, 4);
        const payload = JSON.stringify({ items });
        await APP_KV.put(ikey, payload, { expirationTtl: 60 * 60 * 24 * 14 });
        res.status(200).type("application/json").send(payload);
      } catch (err) {
        return sendJson(res, { items: [], error: err.message }, 200);
      }
    }

    // ===== 생기부 읽기 (활동 요약만) =====
    // 파일(PDF·사진·HWPX·DOCX)을 받아 "과목별로 무엇을 했는지"만 돌려준다.
    // 원문은 이 요청을 처리하는 동안만 메모리에 있고, 저장하지 않는다. 응답에도 원문을 넣지 않는다.
    if (body.action === "analyze_record") {
      if (!process.env.ANTHROPIC_API_KEY) return sendJson(res, { error: "서버에 API 키가 설정되지 않았어요." }, 500);
      if (!body.consent) return sendJson(res, { error: "개인정보 처리 동의가 필요해요." }, 400);
      const file = body.file;
      if (!file || typeof file.data !== "string") return sendJson(res, { error: "파일이 비어 있어요." }, 400);
      const name = String(file.name || "").toLowerCase();
      const mime = String(file.type || "").toLowerCase();
      if (file.data.length > BRIEF_MAX_BYTES * 1.4) return sendJson(res, { error: "파일이 너무 커요. 8MB 이하로 올려주세요. 쪽을 나눠 저장해서 여러 번 올려도 돼요." }, 400);
      let buf;
      try { buf = Buffer.from(file.data, "base64"); } catch (e) { return sendJson(res, { error: "파일을 읽지 못했어요." }, 400); }
      if (buf.length > BRIEF_MAX_BYTES) return sendJson(res, { error: "파일이 너무 커요. 8MB 이하로 올려주세요." }, 400);
      let text = "", blocks = null;
      try {
        if (name.endsWith(".hwp")) return sendJson(res, { error: "옛 한글(.hwp)은 읽을 수 없어요. PDF로 저장하거나 사진으로 찍어 올려주세요." }, 400);
        else if (name.endsWith(".docx")) text = extractDocxText(buf);
        else if (name.endsWith(".hwpx")) text = extractHwpxText(buf);
        else if (name.endsWith(".txt") || mime === "text/plain") text = buf.toString("utf8");
        else if (name.endsWith(".pdf") || mime === "application/pdf") blocks = [{ type: "document", source: { type: "base64", media_type: "application/pdf", data: file.data } }];
        else if (/\.(png|jpe?g|webp|gif)$/.test(name) || /^image\/(png|jpeg|webp|gif)$/.test(mime)) {
          const mt = /^image\/(png|jpeg|webp|gif)$/.test(mime) ? mime : (name.endsWith(".png") ? "image/png" : name.endsWith(".webp") ? "image/webp" : name.endsWith(".gif") ? "image/gif" : "image/jpeg");
          blocks = [{ type: "image", source: { type: "base64", media_type: mt, data: file.data } }];
        } else return sendJson(res, { error: "지원하지 않는 파일이에요. PDF, 사진(JPG·PNG), HWPX, DOCX로 올려주세요." }, 400);
      } catch (e) {
        return sendJson(res, { error: "파일 내용을 읽지 못했어요. PDF나 사진으로 올려보세요." }, 400);
      }
      if (!blocks && text.trim().length < 50) return sendJson(res, { error: "파일에서 글자를 거의 찾지 못했어요. 스캔본이면 사진이나 PDF로 올려주세요." }, 400);
      text = text.slice(0, 40000);

      const rToday = new Date().toISOString().slice(0, 10);
      const rCalls = await APP_KV.incr("apicalls:" + username + ":" + rToday, 172800);
      if (rCalls > RAW_CALL_DAILY_CAP) return sendJson(res, { error: "오늘 요청이 너무 많아요. 잠시 후나 내일 다시 시도해주세요.", limitReached: true }, 429);

      const content = blocks
        ? blocks.concat([{ type: "text", text: RECORD_INSTRUCTION }])
        : [{ type: "text", text: "생기부 내용:\n" + text + "\n\n" + RECORD_INSTRUCTION }];
      try {
        const r = await fetch("https://api.anthropic.com/v1/messages", {
          method: "POST",
          headers: { "content-type": "application/json", "x-api-key": process.env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "user-agent": "signet-backend/1.0 (Render)" },
          body: JSON.stringify({ model: DEFAULT_MODEL, max_tokens: 4000, messages: [{ role: "user", content }] }),
        });
        const raw = await r.text();
        if (r.status === 401 || r.status === 403) {
          console.error("[Anthropic 인증 오류/analyze_record]", r.status);
          return sendJson(res, { error: "AI 서버 연결에 문제가 생겼어요. 잠시 후 다시 시도해주세요." }, 502);
        }
        if (!r.ok) {
          console.error("[analyze_record 실패]", r.status, raw.slice(0, 200));
          return sendJson(res, { error: "생기부를 읽지 못했어요. 잠시 후 다시 시도해주세요." }, 502);
        }
        await recordTokenUsage(username, raw, false);
        let outText = "";
        try { outText = (JSON.parse(raw).content || []).filter(c => c.type === "text").map(c => c.text).join("\n"); } catch (e) {}
        const parsed = parseRecord(outText);
        // 원문(buf, text, blocks)은 여기서 끝. 아무 데도 저장하지 않는다.
        return sendJson(res, { success: true, record: parsed }, 200);
      } catch (err) {
        return sendJson(res, { error: "생기부 읽기 중 오류: " + err.message }, 500);
      }
    }

    // ===== 선생님 안내문 분석 =====
    // 글(text) 또는 파일(file: {name, type, data(base64)}) 하나를 받아 요구사항을 구조화해 돌려준다.
    // 비용: 글자 파일 ≈ 5원, 사진·PDF ≈ 15원(Haiku). 일반 AI 호출과 같은 일일 호출 한도를 공유한다.
    if (body.action === "analyze_brief") {
      if (!process.env.ANTHROPIC_API_KEY) return sendJson(res, { error: "서버에 API 키가 설정되지 않았어요." }, 500);
      let text = String(body.text || "").trim().slice(0, 12000);
      let blocks = null;
      let sourceKind = "text";
      const file = body.file;
      if (file && typeof file.data === "string") {
        const name = String(file.name || "").toLowerCase();
        const mime = String(file.type || "").toLowerCase();
        if (file.data.length > BRIEF_MAX_BYTES * 1.4) return sendJson(res, { error: "파일이 너무 커요. 8MB 이하로 올려주세요." }, 400);
        let buf;
        try { buf = Buffer.from(file.data, "base64"); } catch (e) { return sendJson(res, { error: "파일을 읽지 못했어요." }, 400); }
        if (buf.length > BRIEF_MAX_BYTES) return sendJson(res, { error: "파일이 너무 커요. 8MB 이하로 올려주세요." }, 400);
        try {
          if (name.endsWith(".hwp")) {
            return sendJson(res, { error: "옛 한글(.hwp) 파일은 읽을 수 없어요. 한글에서 'PDF로 저장'하거나(파일 → PDF로 저장하기), 안내문을 사진으로 찍어 올려주세요." }, 400);
          } else if (name.endsWith(".docx")) {
            text = extractDocxText(buf); sourceKind = "docx";
          } else if (name.endsWith(".hwpx")) {
            text = extractHwpxText(buf); sourceKind = "hwpx";
          } else if (name.endsWith(".txt") || mime === "text/plain") {
            text = buf.toString("utf8"); sourceKind = "txt";
          } else if (name.endsWith(".pdf") || mime === "application/pdf") {
            blocks = [{ type: "document", source: { type: "base64", media_type: "application/pdf", data: file.data } }]; sourceKind = "pdf";
          } else if (/\.(png|jpe?g|webp|gif)$/.test(name) || /^image\/(png|jpeg|webp|gif)$/.test(mime)) {
            const mt = /^image\/(png|jpeg|webp|gif)$/.test(mime) ? mime : (name.endsWith(".png") ? "image/png" : name.endsWith(".webp") ? "image/webp" : name.endsWith(".gif") ? "image/gif" : "image/jpeg");
            blocks = [{ type: "image", source: { type: "base64", media_type: mt, data: file.data } }]; sourceKind = "image";
          } else {
            return sendJson(res, { error: "지원하지 않는 파일이에요. PDF, 사진(JPG·PNG), HWPX, DOCX, TXT로 올려주세요." }, 400);
          }
        } catch (e) {
          return sendJson(res, { error: "파일 내용을 읽지 못했어요. 다른 형식(PDF나 사진)으로 올려보세요." }, 400);
        }
        if (!blocks && text.trim().length < 20) {
          return sendJson(res, { error: "파일에서 글자를 거의 찾지 못했어요. 스캔한 문서면 사진이나 PDF로 올려주세요." }, 400);
        }
        text = text.slice(0, 12000);
      }
      if (!blocks && !text) return sendJson(res, { error: "안내문 내용이 비어 있어요." }, 400);

      // 일반 AI 호출과 같은 사용자별 한도를 쓴다
      const bToday = new Date().toISOString().slice(0, 10);
      const bCalls = await APP_KV.incr("apicalls:" + username + ":" + bToday, 172800);
      if (bCalls > RAW_CALL_DAILY_CAP) return sendJson(res, { error: "오늘 요청이 너무 많아요. 잠시 후나 내일 다시 시도해주세요.", limitReached: true }, 429);

      const content = blocks
        ? blocks.concat([{ type: "text", text: BRIEF_INSTRUCTION }])
        : [{ type: "text", text: "안내문 원문:\n" + text + "\n\n" + BRIEF_INSTRUCTION }];
      const callModel = async (model) => fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "content-type": "application/json", "x-api-key": process.env.ANTHROPIC_API_KEY, "anthropic-version": "2023-06-01", "user-agent": "signet-backend/1.0 (Render)" },
        body: JSON.stringify({ model, max_tokens: 2500, messages: [{ role: "user", content }] }),
      });
      try {
        // 항목을 빠뜨리면 그 뒤 결과물이 전부 어긋나서, 이 호출만은 기본 모델(Sonnet)로 돌린다 (약 40원)
        let r = await callModel(DEFAULT_MODEL);
        const raw = await r.text();
        if (r.status === 401 || r.status === 403) {
          console.error("[Anthropic 인증 오류/analyze_brief]", r.status, raw.slice(0, 200));
          return sendJson(res, { error: "AI 서버 연결에 문제가 생겼어요. 잠시 후 다시 시도해주세요." }, 502);
        }
        if (!r.ok) {
          console.error("[analyze_brief 실패]", r.status, raw.slice(0, 300));
          return sendJson(res, { error: "안내문을 분석하지 못했어요. 잠시 후 다시 시도해주세요." }, 502);
        }
        await recordTokenUsage(username, raw, false);
        let outText = "";
        try { outText = (JSON.parse(raw).content || []).filter(c => c.type === "text").map(c => c.text).join("\n"); } catch (e) {}
        const brief = parseBrief(outText);
        // 화면과 다음 프롬프트에서 쓸 원문: 글자 파일은 뽑은 글자, 사진·PDF는 모델이 옮겨 적은 것
        brief.text = blocks ? brief.text : text.slice(0, 3000);
        brief.source = sourceKind;
        return sendJson(res, { success: true, brief }, 200);
      } catch (err) {
        return sendJson(res, { error: "안내문 분석 중 오류: " + err.message }, 500);
      }
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

    // 보낼 내용을 먼저 확정한다. 캐시 키를 이 내용으로 만들기 때문에,
    // 사용자가 model이나 max_tokens를 바꿔 보내도 키가 갈라질 뿐 남의 캐시를 건드리지 못한다.
    const requestedModel = typeof body.model === "string" ? body.model : "";
    const requestedTokens = parseInt(body.max_tokens, 10);
    const anthropicBody = {
      model: ALLOWED_MODELS.includes(requestedModel) ? requestedModel : DEFAULT_MODEL,
      max_tokens: Math.min(Number.isFinite(requestedTokens) && requestedTokens > 0 ? requestedTokens : 1000, MAX_TOKENS_CAP),
      messages: body.messages,
    };
    if (body.enableSearch) {
      // max_uses로 검색 횟수를 제한해둔다. 안 걸어두면 AI가 데이터를 찾으려고
      // 검색을 반복하면서 응답이 몇 분씩 걸리고 입력 토큰도 그만큼 불어난다.
      anthropicBody.tools = [{ type: "web_search_20250305", name: "web_search", max_uses: WEB_SEARCH_MAX_USES }];
    }

    // ── (0) 캐시부터 본다. 맞으면 API를 아예 부르지 않는다 ──
    const hash = aiCacheKey(anthropicBody);
    const sharedKey = "aic:" + hash;                       // 모두가 나눠 쓰는 캐시
    const selfKey = "aiself:" + username + ":" + hash;     // 같은 사람이 같은 요청을 다시 보낸 경우
    const sharedTtl = sharedCacheTtl(body.cacheType, body.messages);
    const neverCache = isNeverCacheable(body.messages);

    let cached = null;
    if (sharedTtl) cached = await APP_KV.get(sharedKey);
    if (!cached && !neverCache) cached = await APP_KV.get(selfKey);

    if (cached) {
      // 캐시는 요금이 안 나가지만, 무한정 두드리는 것도 막아야 하니 넉넉한 상한을 둔다
      const hits = await APP_KV.incr("aihit:" + username + ":" + today, 172800);
      if (hits > RAW_CALL_DAILY_CAP * 5) {
        return sendJson(res, { error: "오늘 요청이 너무 많아요. 잠시 후 다시 시도해주세요.", limitReached: true }, 429);
      }
      await recordTokenUsage(username, cached, true);
      res.status(200).type("application/json").send(cached);
      return;
    }

    // (1) 사용자별 원시 호출 한도.
    // consume_usage를 건너뛰고 여기로 직접 요청해도 막히도록, 호출 "전에" 원자적으로
    // 1 올리고 그 결과로 판정한다.
    const rawCallKey = "apicalls:" + username + ":" + today;
    const myCalls = await APP_KV.incr(rawCallKey, 172800);
    if (myCalls > RAW_CALL_DAILY_CAP) {
      return sendJson(res, { error: "오늘 요청이 너무 많아요. 잠시 후나 내일 다시 시도해주세요.", limitReached: true }, 429);
    }

    // (2) 전체 한도. 마찬가지로 원자적 증가로 판정한다.
    const usageKey = "count:" + today;
    const globalCalls = await APP_KV.incr(usageKey, 172800);
    if (globalCalls > GLOBAL_DAILY_LIMIT) {
      return sendJson(res, { error: "오늘 전체 사용량 한도를 넘었어요. 내일 다시 시도해주세요.", limitReached: true }, 429);
    }

    try {
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

      if (anthropicResponse.ok) {
        await recordTokenUsage(username, data, false);
        // 성공한 응답만 보관한다. 오류 응답을 캐시하면 그 뒤로 계속 오류가 나간다.
        if (data.length <= CACHE_MAX_CHARS) {
          if (sharedTtl) await APP_KV.put(sharedKey, data, { expirationTtl: sharedTtl });
          // 같은 사람이 탭을 다시 열거나 새로고침했을 때를 위한 짧은 보관.
          // 주제 추천·로드맵처럼 매번 달라야 하는 건 여기에도 넣지 않는다.
          if (!neverCache) await APP_KV.put(selfKey, data, { expirationTtl: 900 });
        }
      }

      // Anthropic이 401/403을 주는 건 "서버의 API 키" 문제지 학생의 로그인 문제가 아니다.
      // 그대로 401을 넘기면 화면이 로그인 만료로 착각해서 학생을 로그아웃시킨다.
      // 그래서 502로 바꾸고 무슨 일인지 서버 로그에 남긴다.
      if (anthropicResponse.status === 401 || anthropicResponse.status === 403) {
        console.error("[Anthropic 인증 오류]", anthropicResponse.status, data.slice(0, 300));
        return sendJson(res, { error: "AI 서버 연결에 문제가 생겼어요. 잠시 후 다시 시도해주세요. (관리자 확인 중)" }, 502);
      }
      res.status(anthropicResponse.status).type("application/json").send(data);
      return;
    } catch (err) {
      return sendJson(res, { error: err.message }, 500);
    }
}

// ============================================================
// 선생님 안내문 읽기 (파일 → 글자)
// 외부 라이브러리 없이 처리한다. docx·hwpx는 zip 안의 XML이라 zlib만 있으면 풀 수 있고,
// PDF와 사진은 Anthropic에 그대로 넘겨 읽게 한다. 옛 .hwp는 바이너리 포맷이라 못 읽는다.
// ============================================================
const zlib = require("zlib");
const BRIEF_MAX_BYTES = 8 * 1024 * 1024;

// zip 안의 파일 하나를 꺼낸다. 중앙 디렉터리를 뒤에서부터 찾아 이름이 맞는 항목만 푼다.
function zipEntries(buf) {
  const entries = {};
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 70000); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) return entries;
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  for (let n = 0; n < count && off + 46 <= buf.length; n++) {
    if (buf.readUInt32LE(off) !== 0x02014b50) break;
    const method = buf.readUInt16LE(off + 10);
    const csize = buf.readUInt32LE(off + 20);
    const nameLen = buf.readUInt16LE(off + 28);
    const extraLen = buf.readUInt16LE(off + 30);
    const commentLen = buf.readUInt16LE(off + 32);
    const localOff = buf.readUInt32LE(off + 42);
    const name = buf.slice(off + 46, off + 46 + nameLen).toString("utf8");
    entries[name] = { method, csize, localOff };
    off += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}
function zipRead(buf, entries, name) {
  const e = entries[name];
  if (!e || buf.readUInt32LE(e.localOff) !== 0x04034b50) return null;
  const nameLen = buf.readUInt16LE(e.localOff + 26);
  const extraLen = buf.readUInt16LE(e.localOff + 28);
  const start = e.localOff + 30 + nameLen + extraLen;
  const data = buf.slice(start, start + e.csize);
  if (e.method === 0) return data;
  if (e.method === 8) return zlib.inflateRawSync(data);
  return null;
}
function xmlToText(xml, paragraphTag) {
  return String(xml)
    .replace(new RegExp("</" + paragraphTag + ">", "g"), "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&apos;/g, "'")
    .replace(/[ \t]+/g, " ").replace(/\n\s*\n+/g, "\n").trim();
}
function extractDocxText(buf) {
  const entries = zipEntries(buf);
  const xml = zipRead(buf, entries, "word/document.xml");
  return xml ? xmlToText(xml.toString("utf8"), "w:p") : "";
}
function extractHwpxText(buf) {
  const entries = zipEntries(buf);
  const names = Object.keys(entries).filter(n => /^Contents\/section\d+\.xml$/.test(n)).sort();
  return names.map(n => { const x = zipRead(buf, entries, n); return x ? xmlToText(x.toString("utf8"), "hp:p") : ""; }).join("\n").trim();
}

// 생기부에서 뽑아낼 것: "어떤 활동을 했는지"만. 개인정보·성적·평가 문장은 뽑지 않는다.
// 원문은 이 요청 안에서만 쓰고 저장하지 않는다 (아래 analyze_record 참고).
const RECORD_INSTRUCTION = `위 내용은 고등학생의 학교생활기록부(생기부)야. 이 학생이 다음 탐구 계획을 "이미 한 활동에 이어서" 짤 수 있도록, 지금까지 어떤 탐구·활동을 했는지만 과목별로 정리해줘.

반드시 지켜:
- 뽑는 것: 학년, 과목(또는 영역: 자율활동/동아리/진로활동/독서), 무엇을 했는지(탐구 소재·방법·결론·읽은 책). 이것만.
- 절대 뽑지 않는 것: 이름, 학교명, 학번, 반·번호, 생년월일, 주소, 성적·등급·석차·점수, 출결, 봉사 시간, 수상 이름, 선생님의 평가·성품 묘사 문장(예: 성실하다, 리더십이 있다). 활동 내용이 아닌 말은 모두 버려.
- 한 활동은 한 줄로, 소재와 방법이 보이게 구체적으로 (예: 화학Ⅰ — 촉매 유무에 따른 과산화수소 분해 속도 비교 실험, 효소 작용에 비유해 발표).
- 같은 과목에 여러 활동이 있으면 줄을 나눠. 최대 40줄.
- 마지막에 이 학생의 관심사가 어떻게 이어져 왔는지(어떤 줄기가 보이는지) 1~2문장.
- 존댓말(해요체)로 쓰되 평가하는 말은 넣지 마.

절대로 다른 설명 없이, 아래 형식으로만 정확히 응답해. 문장 안에 큰따옴표(")는 쓰지 마.

ITEM: 학년::과목이나 영역::무엇을 했는지 한 줄
(ITEM: 줄을 활동 수만큼, 한 줄에 하나씩. 학년은 1학년/2학년/3학년 중 하나, 모르면 비워둬)
THREAD: 지금까지 보이는 관심사의 흐름 1~2문장`;

function parseRecord(rawText) {
  const text = String(rawText || "").replace(/\*\*/g, "").replace(/`/g, "");
  const items = [];
  text.split(/\n/).forEach(line => {
    const m = line.match(/^\s*[-•·]?\s*ITEM:\s*(.+)$/i);
    if (!m) return;
    const p = m[1].split("::").map(x => x.trim());
    if (p.length < 3 || !p[2]) return;
    items.push({ grade: p[0].replace(/[^0-9]/g, "") ? p[0].replace(/[^0-9]/g, "") + "학년" : "", subject: p[1].slice(0, 40), what: p[2].slice(0, 300) });
  });
  const tm = text.match(/THREAD:\s*([\s\S]*?)$/i);
  return { items: items.slice(0, 40), thread: tm ? tm[1].trim().slice(0, 400) : "" };
}

// 안내문에서 뽑아낼 것. 화면은 이 항목들을 그대로 보여주고, 주제·탐구내용 프롬프트에도 넣는다.
const BRIEF_INSTRUCTION = `위 내용은 선생님이 학생에게 나눠준 수행평가·탐구활동 안내문이야. 학생이 이 안내문에 맞는 탐구를 설계할 수 있게, 안내문에 적힌 요구사항을 빠짐없이 정리해줘.

규칙:
- 안내문에 실제로 적힌 것만 정리해. 없는 조건을 지어내지 마. 없으면 비워둬.
- 요구 항목(ITEMS)이 제일 중요해. 결과물에 들어가야 하는 칸을 하나씩 뽑아. 다음은 전부 요구 항목이야:
  · 제출 양식의 칸(예: 제목 / 주제를 선택한 동기 / 과학적 원리 / 결론 / 참고 자료 출처)
  · 채점 요소·평가 요소·평가 기준 표의 각 줄(예: 1) 제목을 주제와 관련지어 명확히 표현 → 항목 이름은 제목)
  · 목차·구성·반드시 포함할 내용
  양식의 칸과 채점 요소가 둘 다 있으면 양식의 칸을 항목으로 삼고, 해당 채점 요소의 내용을 그 항목의 "기대하는 것"에 녹여. 기한 준수처럼 결과물의 칸이 아닌 조건은 NOTES로 보내.
  안내문이 양식이나 채점표 없이 과제만 설명하면, 그 설명에서 결과물에 들어가야 할 것을 뽑아 항목으로 만들어. 정말 아무것도 없을 때만 비워둬.
- 항목마다 선생님이 거기서 무엇을 보려는지 1문장. 채점표 문구가 있으면 그 말을 써.
- 출처 표기 방식, AI 출처 불인정, 교과서 내용만 베끼면 안 됨 같은 조건은 NOTES에 꼭 넣어.
- 존댓말(해요체)로, 학생에게 설명하듯 자연스럽게.

절대로 다른 설명 없이, 아래 형식으로만 정확히 응답해. 문장 안에 큰따옴표(")는 쓰지 마.

TYPE: 주제탐구 / 실험 / 독서 / 발표 / 창작물 / 토론 / 기타 중 하나
TITLE: 과제 이름과 과목 (예: 생명과학Ⅰ 효소 탐구 보고서)
LENGTH: 분량 (예: A4 2장, 1500자 내외, 발표 5분). 없으면 비워둬
FORMAT: 제출 형식 (예: 보고서, PPT 10장 이내, 구두 발표, 손글씨). 없으면 비워둬
DUE: 제출 기한. 없으면 비워둬
CRITERIA: 평가 기준이나 배점을 | 로 구분. 없으면 비워둬
ITEMS: 항목이름::선생님이 이 항목에서 기대하는 것 형태로, | 로 구분
NOTES: 그 밖에 꼭 지켜야 하는 조건 1~3개를 | 로 구분 (금지 사항, 참고문헌 표기, 감점 조건 등). 없으면 비워둬
TEXT: 사진이나 PDF로 받았을 때만, 안내문의 핵심 내용을 원문에 가깝게 1500자 안으로 옮겨 적어. 글자로 받은 경우는 비워둬`;

function briefField(text, label, next) {
  const re = new RegExp(label + ":[ \\t]*([\\s\\S]*?)(?=\\n(?:" + next.join("|") + "):|$)", "i");
  const m = text.match(re);
  return m ? m[1].trim() : "";
}
function parseBrief(rawText) {
  // 모델이 **TYPE:** 처럼 굵게 쓰거나 줄머리 기호를 붙여도 읽히게 정리한다
  const text = String(rawText || "")
    .replace(/\*\*/g, "").replace(/`/g, "")
    .replace(/^\s*[-•·]\s*(?=[A-Z]{3,}:)/gm, "")
    .replace(/^\s*#+\s*/gm, "");
  const labels = ["TYPE", "TITLE", "LENGTH", "FORMAT", "DUE", "CRITERIA", "ITEMS", "NOTES", "TEXT"];
  const get = l => briefField(text, l, labels.filter(x => x !== l));
  const split = v => v.split("|").map(x => x.trim()).filter(Boolean);
  return {
    type: get("TYPE").replace(/[^가-힣]/g, "").slice(0, 10),
    title: get("TITLE"),
    length: get("LENGTH"),
    format: get("FORMAT"),
    due: get("DUE"),
    criteria: split(get("CRITERIA")),
    items: get("ITEMS").split(/\||\n/).map(x => x.trim().replace(/^[-•·\d.)\s]+/, "")).filter(Boolean)
      .map(c => { const p = c.split("::"); return { name: (p[0] || "").trim().slice(0, 60), expect: (p[1] || "").trim() }; }).filter(i => i.name),
    notes: split(get("NOTES")),
    text: get("TEXT").slice(0, 2000),
  };
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
