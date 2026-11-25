import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const rootDir = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const htmlPath = path.join(rootDir, 'index.html');
const sqlPath = path.join(rootDir, 'supabase', 'phase2_schema_rls.sql');
const dbJsonPath = path.join(rootDir, 'db.json');

const html = fs.readFileSync(htmlPath, 'utf8');
const sql = fs.readFileSync(sqlPath, 'utf8');
const dbJson = fs.readFileSync(dbJsonPath, 'utf8');

// ============================================================================
// 1. 无硬编码敏感词扫描
// ============================================================================
const forbiddenPatterns = [
  /stsfiyzfyfwpbqjkrwbl/i,
  /eyJhbGciOiJIUzI1NiIs/i,
  /13590174063/,
  /13928405270/,
  /syncKey/i,
  /cGhpUDcx/,
  /sb_publishable_[A-Za-z0-9_-]{12,}/,
  /sb_secret_[A-Za-z0-9_-]{8,}/
];

for (const [name, content] of [
  ['index.html', html],
  ['supabase/phase2_schema_rls.sql', sql],
  ['db.json', dbJson]
]) {
  for (const pat of forbiddenPatterns) {
    assert.equal(pat.test(content), false, `检测到敏感词泄露：${name} 匹配了 ${pat}`);
  }
}
assert.equal(/\/rest\/v1\/store/.test(html), false, 'index.html 不应再直接读写旧版整库 store 接口');
console.log('✓ 1. 全仓库敏感词与废除整库覆盖检查通过');

// ============================================================================
// 2. SQL 规范化表结构与 RLS 策略完整性校验
// ============================================================================
const requiredTables = [
  'profiles',
  'app_sessions',
  'buildings',
  'manager_assignments',
  'rooms',
  'contracts',
  'bills',
  'meter_readings',
  'repairs',
  'ledger_entries'
];

for (const tbl of requiredTables) {
  assert.match(sql, new RegExp(`CREATE TABLE IF NOT EXISTS public\\.${tbl}\\b`), `缺少表定义：${tbl}`);
  assert.match(sql, new RegExp(`ALTER TABLE public\\.${tbl}\\s+ENABLE ROW LEVEL SECURITY`), `未开启 RLS：${tbl}`);
}

for (const fn of [
  'current_profile_id',
  'current_profile_role',
  'is_landlord',
  'is_active_manager',
  'can_access_building',
  'gfb_login_phone',
  'gfb_whoami',
  'gfb_logout',
  'gfb_migrate_legacy_json',
  'gfb_migrate_from_store_table'
]) {
  assert.match(sql, new RegExp(`CREATE OR REPLACE FUNCTION public\\.${fn}\\b`), `缺少关键函数：${fn}`);
}

assert.match(sql, /REVOKE ALL ON public\.profiles FROM anon, authenticated;/, '必须撤销 profiles 默认全列权限以保护 pin_hash');
assert.match(sql, /REVOKE ALL ON public\.app_sessions FROM anon, authenticated;/, '必须禁止客户端直接访问 app_sessions');
assert.match(sql, /trg_contracts_sync_building/, '缺少 contracts 防跨楼栋伪造触发器');
assert.match(sql, /trg_bills_sync_building/, '缺少 bills 防跨楼栋伪造触发器');
assert.match(sql, /trg_meter_readings_sync_building/, '缺少 meter_readings 防跨楼栋伪造触发器');
console.log('✓ 2. SQL 规范化 7 张核心表及 RLS/防伪造触发器检查通过');

// ============================================================================
// 3. 构建带内存 RLS 模拟后端的前端执行沙箱
// ============================================================================
const scriptMatch = html.match(/<script>([\s\S]*?)<\/script>/);
assert.ok(scriptMatch, 'index.html 中未找到 <script> 标签');

function createHarness() {
  const elements = {};
  function makeEl(id, init = {}) {
    const el = {
      id,
      value: '',
      innerText: '',
      innerHTML: '',
      checked: false,
      style: {},
      classList: { add() {}, remove() {} },
      ...init
    };
    elements[id] = el;
    return el;
  }

  [
    'role-tag', 'sync-status', 'st-total', 'st-vacant', 'st-expiring', 'st-due',
    'msg-list', 'tab-stats', 'cur-user-title', 'cur-user-phone', 'logout-btn',
    'manager-admin-panel', 'backup-section', 'migration-section', 'cloud-config-section',
    'cloud-config-status', 'cfg-sp-url', 'cfg-sp-key', 'restrict-mgr-chk',
    'managers-list-box', 'lv3-modal', 'lv3-tabs', 'lv3-title', 'lv3-body',
    'action-sheet', 'action-title-text', 'action-body', 'module-modal',
    'modal-title', 'modal-body'
  ].forEach(id => makeEl(id));

  const storage = new Map();
  const alerts = [];
  const fetchCalls = [];

  // 内存数据库（模拟 PostgreSQL + RLS 权限隔离引擎）
  const serverDB = {
    profiles: [
      { id: 'prof-boss', phone: '13800001111', display_name: '主房东', role: 'landlord', restrict_manager: true, is_active: true, pin: '123456' },
      { id: 'prof-mgr1', phone: '13900002222', display_name: '管家A', role: 'manager', restrict_manager: false, is_active: true, pin: '654321' }
    ],
    sessions: new Map([
      ['tok-boss', 'prof-boss'],
      ['tok-mgr1', 'prof-mgr1']
    ]),
    buildings: [
      { id: 'bldg-A', name: 'A栋' },
      { id: 'bldg-B', name: 'B栋' }
    ],
    manager_assignments: [
      { id: 'ma-1', manager_id: 'prof-mgr1', building_id: 'bldg-A' }
    ],
    rooms: [
      { id: 'rm-A101', building_id: 'bldg-A', name: '101', rent: 1000, water_price: 5, elec_price: 1.2, last_water: 0, last_elec: 0, status: 'rented', version: 1 },
      { id: 'rm-B201', building_id: 'bldg-B', name: '201', rent: 1500, water_price: 5, elec_price: 1, last_water: 10, last_elec: 20, status: 'vacant', version: 1 }
    ],
    contracts: [
      { id: 'ct-A101', building_id: 'bldg-A', room_id: 'rm-A101', contract_no: '20261101001', tenant_name: '张三', tenant_phone: '13700003333', id_card: '440301199001011234', id_addr: '深圳市南山区隐私地址', start_date: '2026-11-01', end_date: '2027-11-01', rent: 1000, deposit: 1000, status: 'active', extra_fees: [{ name: '网费', amt: 50 }] }
    ],
    bills: [
      { id: 'bl-A1', building_id: 'bldg-A', room_id: 'rm-A101', contract_id: 'ct-A101', room_name: 'A栋 - 101', tenant_name: '张三', tenant_phone: '13700003333', bill_month: '2026-11', bill_date: '2026-11-01', period: '2026-11-01 至 2026-11-30', rent: 1000, deposit: 0, extra_fee: 50, last_water: 0, cur_water: null, use_water: 0, water_price: 5, water_fee: 0, last_elec: 0, cur_elec: null, use_elec: 0, elec_price: 1.2, elec_fee: 0, total: 1050, paid_amount: 0, status: 'unmetered' },
      { id: 'bl-B1', building_id: 'bldg-B', room_id: 'rm-B201', contract_id: null, room_name: 'B栋 - 201', tenant_name: '王五', tenant_phone: '13600004444', bill_month: '2026-11', bill_date: '2026-11-01', period: '2026-11-01 至 2026-11-30', rent: 1500, deposit: 0, extra_fee: 0, total: 1500, status: 'unpaid' }
    ],
    meter_readings: [],
    repairs: [],
    ledger_entries: [
      { id: 'ld-1', building_id: 'bldg-B', entry_type: 'in', title: '[收租] B栋 - 201', amount: 1500, entry_date: '2026-11-01' }
    ]
  };

  function getCaller(headers) {
    const tok = headers['x-gfb-session'];
    if (!tok) return null;
    const pid = serverDB.sessions.get(tok);
    return serverDB.profiles.find(p => p.id === pid) || null;
  }

  function canAccessBldg(caller, bldgId) {
    if (!caller) return false;
    if (caller.role === 'landlord') return true;
    return serverDB.manager_assignments.some(a => a.manager_id === caller.id && a.building_id === bldgId);
  }

  function isRestricted() {
    return serverDB.profiles.some(p => p.role === 'landlord' && p.restrict_manager);
  }

  async function mockFetch(url, opts = {}) {
    const method = opts.method || 'GET';
    const headers = opts.headers || {};
    const body = opts.body ? JSON.parse(opts.body) : undefined;
    fetchCalls.push({ url, method, headers, body });

    // 强制校验 sb_publishable_ 绝不出现在 Authorization 头
    if (headers['Authorization'] && headers['Authorization'].includes('sb_publishable_')) {
      return {
        ok: false,
        status: 401,
        text: async () => JSON.stringify({ message: 'Invalid JWT: publishable key cannot be in Authorization header' })
      };
    }

    const caller = getCaller(headers);
    const u = new URL(url);
    const restPath = u.pathname.replace(/^\/rest\/v1\//, '');
    const jsonResp = (data, status = 200) => ({
      ok: status >= 200 && status < 300,
      status,
      text: async () => JSON.stringify(data)
    });

    // RPC 路由
    if (restPath === 'rpc/gfb_login_phone') {
      const prof = serverDB.profiles.find(p => p.phone === body.p_phone);
      if (!prof || prof.pin !== body.p_pin) {
        return jsonResp({ ok: false, message: '手机号或安全口令错误' });
      }
      const tok = prof.role === 'landlord' ? 'tok-boss' : 'tok-mgr1';
      return jsonResp({
        ok: true,
        is_bootstrap: false,
        session_token: tok,
        profile: { id: prof.id, phone: prof.phone, display_name: prof.display_name, role: prof.role, restrict_manager: isRestricted() }
      });
    }

    if (restPath === 'rpc/gfb_whoami') {
      if (!caller) return jsonResp({ authenticated: false, profile: null });
      return jsonResp({
        authenticated: true,
        profile: { id: caller.id, phone: caller.phone, display_name: caller.display_name, role: caller.role, restrict_manager: isRestricted() }
      });
    }

    if (restPath === 'rpc/gfb_logout') {
      return jsonResp({ ok: true });
    }

    if (restPath === 'rpc/gfb_migrate_from_store_table') {
      if (!caller || caller.role !== 'landlord') {
        return jsonResp({ message: '权限不足：仅主房东可执行旧库迁移' }, 403);
      }
      return jsonResp({ ok: true, buildings: 2, rooms: 3, contracts: 1, bills: 1, meter_readings: 1, managers: 1 });
    }

    if (restPath === 'rpc/gfb_migrate_legacy_json') {
      if (!caller || caller.role !== 'landlord') {
        return jsonResp({ message: '权限不足：仅主房东可执行老数据迁移' }, 403);
      }
      return jsonResp({
        ok: true,
        buildings: 1,
        rooms: (body.p_payload.rooms || []).length,
        contracts: 1,
        bills: (body.p_payload.bills || []).length,
        meter_readings: 1,
        managers: (body.p_payload.managers || []).length
      });
    }

    // 业务表 REST 路由（强制执行 RLS）
    const idParam = u.searchParams.get('id');
    const targetId = idParam ? idParam.replace(/^eq\./, '') : null;

    if (restPath === 'buildings') {
      if (method === 'GET') {
        const nameParam = u.searchParams.get('name');
        let rows = serverDB.buildings.filter(b => canAccessBldg(caller, b.id));
        if (nameParam) rows = rows.filter(b => b.name === nameParam.replace(/^eq\./, ''));
        return jsonResp(rows);
      }
      if (method === 'POST') {
        if (!caller || caller.role !== 'landlord') return jsonResp({ message: 'RLS 拒绝：仅主房东可新建楼栋' }, 403);
        const created = { id: 'bldg-' + (serverDB.buildings.length + 1), ...body };
        serverDB.buildings.push(created);
        return jsonResp([created], 201);
      }
    }

    if (restPath === 'rooms') {
      if (method === 'GET') return jsonResp(serverDB.rooms.filter(r => canAccessBldg(caller, r.building_id)));
      if (method === 'POST') {
        const list = Array.isArray(body) ? body : [body];
        for (const item of list) {
          if (!canAccessBldg(caller, item.building_id) || (caller.role === 'manager' && isRestricted())) {
            return jsonResp({ message: 'RLS 拒绝：无权在此楼栋添加房间' }, 403);
          }
        }
        const inserted = list.map((item, idx) => ({ id: 'rm-new-' + idx, version: 1, ...item }));
        serverDB.rooms.push(...inserted);
        return jsonResp(inserted, 201);
      }
      if (method === 'PATCH') {
        const rm = serverDB.rooms.find(r => r.id === targetId);
        if (!rm || !canAccessBldg(caller, rm.building_id)) return jsonResp({ message: 'RLS 拒绝：无权修改未分配楼栋房间' }, 403);
        Object.assign(rm, body);
        return jsonResp([rm]);
      }
      if (method === 'DELETE') {
        const rm = serverDB.rooms.find(r => r.id === targetId);
        if (!rm || !canAccessBldg(caller, rm.building_id) || (caller.role === 'manager' && isRestricted())) {
          return jsonResp({ message: 'RLS 拒绝：无权删除房间' }, 403);
        }
        serverDB.rooms = serverDB.rooms.filter(r => r.id !== targetId);
        return jsonResp([], 204);
      }
    }

    if (restPath === 'contracts') {
      if (method === 'GET') return jsonResp(serverDB.contracts.filter(c => canAccessBldg(caller, c.building_id)));
      if (method === 'POST') {
        if (!canAccessBldg(caller, body.building_id)) return jsonResp({ message: 'RLS 拒绝' }, 403);
        const ct = { id: 'ct-new', ...body };
        serverDB.contracts.push(ct);
        return jsonResp([ct], 201);
      }
      if (method === 'PATCH') {
        const ct = serverDB.contracts.find(c => c.id === targetId);
        if (!ct || !canAccessBldg(caller, ct.building_id)) return jsonResp({ message: 'RLS 拒绝' }, 403);
        Object.assign(ct, body);
        return jsonResp([ct]);
      }
    }

    if (restPath === 'bills') {
      if (method === 'GET') return jsonResp(serverDB.bills.filter(b => canAccessBldg(caller, b.building_id)));
      if (method === 'POST') {
        const list = Array.isArray(body) ? body : [body];
        for (const item of list) {
          if (!canAccessBldg(caller, item.building_id)) return jsonResp({ message: 'RLS 拒绝' }, 403);
        }
        const inserted = list.map((item, idx) => ({ id: 'bl-new-' + idx, ...item }));
        serverDB.bills.push(...inserted);
        return jsonResp(inserted, 201);
      }
      if (method === 'PATCH') {
        const bl = serverDB.bills.find(b => b.id === targetId);
        if (!bl || !canAccessBldg(caller, bl.building_id)) return jsonResp({ message: 'RLS 拒绝' }, 403);
        Object.assign(bl, body);
        return jsonResp([bl]);
      }
    }

    if (restPath === 'meter_readings') {
      if (method === 'GET') return jsonResp(serverDB.meter_readings.filter(m => canAccessBldg(caller, m.building_id)));
      if (method === 'POST') {
        const list = Array.isArray(body) ? body : [body];
        for (const item of list) {
          if (!canAccessBldg(caller, item.building_id)) return jsonResp({ message: 'RLS 拒绝' }, 403);
        }
        serverDB.meter_readings.push(...list);
        return jsonResp(list, 201);
      }
    }

    if (restPath === 'repairs') {
      if (method === 'GET') return jsonResp(serverDB.repairs.filter(r => canAccessBldg(caller, r.building_id)));
      if (method === 'POST') {
        if (!canAccessBldg(caller, body.building_id)) return jsonResp({ message: 'RLS 拒绝' }, 403);
        const rp = { id: 'rp-new', ...body };
        serverDB.repairs.push(rp);
        return jsonResp([rp], 201);
      }
    }

    if (restPath === 'ledger_entries') {
      if (method === 'GET') {
        if (!caller) return jsonResp([]);
        if (caller.role === 'landlord') return jsonResp(serverDB.ledger_entries);
        if (isRestricted()) return jsonResp([]);
        return jsonResp(serverDB.ledger_entries.filter(l => canAccessBldg(caller, l.building_id)));
      }
      if (method === 'POST') {
        if (!caller) return jsonResp({ message: 'RLS 拒绝' }, 403);
        if (caller.role !== 'landlord' && !(body.entry_type === 'in' && canAccessBldg(caller, body.building_id))) {
          return jsonResp({ message: 'RLS 拒绝：管房员无权写入支出流水' }, 403);
        }
        serverDB.ledger_entries.push(body);
        return jsonResp([body], 201);
      }
    }

    if (restPath === 'profiles') {
      if (method === 'GET') {
        if (!caller) return jsonResp([]);
        const rows = caller.role === 'landlord' ? serverDB.profiles : serverDB.profiles.filter(p => p.id === caller.id);
        return jsonResp(rows.map(({ pin, ...safe }) => safe));
      }
      if (method === 'POST') {
        if (!caller || caller.role !== 'landlord') return jsonResp({ message: 'RLS 拒绝' }, 403);
        const created = { id: 'prof-new', ...body };
        serverDB.profiles.push(created);
        return jsonResp([created], 201);
      }
      if (method === 'PATCH') {
        if (!caller || caller.role !== 'landlord') return jsonResp({ message: 'RLS 拒绝' }, 403);
        const target = serverDB.profiles.find(p => p.id === targetId);
        Object.assign(target, body);
        return jsonResp([target]);
      }
    }

    if (restPath === 'manager_assignments') {
      if (method === 'GET') {
        if (!caller) return jsonResp([]);
        return jsonResp(caller.role === 'landlord' ? serverDB.manager_assignments : serverDB.manager_assignments.filter(a => a.manager_id === caller.id));
      }
      if (method === 'POST') {
        if (!caller || caller.role !== 'landlord') return jsonResp({ message: 'RLS 拒绝' }, 403);
        const list = Array.isArray(body) ? body : [body];
        serverDB.manager_assignments.push(...list.map((a, i) => ({ id: 'ma-new-' + i, ...a })));
        return jsonResp(list, 201);
      }
      if (method === 'DELETE') {
        if (!caller || caller.role !== 'landlord') return jsonResp({ message: 'RLS 拒绝' }, 403);
        const mgrId = u.searchParams.get('manager_id')?.replace(/^eq\./, '');
        const bId = u.searchParams.get('building_id')?.replace(/^eq\./, '');
        serverDB.manager_assignments = serverDB.manager_assignments.filter(a => !(a.manager_id === mgrId && a.building_id === bId));
        return jsonResp([], 204);
      }
    }

    return jsonResp({ message: `Unhandled mock route: ${method} ${restPath}` }, 404);
  }

  const sandbox = {
    window: { location: { href: 'https://example.test/guanfangbao/' } },
    localStorage: {
      getItem: k => (storage.has(k) ? storage.get(k) : null),
      setItem: (k, v) => storage.set(k, String(v)),
      removeItem: k => storage.delete(k)
    },
    document: {
      activeElement: null,
      getElementById: id => elements[id] || makeEl(id),
      querySelectorAll: sel => {
        if (sel === '.assign-bldg-chk:checked') return elements.__checkedAssign || [];
        return [];
      }
    },
    alert: msg => alerts.push(msg),
    confirm: () => true,
    prompt: () => null,
    fetch: mockFetch,
    URL,
    Blob,
    console
  };

  vm.createContext(sandbox);
  vm.runInContext(scriptMatch[1], sandbox);

  return {
    sandbox,
    elements,
    storage,
    alerts,
    fetchCalls,
    serverDB,
    evalIn: expr => vm.runInContext(expr, sandbox)
  };
}

// ============================================================================
// 4. 测试 sb_publishable_ 请求头兼容性（绝不发送 Authorization: Bearer sb_publishable_）
// ============================================================================
{
  const h = createHarness();
  h.storage.set('FDZY_SP_URL', 'https://demo.supabase.co');
  h.storage.set('FDZY_SP_KEY', 'sb_publishable_demo_opaque_key');
  h.storage.set('FDZY_SESSION_TOKEN_V2', 'tok-boss');

  const headers = h.sandbox.buildSupabaseHeaders();
  assert.equal(headers.apikey, 'sb_publishable_demo_opaque_key');
  assert.equal(headers['x-gfb-session'], 'tok-boss');
  assert.equal('Authorization' in headers, false, 'sb_publishable_ 密钥不得出现在 Authorization 头中');

  // 兼容旧版 3 段式 eyJ JWT
  h.storage.set('FDZY_SP_KEY', 'eyJhbGci.eyJyb2xlIjoiYW5vbiJ9.sig');
  const legacyHeaders = h.sandbox.buildSupabaseHeaders();
  assert.equal(legacyHeaders.Authorization, 'Bearer eyJhbGci.eyJyb2xlIjoiYW5vbiJ9.sig');
  console.log('✓ 3. sb_publishable_ 可发布密钥与旧版 JWT 请求头兼容性验证通过');
}

// ============================================================================
// 5. 测试管房员登录与数据库 RLS 权限隔离（仅可见分配楼栋 A，不可见楼栋 B 与总账）
// ============================================================================
{
  const h = createHarness();
  h.storage.set('FDZY_SP_URL', 'https://demo.supabase.co');
  h.storage.set('FDZY_SP_KEY', 'sb_publishable_demo_opaque_key');

  h.sandbox.openLoginSheet();
  h.elements['login-phone'] = { value: '13900002222' };
  h.elements['login-pin'] = { value: '654321' };
  await h.sandbox.submitLoginPhone();

  assert.equal(h.sandbox.isBoss(), false, '管房员不应判定为老板');
  const mgrRooms = h.evalIn('db.rooms');
  const mgrBills = h.evalIn('db.bills');
  const mgrLedger = h.evalIn('db.ledger');
  assert.equal(mgrRooms.length, 1, '管房员应仅能看到已分配的 A栋 房间');
  assert.equal(mgrRooms[0].building, 'A栋');
  assert.equal(mgrBills.length, 1, '管房员应仅能看到已分配的 A栋 账单');
  assert.equal(mgrLedger.length, 0, '受限管房员在数据库 RLS 下应无法读取总账流水');
  assert.equal(h.elements['manager-admin-panel'].style.display, 'none', '管房员应隐藏管理员面板');
  assert.equal(h.elements['migration-section'].style.display, 'none', '管房员应隐藏老数据迁移入口');
  assert.equal(h.elements['backup-section'].style.display, 'none', '管房员应隐藏全量备份区');

  // 管房员查看租客详情：身份证号脱敏且地址不可见
  h.sandbox.openTenantDetail(0);
  assert.equal(h.elements['action-body'].innerHTML.includes('440301199001011234'), false);
  assert.equal(h.elements['action-body'].innerHTML.includes('深圳市南山区隐私地址'), false);
  assert.equal(h.elements['action-body'].innerHTML.includes('4403**********1234'), true);
  assert.equal(h.elements['action-body'].innerHTML.includes('仅主房东可见'), true);

  // 管房员抄表（水电底数为 0 场景）+ 增量写入验证
  h.fetchCalls.length = 0;
  h.sandbox.openMeterForm(0);
  h.elements['am-rent'] = { value: '1000' };
  h.elements['am-dep'] = { value: '0' };
  h.elements['am-w'] = { value: '10' };
  h.elements['am-e'] = { value: '100' };
  await h.sandbox.saveMeterForm(0, true);

  // 验证增量调用了 bills PATCH, meter_readings POST, rooms PATCH, ledger_entries POST
  const methodsAndPaths = h.fetchCalls.map(c => `${c.method} ${new URL(c.url).pathname}`);
  assert.ok(methodsAndPaths.some(x => x === 'PATCH /rest/v1/bills'), '应增量 PATCH bills 表');
  assert.ok(methodsAndPaths.some(x => x === 'POST /rest/v1/meter_readings'), '应增量写入 meter_readings 表');
  assert.ok(methodsAndPaths.some(x => x === 'PATCH /rest/v1/rooms'), '应增量 PATCH rooms 底数');
  assert.ok(methodsAndPaths.some(x => x === 'POST /rest/v1/ledger_entries'), '收款后应写入收入流水');
  assert.equal(methodsAndPaths.some(x => x.includes('/store')), false, '绝不应写回旧 store 表');

  // 验证 0 底数水电计算结果：10*5=50水 + 100*1.2=120电 + 1000租 + 50杂费 = 1220
  assert.equal(h.serverDB.bills[0].use_water, 10);
  assert.equal(h.serverDB.bills[0].water_fee, 50);
  assert.equal(h.serverDB.bills[0].use_elec, 100);
  assert.equal(h.serverDB.bills[0].elec_fee, 120);
  assert.equal(h.serverDB.bills[0].total, 1220);
  assert.equal(h.serverDB.rooms[0].last_water, 10);
  assert.equal(h.serverDB.rooms[0].last_elec, 100);
  assert.equal(h.serverDB.meter_readings.length, 1);

  // 管房员越权尝试直接修改 B栋 房间：数据库 RLS 拦截返回 403
  await assert.rejects(
    () => h.sandbox.sbRequest('rooms?id=eq.rm-B201', { method: 'PATCH', body: { rent: 1 } }),
    err => err.status === 403
  );
  console.log('✓ 4. 管房员 RLS 楼栋隔离、0底数增量抄表与越权拦截测试通过');
}

// ============================================================================
// 6. 测试主房东全局读写、楼栋分配（manager_assignments）与老数据一键迁移
// ============================================================================
{
  const h = createHarness();
  h.storage.set('FDZY_SP_URL', 'https://demo.supabase.co');
  h.storage.set('FDZY_SP_KEY', 'sb_publishable_demo_opaque_key');

  h.sandbox.openLoginSheet();
  h.elements['login-phone'] = { value: '13800001111' };
  h.elements['login-pin'] = { value: '123456' };
  await h.sandbox.submitLoginPhone();

  assert.equal(h.sandbox.isBoss(), true, '主房东应拥有老板角色');
  assert.equal(h.evalIn('db.rooms').length, 2, '主房东应能看到 A栋 与 B栋 全部房间');
  assert.equal(h.evalIn('db.bills').length, 2, '主房东应能看到全部账单');
  assert.equal(h.evalIn('db.ledger').length, 1, '主房东应能看到财务总账流水');
  assert.equal(h.elements['migration-section'].style.display, 'block', '主房东应看到老数据一键迁移面板');

  // 分配 B栋 给管家A（同时取消 A栋）
  h.elements.__checkedAssign = [{ value: 'bldg-B' }];
  h.fetchCalls.length = 0;
  await h.sandbox.saveManagerAssignments('prof-mgr1');
  assert.equal(h.serverDB.manager_assignments.length, 1);
  assert.equal(h.serverDB.manager_assignments[0].building_id, 'bldg-B');

  // 一键迁移老数据
  h.fetchCalls.length = 0;
  await h.sandbox.migrateLegacyData();
  assert.ok(h.fetchCalls.some(c => c.url.includes('/rest/v1/rpc/gfb_migrate_from_store_table')), '应调用老数据迁移 RPC');
  assert.ok(h.alerts.some(msg => msg.includes('老数据迁移完成')), '应向房东展示迁移结果汇总');
  console.log('✓ 5. 主房东全局权限、管房员楼栋分配与老数据一键迁移测试通过');
}

console.log('\n🎉 第二阶段全部自动化单元测试通过！');
