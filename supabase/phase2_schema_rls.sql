-- ============================================================================
-- 观芳宝（guanfangbao）第二阶段数据库升级脚本
-- 内容：规范化关系表拆分 + 行级安全策略（RLS）+ 手机号会话校验 + 老数据无损迁移 RPC
-- 适用环境：Supabase PostgreSQL 15+
-- 兼容特性：完全兼容 SUPABASE_URL + 新版 sb_publishable_ 可发布密钥及旧版 anon JWT
-- ============================================================================

BEGIN;

-- 1. 启用加密扩展（Supabase 默认安装在 extensions 模式，兼容 public 模式）
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================================
-- 2. 规范化核心业务表定义（共 7 张核心表 + 报修/流水/会话辅助表）
-- ============================================================================

-- 2.1 账号与角色表（profiles）
CREATE TABLE IF NOT EXISTS public.profiles (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  auth_user_id     uuid UNIQUE,
  phone            text NOT NULL UNIQUE,
  display_name     text NOT NULL DEFAULT '',
  role             text NOT NULL CHECK (role IN ('landlord', 'manager')),
  pin_hash         text,
  restrict_manager boolean NOT NULL DEFAULT false,
  is_active        boolean NOT NULL DEFAULT true,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now()
);

-- 2.2 内部登录会话表（app_sessions，严格禁止前端直接读写，仅限 SECURITY DEFINER RPC 操作）
CREATE TABLE IF NOT EXISTS public.app_sessions (
  token_hash text PRIMARY KEY,
  profile_id uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_app_sessions_profile_id ON public.app_sessions(profile_id);
CREATE INDEX IF NOT EXISTS idx_app_sessions_expires_at ON public.app_sessions(expires_at);

-- 2.3 楼栋表（buildings）
CREATE TABLE IF NOT EXISTS public.buildings (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name                text NOT NULL UNIQUE,
  address             text NOT NULL DEFAULT '',
  default_rent        numeric(12,2) NOT NULL DEFAULT 1000,
  default_water_price numeric(10,2) NOT NULL DEFAULT 5,
  default_elec_price  numeric(10,2) NOT NULL DEFAULT 1,
  remark              text NOT NULL DEFAULT '',
  created_by          uuid REFERENCES public.profiles(id) ON DELETE SET NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now()
);

-- 2.4 管房员楼栋分配表（manager_assignments）
CREATE TABLE IF NOT EXISTS public.manager_assignments (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  manager_id  uuid NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
  building_id uuid NOT NULL REFERENCES public.buildings(id) ON DELETE CASCADE,
  assigned_by uuid REFERENCES public.profiles(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  UNIQUE (manager_id, building_id)
);
CREATE INDEX IF NOT EXISTS idx_manager_assignments_manager ON public.manager_assignments(manager_id);
CREATE INDEX IF NOT EXISTS idx_manager_assignments_building ON public.manager_assignments(building_id);

-- 2.5 房间表（rooms）
CREATE TABLE IF NOT EXISTS public.rooms (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  legacy_id     text UNIQUE,
  building_id   uuid NOT NULL REFERENCES public.buildings(id) ON DELETE CASCADE,
  name          text NOT NULL,
  floor         integer,
  house_type    text NOT NULL DEFAULT '',
  rent          numeric(12,2) NOT NULL DEFAULT 1000,
  water_price   numeric(10,2) NOT NULL DEFAULT 5,
  elec_price    numeric(10,2) NOT NULL DEFAULT 1,
  last_water    numeric(12,2) NOT NULL DEFAULT 0,
  last_elec     numeric(12,2) NOT NULL DEFAULT 0,
  status        text NOT NULL DEFAULT 'vacant' CHECK (status IN ('vacant', 'rented')),
  vacant_since  date,
  plan_checkout date,
  version       integer NOT NULL DEFAULT 1,
  updated_by    uuid REFERENCES public.profiles(id) ON DELETE SET NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (building_id, name)
);
CREATE INDEX IF NOT EXISTS idx_rooms_building_id ON public.rooms(building_id);
CREATE INDEX IF NOT EXISTS idx_rooms_status ON public.rooms(status);

-- 2.6 租约表（contracts）
CREATE TABLE IF NOT EXISTS public.contracts (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  legacy_id     text UNIQUE,
  building_id   uuid NOT NULL REFERENCES public.buildings(id) ON DELETE CASCADE,
  room_id       uuid NOT NULL REFERENCES public.rooms(id) ON DELETE CASCADE,
  contract_no   text NOT NULL DEFAULT '',
  tenant_name   text NOT NULL,
  tenant_phone  text NOT NULL DEFAULT '',
  id_card       text NOT NULL DEFAULT '',
  id_addr       text NOT NULL DEFAULT '',
  start_date    date,
  end_date      date,
  sign_date     date,
  checkout_date date,
  cycle         text NOT NULL DEFAULT '月付 (每月收一次)',
  bill_mode     text NOT NULL DEFAULT '按起租日算',
  pay_day       text NOT NULL DEFAULT '账单开始前 当天',
  rent          numeric(12,2) NOT NULL DEFAULT 0,
  deposit       numeric(12,2) NOT NULL DEFAULT 0,
  water_price   numeric(10,2) NOT NULL DEFAULT 5,
  elec_price    numeric(10,2) NOT NULL DEFAULT 1,
  extra_fees    jsonb NOT NULL DEFAULT '[]'::jsonb,
  status        text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'checked_out', 'voided')),
  settle_note   text NOT NULL DEFAULT '',
  created_by    uuid REFERENCES public.profiles(id) ON DELETE SET NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_contracts_building_id ON public.contracts(building_id);
CREATE INDEX IF NOT EXISTS idx_contracts_room_id ON public.contracts(room_id);
CREATE INDEX IF NOT EXISTS idx_contracts_status ON public.contracts(status);

-- 2.7 账单表（bills）
CREATE TABLE IF NOT EXISTS public.bills (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  legacy_id    text UNIQUE,
  building_id  uuid NOT NULL REFERENCES public.buildings(id) ON DELETE CASCADE,
  room_id      uuid NOT NULL REFERENCES public.rooms(id) ON DELETE CASCADE,
  contract_id  uuid REFERENCES public.contracts(id) ON DELETE SET NULL,
  room_name    text NOT NULL DEFAULT '',
  tenant_name  text NOT NULL DEFAULT '',
  tenant_phone text NOT NULL DEFAULT '',
  bill_month   text NOT NULL DEFAULT '',
  bill_date    date,
  period       text NOT NULL DEFAULT '',
  rent         numeric(12,2) NOT NULL DEFAULT 0,
  deposit      numeric(12,2) NOT NULL DEFAULT 0,
  extra_fee    numeric(12,2) NOT NULL DEFAULT 0,
  last_water   numeric(12,2),
  cur_water    numeric(12,2),
  use_water    numeric(12,2) NOT NULL DEFAULT 0,
  water_price  numeric(10,2) NOT NULL DEFAULT 5,
  water_fee    numeric(12,2) NOT NULL DEFAULT 0,
  last_elec    numeric(12,2),
  cur_elec     numeric(12,2),
  use_elec     numeric(12,2) NOT NULL DEFAULT 0,
  elec_price   numeric(10,2) NOT NULL DEFAULT 1,
  elec_fee     numeric(12,2) NOT NULL DEFAULT 0,
  total        numeric(12,2) NOT NULL DEFAULT 0,
  paid_amount  numeric(12,2) NOT NULL DEFAULT 0,
  paid_at      timestamptz,
  detail       text NOT NULL DEFAULT '',
  status       text NOT NULL DEFAULT 'unmetered' CHECK (status IN ('unmetered', 'unpaid', 'paid')),
  updated_by   uuid REFERENCES public.profiles(id) ON DELETE SET NULL,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_bills_building_id ON public.bills(building_id);
CREATE INDEX IF NOT EXISTS idx_bills_room_id ON public.bills(room_id);
CREATE INDEX IF NOT EXISTS idx_bills_status ON public.bills(status);
CREATE INDEX IF NOT EXISTS idx_bills_bill_month ON public.bills(bill_month);

-- 2.8 水电抄表记录表（meter_readings）
CREATE TABLE IF NOT EXISTS public.meter_readings (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  legacy_id     text UNIQUE,
  building_id   uuid NOT NULL REFERENCES public.buildings(id) ON DELETE CASCADE,
  room_id       uuid NOT NULL REFERENCES public.rooms(id) ON DELETE CASCADE,
  bill_id       uuid REFERENCES public.bills(id) ON DELETE SET NULL,
  reading_month text NOT NULL DEFAULT '',
  reading_date  date NOT NULL DEFAULT CURRENT_DATE,
  prev_water    numeric(12,2) NOT NULL DEFAULT 0,
  curr_water    numeric(12,2),
  usage_water   numeric(12,2) NOT NULL DEFAULT 0,
  water_price   numeric(10,2) NOT NULL DEFAULT 5,
  water_fee     numeric(12,2) NOT NULL DEFAULT 0,
  prev_elec     numeric(12,2) NOT NULL DEFAULT 0,
  curr_elec     numeric(12,2),
  usage_elec    numeric(12,2) NOT NULL DEFAULT 0,
  elec_price    numeric(10,2) NOT NULL DEFAULT 1,
  elec_fee      numeric(12,2) NOT NULL DEFAULT 0,
  recorded_by   uuid REFERENCES public.profiles(id) ON DELETE SET NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_meter_readings_building_id ON public.meter_readings(building_id);
CREATE INDEX IF NOT EXISTS idx_meter_readings_room_id ON public.meter_readings(room_id);
CREATE INDEX IF NOT EXISTS idx_meter_readings_bill_id ON public.meter_readings(bill_id);

-- 2.9 报修工单表（repairs，按楼栋同步实施 RLS 隔离）
CREATE TABLE IF NOT EXISTS public.repairs (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  legacy_id   text UNIQUE,
  building_id uuid REFERENCES public.buildings(id) ON DELETE SET NULL,
  room_id     uuid REFERENCES public.rooms(id) ON DELETE SET NULL,
  room_name   text NOT NULL,
  repair_type text NOT NULL DEFAULT '水电',
  description text NOT NULL,
  status      text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'done')),
  report_date date NOT NULL DEFAULT CURRENT_DATE,
  created_by  uuid REFERENCES public.profiles(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_repairs_building_id ON public.repairs(building_id);
CREATE INDEX IF NOT EXISTS idx_repairs_status ON public.repairs(status);

-- 2.10 财务收支流水表（ledger_entries，保护老板财务总账隐私）
CREATE TABLE IF NOT EXISTS public.ledger_entries (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  legacy_id   text UNIQUE,
  building_id uuid REFERENCES public.buildings(id) ON DELETE SET NULL,
  bill_id     uuid REFERENCES public.bills(id) ON DELETE SET NULL,
  entry_type  text NOT NULL CHECK (entry_type IN ('in', 'out')),
  category    text NOT NULL DEFAULT '',
  title       text NOT NULL,
  amount      numeric(12,2) NOT NULL DEFAULT 0,
  entry_date  date NOT NULL DEFAULT CURRENT_DATE,
  created_by  uuid REFERENCES public.profiles(id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ledger_entries_building_id ON public.ledger_entries(building_id);
CREATE INDEX IF NOT EXISTS idx_ledger_entries_entry_date ON public.ledger_entries(entry_date DESC);

-- ============================================================================
-- 3. 通用触发器（自动维护 updated_at 与防伪造 building_id 同步）
-- ============================================================================

CREATE OR REPLACE FUNCTION public.gfb_touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END;
$$;

-- 强制 contracts / bills / meter_readings 的 building_id 与 room_id 所属楼栋保持一致，
-- 从数据库层杜绝跨楼栋引用伪造
CREATE OR REPLACE FUNCTION public.gfb_sync_building_from_room()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_bldg_id uuid;
BEGIN
  IF NEW.room_id IS NOT NULL THEN
    SELECT building_id INTO v_bldg_id FROM public.rooms WHERE id = NEW.room_id;
    IF v_bldg_id IS NULL THEN
      RAISE EXCEPTION '关联的房间不存在（room_id=%）', NEW.room_id;
    END IF;
    NEW.building_id := v_bldg_id;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_profiles_updated_at ON public.profiles;
CREATE TRIGGER trg_profiles_updated_at BEFORE UPDATE ON public.profiles
  FOR EACH ROW EXECUTE FUNCTION public.gfb_touch_updated_at();

DROP TRIGGER IF EXISTS trg_buildings_updated_at ON public.buildings;
CREATE TRIGGER trg_buildings_updated_at BEFORE UPDATE ON public.buildings
  FOR EACH ROW EXECUTE FUNCTION public.gfb_touch_updated_at();

DROP TRIGGER IF EXISTS trg_rooms_updated_at ON public.rooms;
CREATE TRIGGER trg_rooms_updated_at BEFORE UPDATE ON public.rooms
  FOR EACH ROW EXECUTE FUNCTION public.gfb_touch_updated_at();

DROP TRIGGER IF EXISTS trg_contracts_updated_at ON public.contracts;
CREATE TRIGGER trg_contracts_updated_at BEFORE UPDATE ON public.contracts
  FOR EACH ROW EXECUTE FUNCTION public.gfb_touch_updated_at();

DROP TRIGGER IF EXISTS trg_bills_updated_at ON public.bills;
CREATE TRIGGER trg_bills_updated_at BEFORE UPDATE ON public.bills
  FOR EACH ROW EXECUTE FUNCTION public.gfb_touch_updated_at();

DROP TRIGGER IF EXISTS trg_meter_readings_updated_at ON public.meter_readings;
CREATE TRIGGER trg_meter_readings_updated_at BEFORE UPDATE ON public.meter_readings
  FOR EACH ROW EXECUTE FUNCTION public.gfb_touch_updated_at();

DROP TRIGGER IF EXISTS trg_repairs_updated_at ON public.repairs;
CREATE TRIGGER trg_repairs_updated_at BEFORE UPDATE ON public.repairs
  FOR EACH ROW EXECUTE FUNCTION public.gfb_touch_updated_at();

DROP TRIGGER IF EXISTS trg_contracts_sync_building ON public.contracts;
CREATE TRIGGER trg_contracts_sync_building BEFORE INSERT OR UPDATE OF room_id, building_id ON public.contracts
  FOR EACH ROW EXECUTE FUNCTION public.gfb_sync_building_from_room();

DROP TRIGGER IF EXISTS trg_bills_sync_building ON public.bills;
CREATE TRIGGER trg_bills_sync_building BEFORE INSERT OR UPDATE OF room_id, building_id ON public.bills
  FOR EACH ROW EXECUTE FUNCTION public.gfb_sync_building_from_room();

DROP TRIGGER IF EXISTS trg_meter_readings_sync_building ON public.meter_readings;
CREATE TRIGGER trg_meter_readings_sync_building BEFORE INSERT OR UPDATE OF room_id, building_id ON public.meter_readings
  FOR EACH ROW EXECUTE FUNCTION public.gfb_sync_building_from_room();

-- ============================================================================
-- 4. 身份识别与权限判定辅助函数（供所有 RLS 策略调用）
--    双通道支持：1) Supabase Auth JWT (auth.uid())
--                2) 手机号登录会话头 x-gfb-session（完全兼容 sb_publishable_）
-- ============================================================================

CREATE OR REPLACE FUNCTION public.current_profile_id()
RETURNS uuid
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  v_uid           uuid;
  v_profile_id    uuid;
  v_headers       jsonb;
  v_session_token text;
  v_token_hash    text;
BEGIN
  -- 通道 1：优先识别 Supabase Auth JWT
  v_uid := auth.uid();
  IF v_uid IS NOT NULL THEN
    SELECT id INTO v_profile_id
    FROM public.profiles
    WHERE auth_user_id = v_uid AND is_active = true
    LIMIT 1;
    IF v_profile_id IS NOT NULL THEN
      RETURN v_profile_id;
    END IF;
  END IF;

  -- 通道 2：识别手机号登录签发的 256 位随机令牌（经由 x-gfb-session 请求头传入）
  BEGIN
    v_headers := COALESCE(current_setting('request.headers', true), '{}')::jsonb;
  EXCEPTION WHEN OTHERS THEN
    v_headers := '{}'::jsonb;
  END;

  v_session_token := NULLIF(trim(COALESCE(v_headers ->> 'x-gfb-session', '')), '');
  IF v_session_token IS NOT NULL THEN
    v_token_hash := encode(digest(convert_to(v_session_token, 'utf8'), 'sha256'), 'hex');
    SELECT s.profile_id INTO v_profile_id
    FROM public.app_sessions s
    JOIN public.profiles p ON p.id = s.profile_id
    WHERE s.token_hash = v_token_hash
      AND s.expires_at > now()
      AND p.is_active = true
    LIMIT 1;
    RETURN v_profile_id;
  END IF;

  RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION public.current_profile_role()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT role
  FROM public.profiles
  WHERE id = public.current_profile_id()
    AND is_active = true
  LIMIT 1;
$$;

CREATE OR REPLACE FUNCTION public.is_landlord()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT COALESCE(public.current_profile_role() = 'landlord', false);
$$;

CREATE OR REPLACE FUNCTION public.is_active_manager()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT COALESCE(public.current_profile_role() = 'manager', false);
$$;

CREATE OR REPLACE FUNCTION public.is_manager_restricted()
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT COALESCE(
    (SELECT bool_or(restrict_manager) FROM public.profiles WHERE role = 'landlord' AND is_active = true),
    false
  );
$$;

CREATE OR REPLACE FUNCTION public.can_access_building(p_building_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT public.is_landlord()
    OR (
      p_building_id IS NOT NULL
      AND public.is_active_manager()
      AND EXISTS (
        SELECT 1
        FROM public.manager_assignments ma
        WHERE ma.manager_id = public.current_profile_id()
          AND ma.building_id = p_building_id
      )
    );
$$;

-- ============================================================================
-- 5. 手机号身份校验与会话管理 RPC（SECURITY DEFINER）
-- ============================================================================

-- 5.1 手机号 + 口令（PIN）登录（首次无房东时自动初始化主房东账号）
CREATE OR REPLACE FUNCTION public.gfb_login_phone(
  p_phone        text,
  p_pin          text DEFAULT '',
  p_display_name text DEFAULT ''
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  v_phone         text := regexp_replace(trim(COALESCE(p_phone, '')), '\s+', '', 'g');
  v_pin           text := trim(COALESCE(p_pin, ''));
  v_name          text := trim(COALESCE(p_display_name, ''));
  v_landlord_cnt  integer;
  v_profile       public.profiles%ROWTYPE;
  v_raw_token     text;
  v_token_hash    text;
  v_is_bootstrap  boolean := false;
BEGIN
  IF length(v_phone) < 5 THEN
    RETURN jsonb_build_object('ok', false, 'message', '请输入有效的登录手机号');
  END IF;

  SELECT count(*) INTO v_landlord_cnt
  FROM public.profiles
  WHERE role = 'landlord' AND is_active = true;

  -- 场景 A：系统首次初始化，尚无主房东账号
  IF v_landlord_cnt = 0 THEN
    IF length(v_pin) < 4 THEN
      RETURN jsonb_build_object(
        'ok', false,
        'need_pin', true,
        'is_bootstrap', true,
        'message', '首次初始化主房东账号，请设置至少 4 位安全口令（PIN）'
      );
    END IF;

    INSERT INTO public.profiles (phone, display_name, role, pin_hash, restrict_manager, is_active)
    VALUES (
      v_phone,
      CASE WHEN v_name <> '' THEN v_name ELSE '主房东' END,
      'landlord',
      crypt(v_pin, gen_salt('bf')),
      false,
      true
    )
    ON CONFLICT (phone) DO UPDATE
      SET role = 'landlord',
          pin_hash = crypt(v_pin, gen_salt('bf')),
          is_active = true,
          updated_at = now()
    RETURNING * INTO v_profile;

    v_is_bootstrap := true;
  ELSE
    -- 场景 B：校验已有账号
    SELECT * INTO v_profile
    FROM public.profiles
    WHERE phone = v_phone AND is_active = true
    LIMIT 1;

    IF NOT FOUND THEN
      RETURN jsonb_build_object('ok', false, 'message', '该手机号未授权登录，请联系主房东在管房组中添加');
    END IF;

    IF v_profile.pin_hash IS NULL OR v_profile.pin_hash = '' THEN
      -- 管房员由房东刚添加、首次登录时自行设定安全口令
      IF length(v_pin) < 4 THEN
        RETURN jsonb_build_object(
          'ok', false,
          'need_pin', true,
          'is_first_pin', true,
          'message', '首次登录，请为该手机号设置至少 4 位安全口令（PIN）'
        );
      END IF;
      UPDATE public.profiles
      SET pin_hash = crypt(v_pin, gen_salt('bf')), updated_at = now()
      WHERE id = v_profile.id
      RETURNING * INTO v_profile;
    ELSE
      IF v_pin = '' THEN
        RETURN jsonb_build_object('ok', false, 'need_pin', true, 'message', '请输入安全口令（PIN）');
      END IF;
      IF crypt(v_pin, v_profile.pin_hash) <> v_profile.pin_hash THEN
        RETURN jsonb_build_object('ok', false, 'message', '手机号或安全口令错误');
      END IF;
    END IF;
  END IF;

  -- 签发 256 位随机令牌并仅在库中存 SHA-256 哈希，有效期 30 天
  v_raw_token  := encode(gen_random_bytes(32), 'hex');
  v_token_hash := encode(digest(convert_to(v_raw_token, 'utf8'), 'sha256'), 'hex');

  DELETE FROM public.app_sessions
  WHERE profile_id = v_profile.id AND expires_at <= now();

  INSERT INTO public.app_sessions (token_hash, profile_id, expires_at)
  VALUES (v_token_hash, v_profile.id, now() + interval '30 days');

  RETURN jsonb_build_object(
    'ok', true,
    'is_bootstrap', v_is_bootstrap,
    'session_token', v_raw_token,
    'profile', jsonb_build_object(
      'id', v_profile.id,
      'phone', v_profile.phone,
      'display_name', v_profile.display_name,
      'role', v_profile.role,
      'restrict_manager', public.is_manager_restricted()
    )
  );
END;
$$;

-- 5.2 查询当前登录身份（whoami）
CREATE OR REPLACE FUNCTION public.gfb_whoami()
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_pid     uuid := public.current_profile_id();
  v_profile public.profiles%ROWTYPE;
BEGIN
  IF v_pid IS NULL THEN
    RETURN jsonb_build_object('authenticated', false, 'profile', NULL);
  END IF;

  SELECT * INTO v_profile FROM public.profiles WHERE id = v_pid AND is_active = true;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('authenticated', false, 'profile', NULL);
  END IF;

  RETURN jsonb_build_object(
    'authenticated', true,
    'profile', jsonb_build_object(
      'id', v_profile.id,
      'phone', v_profile.phone,
      'display_name', v_profile.display_name,
      'role', v_profile.role,
      'restrict_manager', public.is_manager_restricted()
    )
  );
END;
$$;

-- 5.3 退出登录（销毁当前会话令牌）
CREATE OR REPLACE FUNCTION public.gfb_logout()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  v_headers       jsonb;
  v_session_token text;
  v_token_hash    text;
BEGIN
  BEGIN
    v_headers := COALESCE(current_setting('request.headers', true), '{}')::jsonb;
  EXCEPTION WHEN OTHERS THEN
    v_headers := '{}'::jsonb;
  END;

  v_session_token := NULLIF(trim(COALESCE(v_headers ->> 'x-gfb-session', '')), '');
  IF v_session_token IS NOT NULL THEN
    v_token_hash := encode(digest(convert_to(v_session_token, 'utf8'), 'sha256'), 'hex');
    DELETE FROM public.app_sessions WHERE token_hash = v_token_hash;
  END IF;
  RETURN jsonb_build_object('ok', true);
END;
$$;

-- 5.4 房东重置指定账号口令（或用户修改自己的口令）
CREATE OR REPLACE FUNCTION public.gfb_reset_pin(
  p_target_profile_id uuid,
  p_new_pin           text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
  v_me  uuid := public.current_profile_id();
  v_pin text := trim(COALESCE(p_new_pin, ''));
BEGIN
  IF v_me IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'message', '请先登录');
  END IF;
  IF NOT public.is_landlord() AND v_me <> p_target_profile_id THEN
    RETURN jsonb_build_object('ok', false, 'message', '仅主房东或本人可修改安全口令');
  END IF;
  IF length(v_pin) < 4 THEN
    RETURN jsonb_build_object('ok', false, 'message', '安全口令至少需要 4 位字符');
  END IF;

  UPDATE public.profiles
  SET pin_hash = crypt(v_pin, gen_salt('bf')), updated_at = now()
  WHERE id = p_target_profile_id;

  -- 使旧会话失效，确保口令重置立即生效
  DELETE FROM public.app_sessions WHERE profile_id = p_target_profile_id;

  RETURN jsonb_build_object('ok', true, 'message', '安全口令已更新');
END;
$$;

-- ============================================================================
-- 6. 启用全部表行级安全策略（RLS）与最小权限授权
-- ============================================================================

ALTER TABLE public.profiles            ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.app_sessions        ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.buildings           ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.manager_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rooms               ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.contracts           ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.bills               ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.meter_readings      ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.repairs             ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.ledger_entries      ENABLE ROW LEVEL SECURITY;

-- 6.1 profiles 策略（老板全局管理；管房员仅可读自己，且严禁暴露 pin_hash 列）
DROP POLICY IF EXISTS profiles_select ON public.profiles;
CREATE POLICY profiles_select ON public.profiles
  FOR SELECT TO anon, authenticated
  USING (public.is_landlord() OR id = public.current_profile_id());

DROP POLICY IF EXISTS profiles_insert ON public.profiles;
CREATE POLICY profiles_insert ON public.profiles
  FOR INSERT TO anon, authenticated
  WITH CHECK (public.is_landlord());

DROP POLICY IF EXISTS profiles_update ON public.profiles;
CREATE POLICY profiles_update ON public.profiles
  FOR UPDATE TO anon, authenticated
  USING (public.is_landlord())
  WITH CHECK (public.is_landlord());

DROP POLICY IF EXISTS profiles_delete ON public.profiles;
CREATE POLICY profiles_delete ON public.profiles
  FOR DELETE TO anon, authenticated
  USING (public.is_landlord() AND id <> public.current_profile_id());

-- 6.2 manager_assignments 策略（老板全权分配；管房员仅可读自己的分配记录）
DROP POLICY IF EXISTS manager_assignments_select ON public.manager_assignments;
CREATE POLICY manager_assignments_select ON public.manager_assignments
  FOR SELECT TO anon, authenticated
  USING (public.is_landlord() OR manager_id = public.current_profile_id());

DROP POLICY IF EXISTS manager_assignments_insert ON public.manager_assignments;
CREATE POLICY manager_assignments_insert ON public.manager_assignments
  FOR INSERT TO anon, authenticated
  WITH CHECK (public.is_landlord());

DROP POLICY IF EXISTS manager_assignments_update ON public.manager_assignments;
CREATE POLICY manager_assignments_update ON public.manager_assignments
  FOR UPDATE TO anon, authenticated
  USING (public.is_landlord())
  WITH CHECK (public.is_landlord());

DROP POLICY IF EXISTS manager_assignments_delete ON public.manager_assignments;
CREATE POLICY manager_assignments_delete ON public.manager_assignments
  FOR DELETE TO anon, authenticated
  USING (public.is_landlord());

-- 6.3 buildings 策略（老板全局读写；管房员仅可查询已分配给自己的楼栋）
DROP POLICY IF EXISTS buildings_select ON public.buildings;
CREATE POLICY buildings_select ON public.buildings
  FOR SELECT TO anon, authenticated
  USING (public.can_access_building(id));

DROP POLICY IF EXISTS buildings_insert ON public.buildings;
CREATE POLICY buildings_insert ON public.buildings
  FOR INSERT TO anon, authenticated
  WITH CHECK (public.is_landlord());

DROP POLICY IF EXISTS buildings_update ON public.buildings;
CREATE POLICY buildings_update ON public.buildings
  FOR UPDATE TO anon, authenticated
  USING (public.is_landlord())
  WITH CHECK (public.is_landlord());

DROP POLICY IF EXISTS buildings_delete ON public.buildings;
CREATE POLICY buildings_delete ON public.buildings
  FOR DELETE TO anon, authenticated
  USING (public.is_landlord());

-- 6.4 rooms 策略（按楼栋分配严格隔离；受限管房员禁增删房间）
DROP POLICY IF EXISTS rooms_select ON public.rooms;
CREATE POLICY rooms_select ON public.rooms
  FOR SELECT TO anon, authenticated
  USING (public.can_access_building(building_id));

DROP POLICY IF EXISTS rooms_insert ON public.rooms;
CREATE POLICY rooms_insert ON public.rooms
  FOR INSERT TO anon, authenticated
  WITH CHECK (
    public.is_landlord()
    OR (public.is_active_manager() AND NOT public.is_manager_restricted() AND public.can_access_building(building_id))
  );

DROP POLICY IF EXISTS rooms_update ON public.rooms;
CREATE POLICY rooms_update ON public.rooms
  FOR UPDATE TO anon, authenticated
  USING (public.can_access_building(building_id))
  WITH CHECK (public.can_access_building(building_id));

DROP POLICY IF EXISTS rooms_delete ON public.rooms;
CREATE POLICY rooms_delete ON public.rooms
  FOR DELETE TO anon, authenticated
  USING (
    public.is_landlord()
    OR (public.is_active_manager() AND NOT public.is_manager_restricted() AND public.can_access_building(building_id))
  );

-- 6.5 contracts 策略（按楼栋分配严格隔离）
DROP POLICY IF EXISTS contracts_select ON public.contracts;
CREATE POLICY contracts_select ON public.contracts
  FOR SELECT TO anon, authenticated
  USING (public.can_access_building(building_id));

DROP POLICY IF EXISTS contracts_insert ON public.contracts;
CREATE POLICY contracts_insert ON public.contracts
  FOR INSERT TO anon, authenticated
  WITH CHECK (public.can_access_building(building_id));

DROP POLICY IF EXISTS contracts_update ON public.contracts;
CREATE POLICY contracts_update ON public.contracts
  FOR UPDATE TO anon, authenticated
  USING (public.can_access_building(building_id))
  WITH CHECK (public.can_access_building(building_id));

DROP POLICY IF EXISTS contracts_delete ON public.contracts;
CREATE POLICY contracts_delete ON public.contracts
  FOR DELETE TO anon, authenticated
  USING (
    public.is_landlord()
    OR (public.is_active_manager() AND NOT public.is_manager_restricted() AND public.can_access_building(building_id))
  );

-- 6.6 bills 策略（按楼栋分配严格隔离）
DROP POLICY IF EXISTS bills_select ON public.bills;
CREATE POLICY bills_select ON public.bills
  FOR SELECT TO anon, authenticated
  USING (public.can_access_building(building_id));

DROP POLICY IF EXISTS bills_insert ON public.bills;
CREATE POLICY bills_insert ON public.bills
  FOR INSERT TO anon, authenticated
  WITH CHECK (public.can_access_building(building_id));

DROP POLICY IF EXISTS bills_update ON public.bills;
CREATE POLICY bills_update ON public.bills
  FOR UPDATE TO anon, authenticated
  USING (public.can_access_building(building_id))
  WITH CHECK (public.can_access_building(building_id));

DROP POLICY IF EXISTS bills_delete ON public.bills;
CREATE POLICY bills_delete ON public.bills
  FOR DELETE TO anon, authenticated
  USING (
    public.is_landlord()
    OR (public.is_active_manager() AND NOT public.is_manager_restricted() AND public.can_access_building(building_id))
  );

-- 6.7 meter_readings 策略（按楼栋分配严格隔离；抄表审计日志仅老板可删）
DROP POLICY IF EXISTS meter_readings_select ON public.meter_readings;
CREATE POLICY meter_readings_select ON public.meter_readings
  FOR SELECT TO anon, authenticated
  USING (public.can_access_building(building_id));

DROP POLICY IF EXISTS meter_readings_insert ON public.meter_readings;
CREATE POLICY meter_readings_insert ON public.meter_readings
  FOR INSERT TO anon, authenticated
  WITH CHECK (public.can_access_building(building_id));

DROP POLICY IF EXISTS meter_readings_update ON public.meter_readings;
CREATE POLICY meter_readings_update ON public.meter_readings
  FOR UPDATE TO anon, authenticated
  USING (public.can_access_building(building_id))
  WITH CHECK (public.can_access_building(building_id));

DROP POLICY IF EXISTS meter_readings_delete ON public.meter_readings;
CREATE POLICY meter_readings_delete ON public.meter_readings
  FOR DELETE TO anon, authenticated
  USING (public.is_landlord());

-- 6.8 repairs 策略（按楼栋分配隔离）
DROP POLICY IF EXISTS repairs_select ON public.repairs;
CREATE POLICY repairs_select ON public.repairs
  FOR SELECT TO anon, authenticated
  USING (public.is_landlord() OR (building_id IS NOT NULL AND public.can_access_building(building_id)));

DROP POLICY IF EXISTS repairs_insert ON public.repairs;
CREATE POLICY repairs_insert ON public.repairs
  FOR INSERT TO anon, authenticated
  WITH CHECK (public.is_landlord() OR (building_id IS NOT NULL AND public.can_access_building(building_id)));

DROP POLICY IF EXISTS repairs_update ON public.repairs;
CREATE POLICY repairs_update ON public.repairs
  FOR UPDATE TO anon, authenticated
  USING (public.is_landlord() OR (building_id IS NOT NULL AND public.can_access_building(building_id)))
  WITH CHECK (public.is_landlord() OR (building_id IS NOT NULL AND public.can_access_building(building_id)));

DROP POLICY IF EXISTS repairs_delete ON public.repairs;
CREATE POLICY repairs_delete ON public.repairs
  FOR DELETE TO anon, authenticated
  USING (public.is_landlord());

-- 6.9 ledger_entries 策略（保护老板财务总账；管房员收租可记入账但受限时不可查看流水）
DROP POLICY IF EXISTS ledger_entries_select ON public.ledger_entries;
CREATE POLICY ledger_entries_select ON public.ledger_entries
  FOR SELECT TO anon, authenticated
  USING (
    public.is_landlord()
    OR (public.is_active_manager() AND NOT public.is_manager_restricted() AND building_id IS NOT NULL AND public.can_access_building(building_id))
  );

DROP POLICY IF EXISTS ledger_entries_insert ON public.ledger_entries;
CREATE POLICY ledger_entries_insert ON public.ledger_entries
  FOR INSERT TO anon, authenticated
  WITH CHECK (
    public.is_landlord()
    OR (public.is_active_manager() AND entry_type = 'in' AND building_id IS NOT NULL AND public.can_access_building(building_id))
  );

DROP POLICY IF EXISTS ledger_entries_update ON public.ledger_entries;
CREATE POLICY ledger_entries_update ON public.ledger_entries
  FOR UPDATE TO anon, authenticated
  USING (public.is_landlord())
  WITH CHECK (public.is_landlord());

DROP POLICY IF EXISTS ledger_entries_delete ON public.ledger_entries;
CREATE POLICY ledger_entries_delete ON public.ledger_entries
  FOR DELETE TO anon, authenticated
  USING (public.is_landlord());

-- 6.10 兼容并收紧旧版 store 表权限：
--      - 开启 RLS 后，未登录请求（如 GitHub Actions 保活 ping）仍返回 HTTP 200 空数组 []，不中断保活
--      - 仅已登录的主房东可读取旧 store.data 用于一键迁移，阻断匿名整库泄露
DO $$
BEGIN
  IF to_regclass('public.store') IS NOT NULL THEN
    EXECUTE 'ALTER TABLE public.store ENABLE ROW LEVEL SECURITY';
    EXECUTE 'DROP POLICY IF EXISTS store_landlord_only ON public.store';
    EXECUTE 'CREATE POLICY store_landlord_only ON public.store FOR ALL TO anon, authenticated USING (public.is_landlord()) WITH CHECK (public.is_landlord())';
    EXECUTE 'GRANT SELECT ON public.store TO anon, authenticated';
  END IF;
END;
$$;

-- ============================================================================
-- 7. 老数据无损幂等迁移 RPC（支持从前端 JSON / 本地缓存 / 旧 store 表一键导入）
-- ============================================================================

CREATE OR REPLACE FUNCTION public.gfb_safe_numeric(p_val text, p_default numeric DEFAULT NULL)
RETURNS numeric
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
  v_s text := trim(COALESCE(p_val, ''));
BEGIN
  IF v_s = '' OR v_s = '-' OR lower(v_s) = 'null' OR lower(v_s) = 'nan' THEN
    RETURN p_default;
  END IF;
  RETURN v_s::numeric;
EXCEPTION WHEN OTHERS THEN
  RETURN p_default;
END;
$$;

CREATE OR REPLACE FUNCTION public.gfb_safe_date(p_val text)
RETURNS date
LANGUAGE plpgsql
IMMUTABLE
AS $$
DECLARE
  v_s text := trim(COALESCE(p_val, ''));
BEGIN
  IF v_s = '' OR v_s = '-' THEN
    RETURN NULL;
  END IF;
  RETURN left(v_s, 10)::date;
EXCEPTION WHEN OTHERS THEN
  RETURN NULL;
END;
$$;

-- 核心幂等迁移函数（支持事务原子性，重复执行不产生脏数据或重复行）
CREATE OR REPLACE FUNCTION public.gfb_migrate_legacy_json(p_payload jsonb)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_caller_id     uuid := public.current_profile_id();
  v_is_superuser  boolean := (current_user IN ('postgres', 'supabase_admin', 'service_role'));
  v_bldg_name     text;
  v_bldg_id       uuid;
  v_room          jsonb;
  v_room_id       uuid;
  v_room_legacy   text;
  v_room_name     text;
  v_contract_id   uuid;
  v_bill          jsonb;
  v_bill_id       uuid;
  v_bill_legacy   text;
  v_past          jsonb;
  v_mgr           jsonb;
  v_rep           jsonb;
  v_led           jsonb;
  v_exp           jsonb;
  v_admin_phone   text;
  v_cnt_buildings integer := 0;
  v_cnt_rooms     integer := 0;
  v_cnt_contracts integer := 0;
  v_cnt_bills     integer := 0;
  v_cnt_readings  integer := 0;
  v_cnt_managers  integer := 0;
  v_cnt_repairs   integer := 0;
  v_cnt_ledger    integer := 0;
  v_idx           integer := 0;
  v_lw            numeric;
  v_cw            numeric;
  v_le            numeric;
  v_ce            numeric;
BEGIN
  IF NOT v_is_superuser AND NOT public.is_landlord() THEN
    RAISE EXCEPTION '权限不足：仅主房东可执行老数据迁移';
  END IF;

  IF p_payload IS NULL OR jsonb_typeof(p_payload) <> 'object' THEN
    RAISE EXCEPTION '迁移数据格式无效：需要 JSON 对象';
  END IF;

  -- 1. 同步主房东 restrict_manager 开关与管房员账号
  v_admin_phone := regexp_replace(trim(COALESCE(p_payload ->> 'adminPhone', '')), '\s+', '', 'g');
  IF v_admin_phone <> '' THEN
    INSERT INTO public.profiles (phone, display_name, role, restrict_manager, is_active)
    VALUES (
      v_admin_phone,
      '主房东',
      'landlord',
      (lower(trim(COALESCE(p_payload ->> 'restrictMgr', ''))) = 'true'),
      true
    )
    ON CONFLICT (phone) DO UPDATE
      SET restrict_manager = CASE
            WHEN p_payload ? 'restrictMgr' THEN (lower(trim(COALESCE(p_payload ->> 'restrictMgr', ''))) = 'true')
            ELSE public.profiles.restrict_manager
          END,
          updated_at = now();
  END IF;

  FOR v_mgr IN SELECT * FROM jsonb_array_elements(COALESCE(p_payload -> 'managers', '[]'::jsonb))
  LOOP
    IF trim(COALESCE(v_mgr ->> 'phone', '')) <> '' THEN
      INSERT INTO public.profiles (phone, display_name, role, is_active)
      VALUES (
        regexp_replace(trim(v_mgr ->> 'phone'), '\s+', '', 'g'),
        COALESCE(NULLIF(trim(v_mgr ->> 'name'), ''), '管房员'),
        'manager',
        true
      )
      ON CONFLICT (phone) DO UPDATE
        SET display_name = EXCLUDED.display_name,
            updated_at = now()
        WHERE public.profiles.role <> 'landlord';
      v_cnt_managers := v_cnt_managers + 1;
    END IF;
  END LOOP;

  -- 2. 迁移楼栋、房间与在租合同
  FOR v_room IN SELECT * FROM jsonb_array_elements(COALESCE(p_payload -> 'rooms', '[]'::jsonb))
  LOOP
    v_bldg_name := COALESCE(NULLIF(trim(v_room ->> 'building'), ''), '默认楼栋');
    INSERT INTO public.buildings (name, default_rent, default_water_price, default_elec_price, created_by)
    VALUES (
      v_bldg_name,
      public.gfb_safe_numeric(v_room ->> 'rent', 1000),
      public.gfb_safe_numeric(v_room ->> 'waterPrice', 5),
      public.gfb_safe_numeric(v_room ->> 'elecPrice', 1),
      v_caller_id
    )
    ON CONFLICT (name) DO NOTHING;

    SELECT id INTO v_bldg_id FROM public.buildings WHERE name = v_bldg_name;

    v_room_legacy := NULLIF(trim(COALESCE(v_room ->> 'id', '')), '');
    v_room_name   := COALESCE(NULLIF(trim(v_room ->> 'name'), ''), '未命名房间');

    SELECT id INTO v_room_id
    FROM public.rooms
    WHERE (v_room_legacy IS NOT NULL AND legacy_id = v_room_legacy)
       OR (building_id = v_bldg_id AND name = v_room_name)
    LIMIT 1;

    IF v_room_id IS NULL THEN
      INSERT INTO public.rooms (
        legacy_id, building_id, name, floor, house_type,
        rent, water_price, elec_price, last_water, last_elec,
        status, vacant_since, plan_checkout, updated_by
      )
      VALUES (
        v_room_legacy,
        v_bldg_id,
        v_room_name,
        public.gfb_safe_numeric(v_room ->> 'floor', NULL)::integer,
        COALESCE(v_room ->> 'houseType', ''),
        public.gfb_safe_numeric(v_room ->> 'rent', 1000),
        public.gfb_safe_numeric(v_room ->> 'waterPrice', 5),
        public.gfb_safe_numeric(v_room ->> 'elecPrice', 1),
        public.gfb_safe_numeric(v_room ->> 'lastWater', 0),
        public.gfb_safe_numeric(v_room ->> 'lastElec', 0),
        CASE WHEN (v_room ->> 'status') = 'rented' THEN 'rented' ELSE 'vacant' END,
        public.gfb_safe_date(v_room ->> 'vacantSince'),
        public.gfb_safe_date(v_room ->> 'planCheckout'),
        v_caller_id
      )
      RETURNING id INTO v_room_id;
    ELSE
      UPDATE public.rooms
      SET legacy_id     = COALESCE(public.rooms.legacy_id, v_room_legacy),
          house_type    = COALESCE(NULLIF(v_room ->> 'houseType', ''), public.rooms.house_type),
          rent          = public.gfb_safe_numeric(v_room ->> 'rent', public.rooms.rent),
          water_price   = public.gfb_safe_numeric(v_room ->> 'waterPrice', public.rooms.water_price),
          elec_price    = public.gfb_safe_numeric(v_room ->> 'elecPrice', public.rooms.elec_price),
          last_water    = public.gfb_safe_numeric(v_room ->> 'lastWater', public.rooms.last_water),
          last_elec     = public.gfb_safe_numeric(v_room ->> 'lastElec', public.rooms.last_elec),
          status        = CASE WHEN (v_room ->> 'status') = 'rented' THEN 'rented' ELSE 'vacant' END,
          vacant_since  = COALESCE(public.gfb_safe_date(v_room ->> 'vacantSince'), public.rooms.vacant_since),
          plan_checkout = COALESCE(public.gfb_safe_date(v_room ->> 'planCheckout'), public.rooms.plan_checkout),
          updated_by    = v_caller_id
      WHERE id = v_room_id;
    END IF;
    v_cnt_rooms := v_cnt_rooms + 1;

    -- 若房间处于已租状态，迁移当前生效租约
    IF (v_room ->> 'status') = 'rented' AND trim(COALESCE(v_room ->> 'tenant', '')) <> '' THEN
      INSERT INTO public.contracts (
        legacy_id, building_id, room_id, contract_no,
        tenant_name, tenant_phone, id_card, id_addr,
        start_date, end_date, sign_date,
        cycle, bill_mode, pay_day,
        rent, deposit, water_price, elec_price, extra_fees,
        status, created_by
      )
      VALUES (
        'CT_ACTIVE_' || COALESCE(v_room_legacy, v_room_id::text),
        v_bldg_id,
        v_room_id,
        COALESCE(v_room ->> 'contractNo', ''),
        trim(v_room ->> 'tenant'),
        COALESCE(v_room ->> 'phone', ''),
        COALESCE(v_room ->> 'idCard', ''),
        COALESCE(v_room ->> 'idAddr', ''),
        public.gfb_safe_date(v_room ->> 'startDate'),
        public.gfb_safe_date(v_room ->> 'endDate'),
        public.gfb_safe_date(COALESCE(v_room ->> 'signDate', v_room ->> 'startDate')),
        COALESCE(v_room ->> 'cycle', '月付 (每月收一次)'),
        COALESCE(v_room ->> 'billMode', COALESCE(v_room ->> 'billCycle', '按起租日算')),
        COALESCE(v_room ->> 'payDay', '账单开始前 当天'),
        public.gfb_safe_numeric(v_room ->> 'rent', 0),
        public.gfb_safe_numeric(v_room ->> 'deposit', 0),
        public.gfb_safe_numeric(v_room ->> 'waterPrice', 5),
        public.gfb_safe_numeric(v_room ->> 'elecPrice', 1),
        COALESCE(v_room -> 'extraFees', '[]'::jsonb),
        'active',
        v_caller_id
      )
      ON CONFLICT (legacy_id) DO UPDATE
        SET tenant_name  = EXCLUDED.tenant_name,
            tenant_phone = EXCLUDED.tenant_phone,
            start_date   = EXCLUDED.start_date,
            end_date     = EXCLUDED.end_date,
            rent         = EXCLUDED.rent,
            deposit      = EXCLUDED.deposit,
            extra_fees   = EXCLUDED.extra_fees,
            status       = 'active';
      v_cnt_contracts := v_cnt_contracts + 1;
    END IF;
  END LOOP;

  -- 3. 迁移历史退租租客记录到 contracts (status = 'checked_out')
  v_idx := 0;
  FOR v_past IN SELECT * FROM jsonb_array_elements(COALESCE(p_payload -> 'pastTenants', '[]'::jsonb))
  LOOP
    v_idx := v_idx + 1;
    v_bldg_name := COALESCE(NULLIF(trim(v_past ->> 'building'), ''), '默认楼栋');
    INSERT INTO public.buildings (name, created_by) VALUES (v_bldg_name, v_caller_id) ON CONFLICT (name) DO NOTHING;
    SELECT id INTO v_bldg_id FROM public.buildings WHERE name = v_bldg_name;

    v_room_name := COALESCE(NULLIF(trim(v_past ->> 'name'), ''), '历史房间');
    SELECT id INTO v_room_id FROM public.rooms WHERE building_id = v_bldg_id AND name = v_room_name LIMIT 1;
    IF v_room_id IS NULL THEN
      INSERT INTO public.rooms (building_id, name, status, updated_by)
      VALUES (v_bldg_id, v_room_name, 'vacant', v_caller_id)
      RETURNING id INTO v_room_id;
    END IF;

    INSERT INTO public.contracts (
      legacy_id, building_id, room_id, tenant_name, tenant_phone,
      checkout_date, status, settle_note, created_by
    )
    VALUES (
      'CT_PAST_' || md5(v_bldg_name || '|' || v_room_name || '|' || COALESCE(v_past ->> 'tenant', '') || '|' || COALESCE(v_past ->> 'checkoutDate', v_idx::text)),
      v_bldg_id,
      v_room_id,
      COALESCE(NULLIF(trim(v_past ->> 'tenant'), ''), '历史租客'),
      COALESCE(v_past ->> 'phone', ''),
      public.gfb_safe_date(v_past ->> 'checkoutDate'),
      'checked_out',
      COALESCE(v_past ->> 'settleNote', ''),
      v_caller_id
    )
    ON CONFLICT (legacy_id) DO NOTHING;
    v_cnt_contracts := v_cnt_contracts + 1;
  END LOOP;

  -- 4. 迁移账单及关联抄表记录（严格 0 值安全）
  v_idx := 0;
  FOR v_bill IN SELECT * FROM jsonb_array_elements(COALESCE(p_payload -> 'bills', '[]'::jsonb))
  LOOP
    v_idx := v_idx + 1;
    v_bill_legacy := COALESCE(NULLIF(trim(v_bill ->> 'id'), ''), 'BL_LEGACY_' || v_idx::text);
    v_room_legacy := NULLIF(trim(COALESCE(v_bill ->> 'roomId', '')), '');
    v_bldg_name   := COALESCE(NULLIF(trim(v_bill ->> 'building'), ''), '默认楼栋');

    SELECT id, building_id INTO v_room_id, v_bldg_id
    FROM public.rooms
    WHERE v_room_legacy IS NOT NULL AND legacy_id = v_room_legacy
    LIMIT 1;

    IF v_room_id IS NULL THEN
      INSERT INTO public.buildings (name, created_by) VALUES (v_bldg_name, v_caller_id) ON CONFLICT (name) DO NOTHING;
      SELECT id INTO v_bldg_id FROM public.buildings WHERE name = v_bldg_name;
      v_room_name := COALESCE(NULLIF(trim(v_bill ->> 'roomName'), ''), '历史房间');
      SELECT id INTO v_room_id FROM public.rooms WHERE building_id = v_bldg_id AND name = v_room_name LIMIT 1;
      IF v_room_id IS NULL THEN
        INSERT INTO public.rooms (legacy_id, building_id, name, status, updated_by)
        VALUES (v_room_legacy, v_bldg_id, v_room_name, 'vacant', v_caller_id)
        RETURNING id INTO v_room_id;
      END IF;
    END IF;

    SELECT id INTO v_contract_id
    FROM public.contracts
    WHERE room_id = v_room_id AND status = 'active'
    ORDER BY created_at DESC
    LIMIT 1;

    v_lw := public.gfb_safe_numeric(v_bill ->> 'lastW', NULL);
    v_cw := public.gfb_safe_numeric(v_bill ->> 'curW', NULL);
    v_le := public.gfb_safe_numeric(v_bill ->> 'lastE', NULL);
    v_ce := public.gfb_safe_numeric(v_bill ->> 'curE', NULL);

    INSERT INTO public.bills (
      legacy_id, building_id, room_id, contract_id,
      room_name, tenant_name, tenant_phone,
      bill_month, bill_date, period,
      rent, deposit, extra_fee,
      last_water, cur_water, use_water, water_price, water_fee,
      last_elec, cur_elec, use_elec, elec_price, elec_fee,
      total, paid_amount, detail, status, updated_by
    )
    VALUES (
      v_bill_legacy,
      v_bldg_id,
      v_room_id,
      v_contract_id,
      COALESCE(v_bill ->> 'roomName', ''),
      COALESCE(v_bill ->> 'tenant', ''),
      COALESCE(v_bill ->> 'phone', ''),
      COALESCE(v_bill ->> 'month', ''),
      public.gfb_safe_date(v_bill ->> 'date'),
      COALESCE(v_bill ->> 'period', COALESCE(v_bill ->> 'month', '')),
      public.gfb_safe_numeric(v_bill ->> 'rent', 0),
      public.gfb_safe_numeric(v_bill ->> 'deposit', 0),
      public.gfb_safe_numeric(v_bill ->> 'extraFee', 0),
      v_lw,
      v_cw,
      public.gfb_safe_numeric(v_bill ->> 'useW', 0),
      COALESCE((SELECT water_price FROM public.rooms WHERE id = v_room_id), 5),
      public.gfb_safe_numeric(v_bill ->> 'waterFee', 0),
      v_le,
      v_ce,
      public.gfb_safe_numeric(v_bill ->> 'useE', 0),
      COALESCE((SELECT elec_price FROM public.rooms WHERE id = v_room_id), 1),
      public.gfb_safe_numeric(v_bill ->> 'elecFee', 0),
      public.gfb_safe_numeric(v_bill ->> 'total', 0),
      public.gfb_safe_numeric(v_bill ->> 'paidAmount', 0),
      COALESCE(v_bill ->> 'detail', ''),
      CASE WHEN (v_bill ->> 'status') IN ('unmetered', 'unpaid', 'paid') THEN (v_bill ->> 'status') ELSE 'unpaid' END,
      v_caller_id
    )
    ON CONFLICT (legacy_id) DO UPDATE
      SET total       = EXCLUDED.total,
          status      = EXCLUDED.status,
          last_water  = EXCLUDED.last_water,
          cur_water   = EXCLUDED.cur_water,
          use_water   = EXCLUDED.use_water,
          water_price = EXCLUDED.water_price,
          water_fee   = EXCLUDED.water_fee,
          last_elec   = EXCLUDED.last_elec,
          cur_elec    = EXCLUDED.cur_elec,
          use_elec    = EXCLUDED.use_elec,
          elec_price  = EXCLUDED.elec_price,
          elec_fee    = EXCLUDED.elec_fee,
          paid_amount = EXCLUDED.paid_amount
    RETURNING id INTO v_bill_id;
    v_cnt_bills := v_cnt_bills + 1;

    -- 若账单含水电抄表读数，同步生成抄表记录（meter_readings）
    IF v_cw IS NOT NULL OR v_ce IS NOT NULL THEN
      INSERT INTO public.meter_readings (
        legacy_id, building_id, room_id, bill_id,
        reading_month, reading_date,
        prev_water, curr_water, usage_water, water_price, water_fee,
        prev_elec, curr_elec, usage_elec, elec_price, elec_fee,
        recorded_by
      )
      VALUES (
        'MR_' || v_bill_legacy,
        v_bldg_id,
        v_room_id,
        v_bill_id,
        COALESCE(v_bill ->> 'month', ''),
        COALESCE(public.gfb_safe_date(v_bill ->> 'date'), CURRENT_DATE),
        COALESCE(v_lw, 0),
        v_cw,
        public.gfb_safe_numeric(v_bill ->> 'useW', 0),
        COALESCE((SELECT water_price FROM public.rooms WHERE id = v_room_id), 5),
        public.gfb_safe_numeric(v_bill ->> 'waterFee', 0),
        COALESCE(v_le, 0),
        v_ce,
        public.gfb_safe_numeric(v_bill ->> 'useE', 0),
        COALESCE((SELECT elec_price FROM public.rooms WHERE id = v_room_id), 1),
        public.gfb_safe_numeric(v_bill ->> 'elecFee', 0),
        v_caller_id
      )
      ON CONFLICT (legacy_id) DO NOTHING;
      v_cnt_readings := v_cnt_readings + 1;
    END IF;
  END LOOP;

  -- 5. 迁移报修工单
  v_idx := 0;
  FOR v_rep IN SELECT * FROM jsonb_array_elements(COALESCE(p_payload -> 'repairs', '[]'::jsonb))
  LOOP
    v_idx := v_idx + 1;
    SELECT id INTO v_bldg_id
    FROM public.buildings
    WHERE position(name IN COALESCE(v_rep ->> 'roomName', '')) > 0
    LIMIT 1;

    INSERT INTO public.repairs (legacy_id, building_id, room_name, repair_type, description, status, report_date, created_by)
    VALUES (
      'RP_' || md5(COALESCE(v_rep ->> 'roomName', '') || '|' || COALESCE(v_rep ->> 'desc', '') || '|' || COALESCE(v_rep ->> 'date', v_idx::text)),
      v_bldg_id,
      COALESCE(v_rep ->> 'roomName', '未指定房间'),
      COALESCE(NULLIF(trim(v_rep ->> 'type'), ''), '水电'),
      COALESCE(v_rep ->> 'desc', ''),
      CASE WHEN (v_rep ->> 'status') = 'done' THEN 'done' ELSE 'pending' END,
      COALESCE(public.gfb_safe_date(v_rep ->> 'date'), CURRENT_DATE),
      v_caller_id
    )
    ON CONFLICT (legacy_id) DO NOTHING;
    v_cnt_repairs := v_cnt_repairs + 1;
  END LOOP;

  -- 6. 迁移收支流水（若 ledger 为空再回退迁移 expenses，避免重复计算）
  v_idx := 0;
  FOR v_led IN SELECT * FROM jsonb_array_elements(COALESCE(p_payload -> 'ledger', '[]'::jsonb))
  LOOP
    v_idx := v_idx + 1;
    INSERT INTO public.ledger_entries (legacy_id, entry_type, title, amount, entry_date, created_by)
    VALUES (
      'LD_' || md5(COALESCE(v_led ->> 'type', '') || '|' || COALESCE(v_led ->> 'title', '') || '|' || COALESCE(v_led ->> 'amount', '') || '|' || COALESCE(v_led ->> 'date', '') || '|' || v_idx::text),
      CASE WHEN (v_led ->> 'type') = 'out' THEN 'out' ELSE 'in' END,
      COALESCE(v_led ->> 'title', '历史流水'),
      public.gfb_safe_numeric(v_led ->> 'amount', 0),
      COALESCE(public.gfb_safe_date(v_led ->> 'date'), CURRENT_DATE),
      v_caller_id
    )
    ON CONFLICT (legacy_id) DO NOTHING;
    v_cnt_ledger := v_cnt_ledger + 1;
  END LOOP;

  IF v_cnt_ledger = 0 THEN
    v_idx := 0;
    FOR v_exp IN SELECT * FROM jsonb_array_elements(COALESCE(p_payload -> 'expenses', '[]'::jsonb))
    LOOP
      v_idx := v_idx + 1;
      INSERT INTO public.ledger_entries (legacy_id, entry_type, category, title, amount, entry_date, created_by)
      VALUES (
        'EX_' || md5(COALESCE(v_exp ->> 'cat', '') || '|' || COALESCE(v_exp ->> 'amount', '') || '|' || COALESCE(v_exp ->> 'date', '') || '|' || v_idx::text),
        'out',
        COALESCE(v_exp ->> 'cat', '日常支出'),
        '[支出] ' || COALESCE(v_exp ->> 'cat', '日常支出'),
        public.gfb_safe_numeric(v_exp ->> 'amount', 0),
        COALESCE(public.gfb_safe_date(v_exp ->> 'date'), CURRENT_DATE),
        v_caller_id
      )
      ON CONFLICT (legacy_id) DO NOTHING;
      v_cnt_ledger := v_cnt_ledger + 1;
    END LOOP;
  END IF;

  SELECT count(*) INTO v_cnt_buildings FROM public.buildings;

  RETURN jsonb_build_object(
    'ok', true,
    'buildings', v_cnt_buildings,
    'rooms', v_cnt_rooms,
    'contracts', v_cnt_contracts,
    'bills', v_cnt_bills,
    'meter_readings', v_cnt_readings,
    'managers', v_cnt_managers,
    'repairs', v_cnt_repairs,
    'ledger_entries', v_cnt_ledger
  );
END;
$$;

-- 便捷函数：直接从旧版 public.store (id=1) 读取并迁移到新表（可在 SQL Editor 或前端一键调用）
CREATE OR REPLACE FUNCTION public.gfb_migrate_from_store_table()
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_is_superuser boolean := (current_user IN ('postgres', 'supabase_admin', 'service_role'));
  v_payload      jsonb;
BEGIN
  IF NOT v_is_superuser AND NOT public.is_landlord() THEN
    RAISE EXCEPTION '权限不足：仅主房东可执行旧库迁移';
  END IF;

  IF to_regclass('public.store') IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'message', '当前数据库不存在旧版 store 表，无需云端迁移');
  END IF;

  EXECUTE 'SELECT data FROM public.store WHERE id = 1 LIMIT 1' INTO v_payload;
  IF v_payload IS NULL THEN
    RETURN jsonb_build_object('ok', false, 'message', '旧版 store 表中暂无可迁移数据');
  END IF;

  RETURN public.gfb_migrate_legacy_json(v_payload);
END;
$$;

-- ============================================================================
-- 8. 最小权限 GRANT（特别注意：撤销对 profiles.pin_hash 与 app_sessions 的直接访问）
-- ============================================================================

GRANT USAGE ON SCHEMA public TO anon, authenticated;

-- profiles 列级最小授权：绝不向客户端暴露 pin_hash
REVOKE ALL ON public.profiles FROM anon, authenticated;
GRANT SELECT (id, auth_user_id, phone, display_name, role, restrict_manager, is_active, created_at, updated_at) ON public.profiles TO anon, authenticated;
GRANT INSERT (phone, display_name, role, restrict_manager, is_active) ON public.profiles TO anon, authenticated;
GRANT UPDATE (phone, display_name, role, restrict_manager, is_active, updated_at) ON public.profiles TO anon, authenticated;
GRANT DELETE ON public.profiles TO anon, authenticated;

-- app_sessions 严禁客户端直接访问
REVOKE ALL ON public.app_sessions FROM anon, authenticated;

-- 其余业务表授权（具体行权限全部由 RLS 策略严格拦截）
GRANT SELECT, INSERT, UPDATE, DELETE ON public.buildings           TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.manager_assignments TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.rooms               TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.contracts           TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.bills               TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.meter_readings      TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.repairs             TO anon, authenticated;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.ledger_entries      TO anon, authenticated;

-- RPC 函数执行授权
GRANT EXECUTE ON FUNCTION public.gfb_login_phone(text, text, text) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.gfb_whoami()                      TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.gfb_logout()                      TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.gfb_reset_pin(uuid, text)         TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.gfb_migrate_legacy_json(jsonb)    TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.gfb_migrate_from_store_table()    TO anon, authenticated;

COMMIT;

-- 刷新 PostgREST API 缓存，确保新表与 RPC 立即生效
NOTIFY pgrst, 'reload schema';

-- ============================================================================
-- 【可选】若希望在 SQL Editor 中直接预设主房东账号，可取消下面注释并替换为真实手机号与口令执行：
-- INSERT INTO public.profiles (phone, display_name, role, pin_hash)
-- VALUES ('你的手机号', '主房东', 'landlord', extensions.crypt('你的6位口令', extensions.gen_salt('bf')))
-- ON CONFLICT (phone) DO NOTHING;
-- ============================================================================
