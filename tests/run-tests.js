#!/usr/bin/env node
/*
 * Logic tests for EventLens. Optional: needs Node.js, not needed to use the tool.
 * Usage:  node tests/run-tests.js
 */
'use strict';
const fs = require('fs');
const path = require('path');
const Core = require('../script.js');

let passed = 0; let failed = 0;
function check(name, cond, extra) {
  if (cond) { passed++; console.log('  PASS  ' + name); } else { failed++; console.log('  FAIL  ' + name + (extra ? '  -> ' + extra : '')); }
}

function run(csvText, cfg) {
  const p = Core.parseCsv(csvText);
  if (p.error) return { error: p.error };
  const b = Core.buildEvents(p.rows);
  if (!b.ok) return { error: b.error };
  const r = Core.analyse(b.events, cfg, b.timeInfo);
  return { built: b, result: r };
}
const sample = (f) => fs.readFileSync(path.join(__dirname, '..', 'samples', f), 'utf8');
const names = (r) => r.result.alerts.map((a) => a.name + ' [' + a.severity + ']');
const has = (r, name, sev) => r.result.alerts.some((a) => a.name === name && (!sev || a.severity === sev));

console.log('\n== Sample datasets ==');
let r = run(sample('normal-windows-events.csv'));
check('normal: parses 20 events', r.built && r.built.events.length === 20, r.error);
check('normal: no High findings', !r.result.alerts.some((a) => a.severity === 'High'), names(r).join(', '));
check('normal: no Medium findings', !r.result.alerts.some((a) => a.severity === 'Medium'), names(r).join(', '));
check('normal: no repeated-failure alert (2 stray failures < threshold)', !has(r, 'REPEATED FAILED LOGONS'));
check('normal: at most 1 finding total', r.result.alerts.length <= 1, names(r).join(', '));
console.log('        findings:', names(r).join(' | ') || '(none)');

r = run(sample('failed-logons-only.csv'));
check('failures: Repeated Failed Logons (Medium)', has(r, 'REPEATED FAILED LOGONS', 'Medium'), names(r).join(', '));
check('failures: NOT escalated to password-guessing', !has(r, 'POSSIBLE PASSWORD GUESSING FOLLOWED BY SUCCESS'));
check('failures: 12 failures counted', (r.result.alerts.find((a) => a.rule === 'rule1') || {}).events.length === 12);
check('failures: earlier success is not used', !r.result.alerts.some((a) => a.rule === 'rule2'));

r = run(sample('password-guessing.csv'));
check('guessing: High password-guessing alert', has(r, 'POSSIBLE PASSWORD GUESSING FOLLOWED BY SUCCESS', 'High'), names(r).join(', '));
check('guessing: no duplicate rule-1 alert for same account', !r.result.alerts.some((a) => a.rule === 'rule1'));
const g = r.result.alerts.find((a) => a.rule === 'rule2');
check('guessing: 8 failures + success, account jsmith', g && g.account === 'jsmith' && g.events.length === 9);
check('guessing: score = 10 + 5? + 20 + 10', g && g.score === 40, 'score=' + (g && g.score) + ' ' + JSON.stringify(g && g.scoreItems));
check('guessing: sequence string compressed', g && g.sequence === '4625 \u00d78 \u2192 4624', g && g.sequence);

r = run(sample('account-persistence.csv'));
check('persistence: High New Account Granted Privileges', has(r, 'NEW ACCOUNT GRANTED PRIVILEGES', 'High'), names(r).join(', '));
const p3 = r.result.alerts.find((a) => a.rule === 'rule3');
check('persistence: account temp-admin created by admin01', p3 && p3.account === 'temp-admin' && p3.actor === 'admin01');
check('persistence: no separate standalone 4720/4732 alerts', r.result.alerts.length === 1, names(r).join(', '));
check('persistence: admin summary present', r.result.adminEvents.length === 2);

r = run(sample('audit-log-cleared.csv'));
check('cleared: High Security Audit Log Cleared', has(r, 'SECURITY AUDIT LOG CLEARED', 'High'), names(r).join(', '));
check('cleared: actor admin01', r.result.alerts[0].account === 'admin01');

r = run(sample('suspicious-admin-activity.csv'));
console.log('        findings:', names(r).join(' | '));
check('mixed: password guessing High', has(r, 'POSSIBLE PASSWORD GUESSING FOLLOWED BY SUCCESS', 'High'));
check('mixed: new account granted privileges High', has(r, 'NEW ACCOUNT GRANTED PRIVILEGES', 'High'));
check('mixed: log cleared High', has(r, 'SECURITY AUDIT LOG CLEARED', 'High'));
check('mixed: service from unusual location Medium', has(r, 'SERVICE INSTALLED FROM AN UNUSUAL LOCATION', 'Medium'));
check('mixed: spray hint (other accounts from same IP) in observed text', r.result.alerts.find((a) => a.rule === 'rule2').observed.includes('password spraying'));
check('mixed: admin alerts cross-linked to jsmith failure->success', r.result.alerts.filter((a) => a.related.length).length >= 2);
check('mixed: admin summary lists 4 types', r.result.adminSummary.length === 4, JSON.stringify(r.result.adminSummary));
check('mixed: needInvestigation > 0', r.result.stats.needInvestigation > 0);

console.log('\n== Settings ==');
r = run(sample('failed-logons-only.csv'), { failThreshold: 13 });
check('threshold 13: 12 failures no longer alert', r.result.alerts.length === 0, names(r).join(', '));
r = run(sample('failed-logons-only.csv'), { failThreshold: 12 });
check('threshold 12: exactly 12 failures alert', has(r, 'REPEATED FAILED LOGONS'));
r = run(sample('failed-logons-only.csv'), { windowMinutes: 1 });
check('window 1 minute: spread-out failures do not alert', !has(r, 'REPEATED FAILED LOGONS'), names(r).join(', '));
r = run(sample('failed-logons-only.csv'), { windowMinutes: 1, useWindow: false });
check('window off: counts whole file again', has(r, 'REPEATED FAILED LOGONS'));
r = run(sample('password-guessing.csv'), { windowMinutes: 1 });
check('guessing with 1-minute window: no alert (documented behaviour)', !has(r, 'POSSIBLE PASSWORD GUESSING FOLLOWED BY SUCCESS'));

console.log('\n== Column name tolerance ==');
const ps = [
  'TimeCreated,Id,LevelDisplayName,ProviderName,MachineName,Message',
  '"2026-10-14T14:00:00","1102","Information","Microsoft-Windows-Eventlog","PC1","The audit log was cleared.\r\n\r\nSubject:\r\n\tAccount Name:\tadmin01"'
].join('\r\n');
r = run(ps);
check('PowerShell-style headers (TimeCreated, Id, ProviderName, MachineName)', r.result && has(r, 'SECURITY AUDIT LOG CLEARED') && r.built.events[0].f.account === 'admin01', r.error);
r = run('#TYPE System.Diagnostics.Eventing.Reader.EventLogRecord\r\n' + ps);
check('#TYPE first line is skipped', r.result && r.result.alerts.length === 1, r.error);
r = run('\ufeffevent_id;date_and_time;message\n1102;2026-10-14 10:00:00;"cleared\nSubject:\nAccount Name: x"');
check('semicolon delimiter, event_id, BOM', r.result && r.built.events.length === 1 && r.built.mapping.eventId === 'event_id', r.error);
r = run('EventID,Date and Time\n4625,10/14/2026 1:00:00 PM\n4625,10/14/2026 1:00:10 PM');
check('EventID with no Message: parses, warns', r.built && r.built.warnings.some((w) => /No Message column/.test(w)), r.error);
check('no Message: failures grouped as unknown account (threshold 5 not met)', r.result.alerts.length === 0);
const unk = ['Event ID,Date and Time'].concat(Array(6).fill('4625,10/14/2026 1:00:00 PM')).join('\n');
r = run(unk);
check('no Message, 6 failures: Low hint only, never High', r.result.alerts.length === 1 && r.result.alerts[0].severity === 'Low', names(r).join(','));

console.log('\n== Errors and malformed input ==');
r = run('Level,Date and Time,Source\nInformation,10/14/2026 1:00:00 PM,x');
check('missing Event ID column: clear error listing columns', r.error && /Event ID column/.test(r.error) && /Level/.test(r.error), r.error);
r = run('');
check('empty file: clear error', r.error && /empty/i.test(r.error), r.error);
r = run('Event ID,Message\n4624,"unclosed quote here\n4625,x');
check('unterminated quote: fails safely', r.error && /malformed/i.test(r.error), r.error);
r = run('Event ID,Message\nabc,hello\n,world');
check('no numeric Event IDs: clear error', r.error && /No usable rows/.test(r.error), r.error);
r = run('Event ID,Message\n4624\n4625,a,b,c,d');
check('ragged rows tolerated with warning', r.built && r.built.warnings.some((w) => /different number of columns/.test(w)), r.error);
r = run('Event ID,Message\n9999,something\n4624,x');
check('unknown Event ID kept as "Other event"', r.built && r.built.events[0].name === 'Other event' && r.built.unrecognisedIds.includes(9999));
const evtx = Buffer.from('ElfFile\0' + 'x'.repeat(50), 'binary');
check('.evtx magic bytes rejected with explanation', /evtx/.test(Core.decodeBuffer(evtx).error || ''));
const bin = Buffer.alloc(500); for (let i = 0; i < 500; i++) bin[i] = i % 7;
check('binary garbage rejected', !!Core.decodeBuffer(bin).error);
const u16 = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from('Event ID,Message\r\n1102,hi\r\n', 'utf16le')]);
const d16 = Core.decodeBuffer(u16);
check('UTF-16 LE with BOM decodes', d16.text && /1102/.test(d16.text), d16.error);
check('very long line / many rows does not crash', (() => { const big = 'Event ID,Message\n' + '4624,x\n'.repeat(50000); const rr = run(big); return rr.built && rr.built.events.length === 50000; })());

console.log('\n== Timestamps ==');
const mk = (ts, id) => 'Event ID,Date and Time\n' + ts.map((t) => id + ',' + t).join('\n');
r = run(mk(['14/10/2026 13:00:00', '15/10/2026 13:00:00'], 4624));
check('day-first dates (14/10) detected', r.built.timeInfo.order === 'DMY' && r.built.timeInfo.reliable);
r = run(mk(['10/14/2026 1:00:00 PM', '10/15/2026 1:00:00 PM'], 4624));
check('month-first dates (10/14) detected', r.built.timeInfo.order === 'MDY');
r = run(mk(['03/04/2026 1:00:00 PM', '03/05/2026 1:00:00 PM'], 4624));
check('ambiguous dates: assumed + warned', r.built.timeInfo.order === 'MDY-assumed' && r.built.warnings.some((w) => /ambiguous/.test(w)));
r = run(mk(['14/10/2026 1:00:00 PM', '10/14/2026 1:00:00 PM'], 4624));
check('conflicting formats: time analysis disabled with warning', !r.built.timeInfo.reliable && r.built.warnings.some((w) => /inconsistent/.test(w)));
r = run(mk(['yesterday', 'tomorrow'], 4624));
check('unreadable dates: no crash, warning', r.built && !r.built.timeInfo.reliable && r.built.warnings.length > 0);
r = run(mk(['10/14/2026 1:00:00\u202fPM'], 4624));
check('narrow no-break space before PM handled (Windows 11)', r.built.timeInfo.reliable && Core.fmtTime(r.built.events[0].time) === '2026-10-14 13:00:00', Core.fmtTime(r.built.events[0].time));
r = run(mk(['10/14/2026 12:30:00 AM'], 4624));
check('12:30 AM = 00:30', Core.fmtTime(r.built.events[0].time) === '2026-10-14 00:30:00');

// Newest-first export, identical timestamps: failures then success must still be ordered correctly.
const tie = ['Event ID,Date and Time,Message'];
const failMsg = (a) => '"Account For Which Logon Failed:\nAccount Name: ' + a + '\nNetwork Information:\nSource Network Address: 10.0.0.9"';
const okMsg = (a) => '"New Logon:\nAccount Name: ' + a + '\nNetwork Information:\nSource Network Address: 10.0.0.9"';
tie.push('4624,10/14/2026 1:00:05 PM,' + okMsg('tuser')); // newest first: success first in file
for (let i = 0; i < 6; i++) tie.push('4625,10/14/2026 1:00:0' + (4 - Math.min(i, 4)) + ' PM,' + failMsg('tuser'));
tie.push('4625,10/14/2026 12:59:50 PM,' + failMsg('tuser'));
r = run(tie.join('\n'));
check('newest-first file: failures-then-success correlated by timestamp not file order', r.result && r.result.alerts.some((a) => a.rule === 'rule2'), names(r).join(','));

console.log('\n== Message parsing ==');
const m4732 = Core.parseSections('A member was added.\r\n\r\nSubject:\r\n\tAccount Name:\tadmin01\r\nMember:\r\n\tSecurity ID:\tLAB\\bob\r\n\tAccount Name:\tCN=bob,CN=Users,DC=lab,DC=local\r\nGroup:\r\n\tGroup Name:\tDomain Admins');
check('sections split into Subject/Member/Group', m4732.map((s) => s.title).join('|') === '|subject|member|group');
check('cleanAccount strips CN= and domain', Core.cleanAccount('CN=bob,CN=Users,DC=lab') === 'bob' && Core.cleanAccount('LAB\\jsmith') === 'jsmith' && Core.cleanAccount('-') === '');
const g28 = run('Event ID,Date and Time,Message\n4720,10/14/2026 1:00:00 PM,"Subject:\nAccount Name: admin1\nNew Account:\nAccount Name: newbie"\n4728,10/14/2026 1:05:00 PM,"Subject:\nAccount Name: admin1\nMember:\nSecurity ID: S-1-5-21-1\nAccount Name: CN=newbie,CN=Users,DC=lab\nGroup:\nGroup Name: Domain Admins"');
check('4728 member via CN= matches 4720 account -> rule 3 High', has(g28, 'NEW ACCOUNT GRANTED PRIVILEGES', 'High'), names(g28).join(','));
const gNon = run('Event ID,Date and Time,Message\n4720,10/14/2026 1:00:00 PM,"Subject:\nAccount Name: admin1\nNew Account:\nAccount Name: newbie"\n4732,10/14/2026 1:05:00 PM,"Subject:\nAccount Name: admin1\nMember:\nSecurity ID: LAB\\newbie\nAccount Name: -\nGroup:\nGroup Name: Remote Desktop Users"');
check('non-privileged group: correlated but Medium (not automatically High)', has(gNon, 'NEW ACCOUNT GRANTED PRIVILEGES', 'Medium'), names(gNon).join(','));
const gSid = run('Event ID,Date and Time,Message\n4732,10/14/2026 1:05:00 PM,"Subject:\nAccount Name: admin1\nMember:\nSecurity ID: S-1-5-21-1-2-3-1001\nAccount Name: -\nGroup:\nGroup Name: Administrators"');
check('unresolved SID member: standalone privileged group change, flagged', has(gSid, 'PRIVILEGED GROUP MEMBERSHIP CHANGE', 'High') && gSid.built.events[0].f.flags.length === 1);
check('privileged group name detection', Core.isPrivilegedGroup('Domain Admins') && Core.isPrivilegedGroup('Backup Operators') && !Core.isPrivilegedGroup('Remote Desktop Users'));

console.log('\n== PowerShell 4104 ==');
const enc = 'powershell.exe -NoProfile -EncodedCommand ' + 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA';
const p1 = run('Event ID,User,Message\n4104,LAB\\bob,"Creating Scriptblock text (1 of 1):\nGet-Process | Sort-Object CPU\n\nScriptBlock ID: abc"');
check('plain 4104 is NOT flagged (PowerShell is not suspicious)', p1.result.alerts.length === 0);
const p2 = run('Event ID,User,Message\n4104,LAB\\bob,"Creating Scriptblock text (1 of 1):\n' + enc + '\n\nScriptBlock ID: abc"');
check('encoded 4104 flagged Medium, wording avoids claiming malicious', has(p2, 'POWERSHELL SCRIPT BLOCK WITH ENCODED OR OBFUSCATED CONTENT', 'Medium') && /not suspicious/.test(p2.result.alerts[0].observed));
check('obfuscation detector', Core.detectObfuscation('IEX ([char]72+[char]101+[char]108+[char]108+[char]111+[char]33)').length > 0 && Core.detectObfuscation('Get-ChildItem C:\\').length === 0);

console.log('\n== 4688 context ==');
const pr = run(sample('normal-windows-events.csv'));
const e688 = pr.built.events.find((e) => e.eventId === 4688);
check('4688: process, parent, command line, account extracted', e688 && /notepad/.test(e688.f.process) && /explorer/.test(e688.f.parent) && e688.f.command.length > 0 && e688.f.account === 'asmith', JSON.stringify(e688 && e688.f));

console.log('\n== Injection safety (logic layer) ==');
const xss = '<img src=x onerror=alert(1)>';
r = run('Event ID,Date and Time,Message\n4625,10/14/2026 1:00:00 PM,"Account For Which Logon Failed:\nAccount Name: ' + xss.replace(/"/g, '""') + '"');
check('hostile account name is carried as plain data (escaping is done at render time)', r.built.events[0].f.account === xss);

console.log('\n' + passed + ' passed, ' + failed + ' failed');
process.exit(failed ? 1 : 0);
