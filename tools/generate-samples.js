#!/usr/bin/env node
/*
 * OPTIONAL maintainer tool. You do NOT need this to run EventLens.
 *
 * It regenerates:
 *   samples/*.csv       - the fictional sample files you can upload manually
 *   sample-data.js      - the same data embedded in JavaScript so the demo
 *                         buttons work when you double-click index.html
 *                         (browsers block fetching local files from file://)
 *
 * Usage:  node tools/generate-samples.js
 *
 * Everything here is FICTIONAL. Names, computers and IPs do not exist.
 * IPs are from private ranges (192.168.x.x, 10.x.x.x).
 * Exports are written newest-first, like Windows Event Viewer does.
 */
'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const HOST = 'WS-LAB-01';
const DOMAIN = 'LAB';
const SRC = 'Microsoft-Windows-Security-Auditing';

/* ---------- message builders (modelled on real Windows message layout) ---------- */

const logon = (acct, type, ip, ws) => [
  'An account was successfully logged on.', '',
  'Subject:', '\tSecurity ID:\t\tSYSTEM', '\tAccount Name:\t\t' + HOST + '$', '\tAccount Domain:\t\t' + DOMAIN, '\tLogon ID:\t\t0x3E7', '',
  'Logon Information:', '\tLogon Type:\t\t' + type, '\tRestricted Admin Mode:\t-', '',
  'New Logon:', '\tSecurity ID:\t\t' + DOMAIN + '\\' + acct, '\tAccount Name:\t\t' + acct, '\tAccount Domain:\t\t' + DOMAIN, '\tLogon ID:\t\t0x1A2B3C', '',
  'Network Information:', '\tWorkstation Name:\t' + (ws || HOST), '\tSource Network Address:\t' + (ip || '-'), '\tSource Port:\t\t' + (ip ? '49822' : '-')
].join('\r\n');

const failure = (acct, type, ip, ws) => [
  'An account failed to log on.', '',
  'Subject:', '\tSecurity ID:\t\tNULL SID', '\tAccount Name:\t\t-', '\tAccount Domain:\t\t-', '\tLogon ID:\t\t0x0', '',
  'Logon Type:\t\t\t' + type, '',
  'Account For Which Logon Failed:', '\tSecurity ID:\t\tNULL SID', '\tAccount Name:\t\t' + acct, '\tAccount Domain:\t\t' + DOMAIN, '',
  'Failure Information:', '\tFailure Reason:\t\tUnknown user name or bad password.', '\tStatus:\t\t\t0xC000006D', '\tSub Status:\t\t0xC000006A', '',
  'Network Information:', '\tWorkstation Name:\t' + (ws || '-'), '\tSource Network Address:\t' + (ip || '-'), '\tSource Port:\t\t51234'
].join('\r\n');

const created = (by, acct) => [
  'A user account was created.', '',
  'Subject:', '\tSecurity ID:\t\t' + DOMAIN + '\\' + by, '\tAccount Name:\t\t' + by, '\tAccount Domain:\t\t' + DOMAIN, '\tLogon ID:\t\t0x2F4E1', '',
  'New Account:', '\tSecurity ID:\t\t' + HOST + '\\' + acct, '\tAccount Name:\t\t' + acct, '\tAccount Domain:\t\t' + HOST, '',
  'Attributes:', '\tSAM Account Name:\t' + acct, '\tDisplay Name:\t\t<value not set>'
].join('\r\n');

const deleted = (by, acct) => [
  'A user account was deleted.', '',
  'Subject:', '\tSecurity ID:\t\t' + DOMAIN + '\\' + by, '\tAccount Name:\t\t' + by, '\tAccount Domain:\t\t' + DOMAIN, '\tLogon ID:\t\t0x2F4E1', '',
  'Target Account:', '\tSecurity ID:\t\t' + HOST + '\\' + acct, '\tAccount Name:\t\t' + acct, '\tAccount Domain:\t\t' + HOST
].join('\r\n');

const groupAdd = (by, member, group, isLocal) => [
  isLocal ? 'A member was added to a security-enabled local group.' : 'A member was added to a security-enabled global group.', '',
  'Subject:', '\tSecurity ID:\t\t' + DOMAIN + '\\' + by, '\tAccount Name:\t\t' + by, '\tAccount Domain:\t\t' + DOMAIN, '\tLogon ID:\t\t0x2F4E1', '',
  'Member:', '\tSecurity ID:\t\t' + HOST + '\\' + member, '\tAccount Name:\t\t-', '',
  'Group:', '\tSecurity ID:\t\t' + (isLocal ? 'BUILTIN\\' : DOMAIN + '\\') + group, '\tGroup Name:\t\t' + group, '\tGroup Domain:\t\t' + (isLocal ? 'Builtin' : DOMAIN)
].join('\r\n');

const cleared = (by) => [
  'The audit log was cleared.', '',
  'Subject:', '\tSecurity ID:\t' + DOMAIN + '\\' + by, '\tAccount Name:\t' + by, '\tDomain Name:\t' + DOMAIN, '\tLogon ID:\t0x2F4E1'
].join('\r\n');

const proc = (acct, exe, parent, cmd) => [
  'A new process has been created.', '',
  'Creator Subject:', '\tSecurity ID:\t\t' + DOMAIN + '\\' + acct, '\tAccount Name:\t\t' + acct, '\tAccount Domain:\t\t' + DOMAIN, '\tLogon ID:\t\t0x1A2B3C', '',
  'Process Information:', '\tNew Process ID:\t\t0x1F40', '\tNew Process Name:\t' + exe, '\tToken Elevation Type:\tTokenElevationTypeDefault (1)',
  '\tCreator Process ID:\t0x0A10', '\tCreator Process Name:\t' + parent, '\tProcess Command Line:\t' + cmd
].join('\r\n');

const service = (name, file) => [
  'A service was installed in the system.', '',
  'Service Name:  ' + name, 'Service File Name:  ' + file, 'Service Type:  user mode service', 'Service Start Type:  auto start', 'Service Account:  LocalSystem'
].join('\r\n');

/* ---------- event constructors: [time, keywords, source, id, task, computer, message] ---------- */

const ev = {
  logon: (t, acct, type, ip, ws) => [t, 'Audit Success', SRC, 4624, 'Logon', HOST, logon(acct, type, ip, ws)],
  fail: (t, acct, type, ip, ws) => [t, 'Audit Failure', SRC, 4625, 'Logon', HOST, failure(acct, type, ip, ws)],
  create: (t, by, acct) => [t, 'Audit Success', SRC, 4720, 'User Account Management', HOST, created(by, acct)],
  delete: (t, by, acct) => [t, 'Audit Success', SRC, 4726, 'User Account Management', HOST, deleted(by, acct)],
  addLocal: (t, by, member, group) => [t, 'Audit Success', SRC, 4732, 'Security Group Management', HOST, groupAdd(by, member, group, true)],
  clear: (t, by) => [t, 'Audit Success', 'Microsoft-Windows-Eventlog', 1102, 'Log clear', HOST, cleared(by)],
  proc: (t, acct, exe, parent, cmd) => [t, 'Audit Success', SRC, 4688, 'Process Creation', HOST, proc(acct, exe, parent, cmd)],
  svc: (t, name, file) => ['' + t, 'Classic', 'Service Control Manager', 7045, 'None', HOST, service(name, file)]
};

/* ---------- time helper: "10/14/2026 3:05:12 PM" (US format; 14 > 12 makes the order unambiguous) ---------- */

function T(h24, m, s) {
  const ampm = h24 >= 12 ? 'PM' : 'AM';
  const h12 = h24 % 12 === 0 ? 12 : h24 % 12;
  return '10/14/2026 ' + h12 + ':' + String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0') + ' ' + ampm;
}

/* ---------- scenarios ---------- */

const scenarios = {};

scenarios.normal = {
  file: 'normal-windows-events.csv',
  expect: 'Mostly informational activity.',
  events: (() => {
    const e = [];
    e.push(ev.logon(T(8, 2, 14), 'asmith', 2, '-', HOST));
    e.push(ev.proc(T(8, 2, 40), 'asmith', 'C:\\Windows\\System32\\notepad.exe', 'C:\\Windows\\explorer.exe', '"C:\\Windows\\System32\\notepad.exe"'));
    e.push(ev.logon(T(8, 15, 5), 'bjones', 2, '-', 'WS-LAB-02'));
    e.push(ev.proc(T(8, 16, 1), 'bjones', 'C:\\Windows\\System32\\calc.exe', 'C:\\Windows\\explorer.exe', '"C:\\Windows\\System32\\calc.exe"'));
    e.push(ev.logon(T(8, 31, 47), 'cnguyen', 3, '192.168.10.31', 'WS-LAB-03'));
    e.push(ev.fail(T(8, 44, 12), 'asmith', 2, '-', HOST));
    e.push(ev.logon(T(8, 44, 31), 'asmith', 2, '-', HOST));
    e.push(ev.proc(T(9, 5, 3), 'asmith', 'C:\\Windows\\System32\\mmc.exe', 'C:\\Windows\\explorer.exe', '"C:\\Windows\\System32\\mmc.exe" "C:\\Windows\\System32\\eventvwr.msc"'));
    e.push(ev.logon(T(9, 20, 8), 'svc-backup', 5, '-', HOST));
    e.push(ev.logon(T(9, 48, 22), 'bjones', 3, '192.168.10.22', 'WS-LAB-02'));
    e.push(ev.fail(T(10, 3, 9), 'cnguyen', 3, '192.168.10.31', 'WS-LAB-03'));
    e.push(ev.logon(T(10, 3, 40), 'cnguyen', 3, '192.168.10.31', 'WS-LAB-03'));
    e.push(ev.proc(T(10, 12, 55), 'cnguyen', 'C:\\Windows\\System32\\taskmgr.exe', 'C:\\Windows\\explorer.exe', '"C:\\Windows\\System32\\taskmgr.exe"'));
    e.push(ev.logon(T(10, 30, 2), 'admin01', 2, '-', HOST));
    e.push(ev.proc(T(10, 31, 18), 'admin01', 'C:\\Windows\\System32\\mmc.exe', 'C:\\Windows\\explorer.exe', '"C:\\Windows\\System32\\mmc.exe" "C:\\Windows\\System32\\lusrmgr.msc"'));
    e.push(ev.delete(T(10, 36, 49), 'admin01', 'old-test-user'));
    e.push(ev.logon(T(11, 2, 33), 'asmith', 2, '-', HOST));
    e.push(ev.proc(T(11, 10, 20), 'asmith', 'C:\\Windows\\System32\\notepad.exe', 'C:\\Windows\\explorer.exe', '"C:\\Windows\\System32\\notepad.exe" C:\\Users\\asmith\\notes.txt'));
    e.push(ev.logon(T(11, 45, 0), 'bjones', 3, '192.168.10.22', 'WS-LAB-02'));
    e.push(ev.logon(T(12, 5, 10), 'cnguyen', 3, '192.168.10.31', 'WS-LAB-03'));
    return e;
  })()
};

scenarios.failures = {
  file: 'failed-logons-only.csv',
  expect: 'Repeated Failed Logons alert.',
  events: (() => {
    const e = [];
    const ip = '192.168.50.77'; const ws = 'LAB-KIOSK-07';
    e.push(ev.logon(T(13, 40, 1), 'asmith', 2, '-', HOST));
    e.push(ev.logon(T(13, 52, 18), 'jsmith', 3, '192.168.10.45', 'WS-LAB-04')); // a success BEFORE the failures: does not count
    const secs = [[14, 2, 3], [14, 2, 19], [14, 2, 41], [14, 3, 2], [14, 3, 24], [14, 3, 50], [14, 4, 11], [14, 4, 33], [14, 4, 58], [14, 5, 20], [14, 5, 44], [14, 6, 9]];
    secs.forEach((s) => e.push(ev.fail(T(...s), 'jsmith', 3, ip, ws)));
    e.push(ev.logon(T(14, 20, 12), 'bjones', 2, '-', 'WS-LAB-02'));
    e.push(ev.logon(T(14, 31, 5), 'asmith', 2, '-', HOST));
    return e;
  })()
};

scenarios.guessing = {
  file: 'password-guessing.csv',
  expect: 'Possible Password Guessing Followed By Success alert.',
  events: (() => {
    const e = [];
    const ip = '192.168.50.77'; const ws = 'LAB-KIOSK-07';
    e.push(ev.logon(T(14, 0, 31), 'asmith', 2, '-', HOST));
    e.push(ev.proc(T(14, 6, 2), 'asmith', 'C:\\Windows\\System32\\notepad.exe', 'C:\\Windows\\explorer.exe', '"C:\\Windows\\System32\\notepad.exe"'));
    const secs = [[14, 14, 3], [14, 14, 29], [14, 14, 58], [14, 15, 21], [14, 15, 47], [14, 16, 12], [14, 16, 44], [14, 17, 41]];
    secs.forEach((s) => e.push(ev.fail(T(...s), 'jsmith', 3, ip, ws)));
    e.push(ev.logon(T(14, 18, 20), 'jsmith', 3, ip, ws));
    e.push(ev.proc(T(14, 19, 2), 'jsmith', 'C:\\Windows\\System32\\cmd.exe', 'C:\\Windows\\explorer.exe', '"C:\\Windows\\System32\\cmd.exe"'));
    e.push(ev.logon(T(14, 40, 9), 'bjones', 2, '-', 'WS-LAB-02'));
    return e;
  })()
};

scenarios.privilege = {
  file: 'account-persistence.csv',
  expect: 'New Account Granted Privileges alert.',
  events: (() => {
    const e = [];
    e.push(ev.logon(T(23, 30, 4), 'admin01', 10, '10.10.1.5', 'ADMIN-PC-01'));
    e.push(ev.proc(T(23, 38, 40), 'admin01', 'C:\\Windows\\System32\\net.exe', 'C:\\Windows\\System32\\cmd.exe', 'net user temp-admin * /add'));
    e.push(ev.create(T(23, 42, 15), 'admin01', 'temp-admin'));
    e.push(ev.addLocal(T(23, 44, 2), 'admin01', 'temp-admin', 'Administrators'));
    e.push(ev.logon(T(23, 51, 33), 'asmith', 2, '-', HOST));
    return e;
  })()
};

scenarios.cleared = {
  file: 'audit-log-cleared.csv',
  expect: 'Security Audit Log Cleared alert.',
  events: (() => {
    const e = [];
    e.push(ev.logon(T(16, 1, 12), 'admin01', 10, '10.10.1.5', 'ADMIN-PC-01'));
    e.push(ev.proc(T(16, 4, 30), 'admin01', 'C:\\Windows\\System32\\wevtutil.exe', 'C:\\Windows\\System32\\cmd.exe', 'wevtutil cl Security'));
    e.push(ev.clear(T(16, 4, 31), 'admin01'));
    e.push(ev.logon(T(16, 20, 8), 'asmith', 2, '-', HOST));
    return e;
  })()
};

scenarios.mixed = {
  file: 'suspicious-admin-activity.csv',
  expect: 'Several correlated findings.',
  events: (() => {
    const e = [];
    const ip = '192.168.50.77'; const ws = 'LAB-KIOSK-07';
    e.push(ev.logon(T(21, 55, 10), 'asmith', 2, '-', HOST));
    // spray pattern: same source IP touches other accounts too
    e.push(ev.fail(T(22, 1, 4), 'bwilson', 3, ip, ws));
    e.push(ev.fail(T(22, 1, 30), 'dpatel', 3, ip, ws));
    e.push(ev.fail(T(22, 1, 55), 'bwilson', 3, ip, ws));
    const secs = [[22, 2, 20], [22, 2, 41], [22, 3, 6], [22, 3, 29], [22, 3, 52], [22, 4, 15], [22, 4, 37], [22, 5, 1], [22, 5, 24]];
    secs.forEach((s) => e.push(ev.fail(T(...s), 'jsmith', 3, ip, ws)));
    e.push(ev.logon(T(22, 6, 2), 'jsmith', 3, ip, ws));
    e.push(ev.proc(T(22, 8, 10), 'jsmith', 'C:\\Windows\\System32\\cmd.exe', 'C:\\Windows\\explorer.exe', '"C:\\Windows\\System32\\cmd.exe"'));
    e.push(ev.create(T(22, 12, 44), 'jsmith', 'helpdesk-tmp'));
    e.push(ev.addLocal(T(22, 13, 27), 'jsmith', 'helpdesk-tmp', 'Administrators'));
    e.push(ev.svc(T(22, 16, 5), 'UpdateHelper', 'C:\\Users\\Public\\uh.exe'));
    e.push(ev.clear(T(22, 21, 38), 'jsmith'));
    e.push(ev.logon(T(22, 40, 2), 'bjones', 2, '-', 'WS-LAB-02'));
    return e;
  })()
};

/* ---------- write files ---------- */

const csvCell = (v) => '"' + String(v).replace(/"/g, '""') + '"';
const HEADER = ['Keywords', 'Date and Time', 'Source', 'Event ID', 'Task Category', 'Computer', 'Message'];

function toCsv(events) {
  // Event Viewer exports newest-first, so reverse our oldest-first lists.
  const lines = [HEADER.map(csvCell).join(',')];
  events.slice().reverse().forEach((r) => lines.push([r[1], r[0]].concat(r.slice(2)).map(csvCell).join(',')));
  return lines.join('\r\n') + '\r\n';
}

fs.mkdirSync(path.join(ROOT, 'samples'), { recursive: true });
const embedded = {};
for (const key of Object.keys(scenarios)) {
  const s = scenarios[key];
  const csv = toCsv(s.events);
  fs.writeFileSync(path.join(ROOT, 'samples', s.file), csv);
  embedded[key] = { file: s.file, csv };
  console.log('wrote samples/' + s.file + ' (' + s.events.length + ' events)');
}
const js = '/* AUTO-GENERATED by tools/generate-samples.js. Do not edit by hand.\n' +
  ' * Fictional demo data only. Embedded so the demo buttons work from file://. */\n' +
  'window.EVENTLENS_SAMPLES = ' + JSON.stringify(embedded, null, 1) + ';\n';
fs.writeFileSync(path.join(ROOT, 'sample-data.js'), js);
console.log('wrote sample-data.js');
