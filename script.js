/*
 * EventLens - Windows Security Event Log Triage Tool
 * Educational SOC triage helper. Everything runs locally in the browser.
 *
 * This file has two halves:
 *   1. "Core"  - CSV parsing, Event ID recognition, correlation rules, scoring.
 *                Pure logic, no DOM access (so it can be tested from Node).
 *   2. "UI"    - draws the page. Every piece of text that comes from an uploaded
 *                file is inserted with textContent / createTextNode, NEVER innerHTML.
 *
 * There are no network calls in this file. No fetch, no XMLHttpRequest, no
 * WebSocket, no beacons, no analytics, no cookies, no storage.
 */
(function (root) {
  'use strict';

  /* ------------------------------------------------------------------ */
  /* 1. CONSTANTS AND KNOWLEDGE BASE                                     */
  /* ------------------------------------------------------------------ */

  const DEFAULTS = { failThreshold: 5, windowMinutes: 10, useWindow: true };
  const LIMITS = { maxBytes: 50 * 1024 * 1024, maxRows: 250000, maxMessageChars: 6000 };
  const PRIVILEGE_QUICK_MINUTES = 60; // "quickly" in rule 3 = within 60 minutes

  const SEVERITIES = ['Informational', 'Low', 'Medium', 'High'];
  const SEV_RANK = { Informational: 0, Low: 1, Medium: 2, High: 3 };
  const maxSeverity = (a, b) => (SEV_RANK[a] >= SEV_RANK[b] ? a : b);

  // Event types ("categories") used by the Event type filter.
  const CATEGORIES = [
    'Authentication',
    'Account management',
    'Privilege / group change',
    'Audit log tampering',
    'Process activity',
    'PowerShell',
    'Service installation',
    'Other'
  ];

  // Header names are lower-cased and stripped of every non-alphanumeric
  // character before comparing, so "Event ID", "EventID" and "event_id"
  // all become "eventid". The order inside each list is the priority order.
  const COLUMN_ALIASES = {
    eventId: ['eventid', 'id', 'eventcode', 'eventidentifier', 'eventidnumber'],
    time: ['dateandtime', 'datetime', 'timecreated', 'timestamp', 'timegenerated', 'eventtime', 'systemtime', 'time', 'date', 'created'],
    level: ['level', 'leveldisplayname', 'levelname', 'severity'],
    source: ['source', 'providername', 'provider', 'sourcename'],
    task: ['taskcategory', 'taskdisplayname', 'task', 'category'],
    user: ['user', 'username', 'userid'],
    computer: ['computer', 'computername', 'machinename', 'hostname', 'host', 'device'],
    keywords: ['keywords', 'keyworddisplaynames', 'auditresult'],
    message: ['message', 'eventmessage', 'description', 'details']
  };
  const FIELD_LABELS = {
    eventId: 'Event ID', time: 'Date and time', level: 'Level', source: 'Source', task: 'Task category',
    user: 'User', computer: 'Computer', keywords: 'Keywords', message: 'Message'
  };

  const LOGON_TYPES = {
    '2': 'Interactive (keyboard at the machine)',
    '3': 'Network (e.g. file share, remote service)',
    '4': 'Batch (scheduled task)',
    '5': 'Service',
    '7': 'Unlock',
    '8': 'NetworkCleartext',
    '9': 'NewCredentials (runas /netonly)',
    '10': 'RemoteInteractive (Remote Desktop)',
    '11': 'CachedInteractive'
  };

  // Group names that deserve extra attention when someone is added to them.
  const PRIVILEGED_GROUP_RE = /admin|operators|group policy creator|dnsadmins/i;
  const isPrivilegedGroup = (name) => !!name && PRIVILEGED_GROUP_RE.test(name);

  // The plain-English knowledge base. One entry per supported Event ID.
  const CATALOG = {
    4624: {
      name: 'Successful logon', category: 'Authentication', severity: 'Informational',
      plain: 'A Windows account logged on successfully.',
      why: 'Successful logons are normal and happen constantly. They matter as context: who logged on, from where, and what happened just before and after.',
      benign: 'Almost always normal user or system activity.',
      steps: ['Note the account, logon type and source IP/workstation.', 'Ask: were there failed logons just before this?', 'Look at what the account did afterwards.']
    },
    4625: {
      name: 'Failed logon', category: 'Authentication', severity: 'Informational',
      plain: 'A logon attempt failed (wrong password, unknown user, locked account and so on).',
      why: 'One failure is usually noise. Many failures for one account, or from one source, can indicate password guessing.',
      benign: 'Mistyped or forgotten password, or an application using an old saved password.',
      steps: ['Check how many failures there are and over what time.', 'Identify the source IP/workstation.', 'Check whether a success follows.']
    },
    4688: {
      name: 'Process created', category: 'Process activity', severity: 'Informational',
      plain: 'A program was started. Needs the "Audit Process Creation" policy; command lines need an extra policy.',
      why: 'Shows what ran, who ran it and (if enabled) its command line. Version 1 of this tool only displays it as context.',
      benign: 'Normal programs start all the time.',
      steps: ['Look at the process name, parent process and command line.', 'Ask whether this program is expected for this user.']
    },
    4720: {
      name: 'User account created', category: 'Account management', severity: 'Medium',
      plain: 'A new Windows user account was created.',
      why: 'Attackers sometimes create accounts to keep access (persistence). Every new account should be traceable to an approved request.',
      benign: 'A new starter, a service account, or lab/test setup by an administrator.',
      steps: ['Confirm the creation was authorised (ticket or change record).', 'Identify who created it (the "Subject" account).', 'Check what the new account has done since.']
    },
    4726: {
      name: 'User account deleted', category: 'Account management', severity: 'Low',
      plain: 'A user account was deleted.',
      why: 'Deletion can be routine clean-up, or an attempt to remove traces of a short-lived account.',
      benign: 'Leaver clean-up, removing test accounts, routine housekeeping.',
      steps: ['Confirm the deletion was authorised.', 'Check whether the account was recently created.', 'Check who performed the deletion.']
    },
    4728: {
      name: 'Member added to global security group', category: 'Privilege / group change', severity: 'Medium',
      plain: 'An account was added to a global (domain-level) security group.',
      why: 'Group membership controls access. Additions to privileged groups (for example Domain Admins) are a classic privilege-escalation step.',
      benign: 'Normal role changes, onboarding, or access requests handled by IT.',
      steps: ['Identify the group and the added member.', 'Confirm there was an approved request.', 'Identify who made the change.']
    },
    4732: {
      name: 'Member added to local security group', category: 'Privilege / group change', severity: 'Medium',
      plain: 'An account was added to a local security group on this machine (for example Administrators).',
      why: 'Local Administrators membership gives full control of the machine, so unexpected additions deserve a look.',
      benign: 'IT granting temporary admin rights or setting up a machine.',
      steps: ['Identify the group and the added member.', 'Confirm there was an approved request.', 'Identify who made the change.']
    },
    1102: {
      name: 'Security audit log cleared', category: 'Audit log tampering', severity: 'High',
      plain: 'The Windows Security audit log was cleared.',
      why: 'This event means the Windows Security audit log was cleared. This can happen during legitimate maintenance, but because attackers may clear logs to remove evidence, it should normally be investigated.',
      benign: 'Planned maintenance, a lab being reset, or an administrator freeing disk space.',
      steps: ['Identify who cleared the log (the Subject account).', 'Check change and maintenance records.', 'Review the events immediately before the clear (if you have another copy).', 'Check whether logs are forwarded to a central store.']
    },
    4104: {
      name: 'PowerShell script block logged', category: 'PowerShell', severity: 'Informational',
      plain: 'PowerShell recorded the text of a script block it executed.',
      why: 'PowerShell script block logging can provide valuable visibility into commands and scripts executed on the endpoint.',
      benign: 'Administrators and software routinely run PowerShell. PowerShell itself is not suspicious.',
      steps: ['Read the script text.', 'Ask whether this user normally runs PowerShell.', 'Look at the events around it.']
    },
    7045: {
      name: 'Service installed', category: 'Service installation', severity: 'Low',
      plain: 'A new Windows service was installed (this event lives in the System log).',
      why: 'Creating a new Windows service can be legitimate software installation or potentially persistence-related activity.',
      benign: 'Software installs, driver or agent installs, updates.',
      steps: ['Check the service name and file path.', 'Is the path a normal install location?', 'Was software being installed at that time?']
    }
  };
  const REFERENCE_ORDER = [4624, 4625, 4688, 4720, 4726, 4728, 4732, 1102, 4104, 7045];

  /* ------------------------------------------------------------------ */
  /* 2. CSV PARSING                                                      */
  /* ------------------------------------------------------------------ */

  // Turn raw bytes into text. Handles UTF-8 (with/without BOM) and UTF-16.
  function decodeBuffer(buf) {
    const b = new Uint8Array(buf);
    if (b.length >= 8 && String.fromCharCode(...b.slice(0, 7)) === 'ElfFile') {
      return { error: 'This looks like a raw .evtx file. Version 1 only reads CSV exports (see "How to get your logs" on this page).' };
    }
    let enc = 'utf-8';
    if (b[0] === 0xff && b[1] === 0xfe) enc = 'utf-16le';
    else if (b[0] === 0xfe && b[1] === 0xff) enc = 'utf-16be';
    else if (b.length > 3 && b[1] === 0 && b[3] === 0) enc = 'utf-16le';
    const text = new TextDecoder(enc, { fatal: false }).decode(b);
    // A text export should contain almost no NUL / control characters.
    let bad = 0;
    const sample = Math.min(text.length, 20000);
    for (let i = 0; i < sample; i++) {
      const c = text.charCodeAt(i);
      if (c === 0 || (c < 9) || (c > 13 && c < 32)) bad++;
    }
    if (sample > 0 && bad / sample > 0.02) {
      return { error: 'This file does not look like a text CSV (it contains binary data). Please export as CSV.' };
    }
    return { text };
  }

  function detectDelimiter(firstLine) {
    const counts = { ',': 0, ';': 0, '\t': 0 };
    let inQ = false;
    for (const ch of firstLine) {
      if (ch === '"') inQ = !inQ;
      else if (!inQ && ch in counts) counts[ch]++;
    }
    let best = ',';
    for (const d of Object.keys(counts)) if (counts[d] > counts[best]) best = d;
    return best;
  }

  // A small, strict CSV reader. Handles quoted fields, commas and line breaks
  // inside quotes (Windows messages contain many), "" escapes, CRLF/LF, BOM.
  // Returns { rows, delimiter } or { error }.
  function parseCsv(text) {
    if (typeof text !== 'string') return { error: 'No text to parse.' };
    if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
    // PowerShell (Windows PowerShell 5.1) can put a "#TYPE ..." line first.
    if (/^#TYPE/i.test(text)) {
      const nl = text.indexOf('\n');
      text = nl === -1 ? '' : text.slice(nl + 1);
    }
    // Excel-style "sep=;" hint line.
    let forced = null;
    const sepMatch = text.match(/^sep=(.)\r?\n/i);
    if (sepMatch) { forced = sepMatch[1]; text = text.slice(sepMatch[0].length); }
    if (!text.trim()) return { error: 'The file is empty.' };

    const firstLine = text.split(/\r?\n/, 1)[0];
    const delim = forced || detectDelimiter(firstLine);

    const rows = [];
    let row = [];
    let field = '';
    let inQ = false;
    const n = text.length;
    let i = 0;
    while (i < n) {
      const c = text[i];
      if (inQ) {
        if (c === '"') {
          if (text[i + 1] === '"') { field += '"'; i += 2; continue; }
          inQ = false; i++; continue;
        }
        field += c; i++; continue;
      }
      if (c === '"' && field === '') { inQ = true; i++; continue; }
      if (c === delim) { row.push(field); field = ''; i++; continue; }
      if (c === '\r') {
        if (text[i + 1] === '\n') { i++; continue; } // CRLF: handled on the \n
        row.push(field); rows.push(row); row = []; field = ''; i++; continue; // lone CR
      }
      if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; i++; continue; }
      field += c; i++;
    }
    if (inQ) {
      return { error: 'The CSV looks malformed: a quoted field is opened but never closed. Please re-export the file and try again.' };
    }
    if (field !== '' || row.length) { row.push(field); rows.push(row); }
    const cleaned = rows.filter((r) => !(r.length === 1 && r[0].trim() === ''));
    if (!cleaned.length) return { error: 'The file is empty.' };
    return { rows: cleaned, delimiter: delim };
  }

  /* ------------------------------------------------------------------ */
  /* 3. TIMESTAMPS                                                       */
  /* ------------------------------------------------------------------ */

  // Windows exports dates using the computer's regional settings, so
  // "03/04/2026" could be 3 April or 4 March. We read the numbers into parts
  // first, then decide day-first or month-first by looking at the whole file.
  function readDateParts(raw) {
    const s = String(raw || '').replace(/[  ]/g, ' ').trim();
    if (!s) return null;
    let m = s.match(/^(\d{4})-(\d{2})-(\d{2})[T ](\d{1,2}):(\d{2})(?::(\d{2}))?/);
    if (m) return { iso: true, y: +m[1], a: +m[2], b: +m[3], hh: +m[4], mm: +m[5], ss: +(m[6] || 0), ampm: '' };
    m = s.match(/^(\d{1,2})[\/.\-](\d{1,2})[\/.\-](\d{2,4}),?\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([AaPp]\.?[Mm]\.?)?/);
    if (m) {
      let y = +m[3]; if (y < 100) y += 2000;
      return { iso: false, y, a: +m[1], b: +m[2], hh: +m[4], mm: +m[5], ss: +(m[6] || 0), ampm: (m[7] || '').replace(/\./g, '').toUpperCase() };
    }
    return null;
  }

  function partsToMs(p, order) {
    let month; let day;
    if (p.iso || order === 'MDY') { month = p.a; day = p.b; } else { day = p.a; month = p.b; }
    if (p.iso) { month = p.a; day = p.b; }
    let hh = p.hh;
    if (p.ampm === 'PM' && hh < 12) hh += 12;
    if (p.ampm === 'AM' && hh === 12) hh = 0;
    if (month < 1 || month > 12 || day < 1 || day > 31 || hh > 23 || p.mm > 59 || p.ss > 59) return null;
    const ms = Date.UTC(p.y, month - 1, day, hh, p.mm, p.ss);
    return Number.isNaN(ms) ? null : ms;
  }

  function fmtTime(ms) {
    if (ms == null) return 'n/a';
    return new Date(ms).toISOString().replace('T', ' ').slice(0, 19);
  }

  /* ------------------------------------------------------------------ */
  /* 4. EXTRACTING DETAILS FROM THE MESSAGE TEXT                         */
  /* ------------------------------------------------------------------ */

  // Event Viewer messages look like:
  //   Subject:
  //       Account Name:   admin01
  //   New Logon:
  //       Account Name:   jsmith
  // We split them into named sections so we can pick the right "Account Name".
  function parseSections(msg) {
    const sections = [];
    let cur = { title: '', kv: {} };
    sections.push(cur);
    for (const rawLine of String(msg || '').split(/\r\n|\n|\r/)) {
      const line = rawLine.replace(/\t+/g, ' ').trim();
      if (!line) continue;
      const m = line.match(/^([A-Za-z][^:]{0,60}?):\s*(.*)$/);
      if (!m) continue;
      const key = m[1].trim().toLowerCase();
      const val = m[2].trim();
      if (val === '') { cur = { title: key, kv: {} }; sections.push(cur); } else if (!(key in cur.kv)) cur.kv[key] = val;
    }
    return sections;
  }
  const findSection = (S, re) => S.find((s) => re.test(s.title));
  const secVal = (s, key) => {
    const v = s && s.kv[key];
    return v && v !== '-' ? v : '';
  };
  const anyVal = (S, key) => {
    for (const s of S) if (s.kv[key] && s.kv[key] !== '-') return s.kv[key];
    return '';
  };

  // "LAB\jsmith" -> "jsmith"; "CN=temp-admin,CN=Users,DC=lab" -> "temp-admin"
  function cleanAccount(v) {
    let s = String(v || '').trim();
    if (!s || s === '-') return '';
    const cn = s.match(/^CN=([^,]+)/i);
    if (cn) s = cn[1];
    if (s.includes('\\')) s = s.slice(s.lastIndexOf('\\') + 1);
    return s.trim();
  }

  function cleanIp(v) {
    let s = String(v || '').trim();
    if (!s || s === '-') return '';
    s = s.replace(/^::ffff:/i, '');
    return s.slice(0, 64);
  }

  // Look for the encoded / heavily obfuscated PowerShell patterns. We only
  // *point at* these; we do not claim PowerShell is malicious.
  function detectObfuscation(text) {
    const reasons = [];
    if (!text) return reasons;
    if (/(^|\s)-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+\/=]{16,}/i.test(text)) reasons.push('Contains an -EncodedCommand style argument');
    if (/FromBase64String/i.test(text)) reasons.push('Decodes Base64 data (FromBase64String)');
    if (/[A-Za-z0-9+\/]{120,}={0,2}/.test(text)) reasons.push('Contains a very long Base64-looking string');
    if (/(`[A-Za-z]){5,}/.test(text)) reasons.push('Contains many backtick escape characters');
    if (/(\[char\]\s*\d+\s*[+,]?\s*){5,}/i.test(text)) reasons.push('Builds text from many [char] numbers');
    if (/('[^']{1,3}'\s*\+\s*){6,}/.test(text)) reasons.push('Builds text from many small joined strings');
    return reasons;
  }

  function extractFields(id, message, userCol) {
    const f = {
      account: '', actor: '', domain: '', ip: '', workstation: '', logonType: '', group: '',
      process: '', parent: '', command: '', service: '', serviceFile: '', failureReason: '', flags: []
    };
    const S = parseSections(message);
    const subj = findSection(S, /^(creator )?subject$/);
    f.actor = cleanAccount(secVal(subj, 'account name'));
    f.workstation = anyVal(S, 'workstation name');
    f.logonType = anyVal(S, 'logon type');
    f.ip = cleanIp(secVal(findSection(S, /network information/), 'source network address') || anyVal(S, 'source network address'));

    const flat = String(message || '');
    switch (id) {
      case 4624: {
        const s = findSection(S, /new logon/);
        f.account = cleanAccount(secVal(s, 'account name'));
        f.domain = secVal(s, 'account domain');
        if (!f.account) {
          const m = flat.match(/New Logon:[\s\S]*?Account Name:\s*([^\s]+)/i);
          if (m) f.account = cleanAccount(m[1]);
        }
        break;
      }
      case 4625: {
        const s = findSection(S, /account for which logon failed/);
        f.account = cleanAccount(secVal(s, 'account name'));
        f.domain = secVal(s, 'account domain');
        f.failureReason = anyVal(S, 'failure reason');
        if (!f.account) {
          const m = flat.match(/Account For Which Logon Failed:[\s\S]*?Account Name:\s*([^\s]+)/i);
          if (m) f.account = cleanAccount(m[1]);
        }
        break;
      }
      case 4720: {
        const s = findSection(S, /new account/);
        f.account = cleanAccount(secVal(s, 'account name') || anyVal(S, 'sam account name'));
        f.domain = secVal(s, 'account domain');
        break;
      }
      case 4726: {
        const s = findSection(S, /target account/);
        f.account = cleanAccount(secVal(s, 'account name'));
        f.domain = secVal(s, 'account domain');
        break;
      }
      case 4728:
      case 4732: {
        const mem = findSection(S, /^member$/);
        f.account = cleanAccount(secVal(mem, 'account name')) || cleanAccount(secVal(mem, 'security id'));
        f.group = secVal(findSection(S, /^group$/), 'group name') || anyVal(S, 'group name');
        if (/^S-1-5-/.test(f.account)) f.flags.push('Member shown as an unresolved SID');
        break;
      }
      case 1102: {
        f.account = f.actor;
        break;
      }
      case 4688: {
        f.account = f.actor;
        const p = findSection(S, /process information/);
        f.process = secVal(p, 'new process name') || anyVal(S, 'new process name');
        f.parent = secVal(p, 'creator process name') || anyVal(S, 'creator process name') || anyVal(S, 'parent process name');
        f.command = anyVal(S, 'process command line');
        break;
      }
      case 4104: {
        let t = flat.replace(/^Creating Scriptblock text[^\n]*\n/i, '');
        t = t.split(/\r?\nScriptBlock ID:/i)[0].trim();
        f.command = t.slice(0, 2000);
        f.account = cleanAccount(userCol);
        const reasons = detectObfuscation(t);
        if (reasons.length) f.flags = f.flags.concat(reasons);
        break;
      }
      case 7045: {
        f.service = anyVal(S, 'service name');
        f.serviceFile = anyVal(S, 'service file name');
        f.account = cleanAccount(userCol);
        break;
      }
      default:
        break;
    }
    if (!f.account && id !== 1102 && id !== 7045) {
      // fall back to the User column when the message had nothing usable
      const u = cleanAccount(userCol);
      if (u && !/^S-1-/.test(u) && !/^N\/A$/i.test(u)) f.account = u;
    }
    return f;
  }

  /* ------------------------------------------------------------------ */
  /* 5. BUILDING EVENT OBJECTS FROM CSV ROWS                             */
  /* ------------------------------------------------------------------ */

  const normHeader = (h) => String(h || '').toLowerCase().replace(/[^a-z0-9]/g, '');

  function buildEvents(rows) {
    const headers = rows[0].map((h) => String(h || '').trim());
    const norm = headers.map(normHeader);
    const map = {};
    for (const field of Object.keys(COLUMN_ALIASES)) {
      for (const alias of COLUMN_ALIASES[field]) {
        const idx = norm.indexOf(alias);
        if (idx !== -1) { map[field] = idx; break; }
      }
    }
    const mapping = {};
    for (const k of Object.keys(map)) mapping[k] = headers[map[k]];

    if (map.eventId === undefined) {
      const shown = headers.filter(Boolean).slice(0, 15).join(', ') || '(none)';
      return {
        ok: false,
        error: 'Could not find an Event ID column. This tool needs a column named "Event ID" (or EventID / event_id / Id). Columns found in your file: ' + shown + '.'
      };
    }

    const warnings = [];
    const missing = Object.keys(FIELD_LABELS).filter((k) => map[k] === undefined);
    if (map.message === undefined) {
      warnings.push('No Message column found, so account names, source IPs and other details cannot be read from your file. Counting and the log-cleared check still work, but correlation by account is not possible. See "How to get your logs" for an export that includes the Message text.');
    }
    if (map.time === undefined) {
      warnings.push('No date/time column found, so the timeline and time-window analysis are switched off. Events are assumed to be in file order, oldest first.');
    }

    const events = [];
    let skipped = 0;
    let raggedRows = 0;
    let truncated = false;
    const dataRows = rows.length - 1;
    const limit = Math.min(rows.length, LIMITS.maxRows + 1);
    if (rows.length > LIMITS.maxRows + 1) truncated = true;

    for (let r = 1; r < limit; r++) {
      const cells = rows[r];
      if (cells.length !== headers.length) raggedRows++;
      const get = (f) => (map[f] !== undefined && cells[map[f]] !== undefined ? String(cells[map[f]]).trim() : '');
      const idMatch = get('eventId').match(/^\s*(\d{1,6})\b/);
      if (!idMatch) { skipped++; continue; }
      const eventId = parseInt(idMatch[1], 10);
      const messageFull = map.message !== undefined && cells[map.message] !== undefined ? String(cells[map.message]) : '';
      const message = messageFull.slice(0, LIMITS.maxMessageChars);
      const cat = CATALOG[eventId];
      const ev = {
        idx: events.length,
        eventId,
        timeText: get('time'),
        time: null,
        level: get('level') || get('keywords'),
        source: get('source'),
        task: get('task'),
        user: get('user'),
        computer: get('computer'),
        keywords: get('keywords'),
        message,
        name: cat ? cat.name : 'Other event',
        category: cat ? cat.category : 'Other',
        baseSeverity: cat ? cat.severity : 'Informational',
        severity: cat ? cat.severity : 'Informational',
        alertIds: [],
        f: extractFields(eventId, messageFull, get('user'))
      };
      if (!ev.f.workstation && ev.computer && eventId !== 4624 && eventId !== 4625) ev.f.hostComputer = ev.computer;
      events.push(ev);
    }

    if (!events.length) {
      return { ok: false, error: 'No usable rows were found: every row had a missing or non-numeric Event ID.' };
    }
    if (skipped) warnings.push(skipped + ' row(s) were skipped because their Event ID was missing or not a number.');
    if (raggedRows) warnings.push(raggedRows + ' row(s) had a different number of columns than the header. They were read as well as possible; check the export if results look odd.');
    if (truncated) warnings.push('The file has more than ' + LIMITS.maxRows.toLocaleString() + ' rows. Only the first ' + LIMITS.maxRows.toLocaleString() + ' were analysed.');

    const timeInfo = resolveTimes(events, map.time !== undefined);
    if (timeInfo.warning) warnings.push(timeInfo.warning);

    const unrecognised = new Set(events.filter((e) => !CATALOG[e.eventId]).map((e) => e.eventId));
    return {
      ok: true, events, mapping, missing, warnings, timeInfo,
      totalRows: dataRows, skipped,
      unrecognisedIds: Array.from(unrecognised)
    };
  }

  function resolveTimes(events, hasTimeColumn) {
    const info = { present: hasTimeColumn, parsed: 0, total: events.length, order: 'none', reliable: false, descending: false, warning: '' };
    if (!hasTimeColumn) return info;
    const parts = events.map((e) => readDateParts(e.timeText));
    let dayFirstEvidence = 0; let monthFirstEvidence = 0; let anyNonIso = false; let anyIso = false;
    for (const p of parts) {
      if (!p) continue;
      if (p.iso) { anyIso = true; continue; }
      anyNonIso = true;
      if (p.a > 12) dayFirstEvidence++;
      if (p.b > 12) monthFirstEvidence++;
    }
    let order = 'ISO';
    let conflict = false;
    if (anyNonIso) {
      if (dayFirstEvidence && monthFirstEvidence) { conflict = true; order = 'conflict'; }
      else if (dayFirstEvidence) order = 'DMY';
      else if (monthFirstEvidence) order = 'MDY';
      else order = 'MDY-assumed';
    }
    const useOrder = order === 'DMY' ? 'DMY' : 'MDY';
    let parsed = 0;
    events.forEach((e, i) => {
      const p = parts[i];
      if (!p || conflict) { e.time = null; return; }
      e.time = partsToMs(p, useOrder);
      if (e.time != null) parsed++;
    });
    info.parsed = parsed;
    info.order = order;
    info.reliable = !conflict && parsed >= events.length * 0.9 && parsed > 0;
    if (info.reliable) {
      const times = events.map((e) => e.time).filter((t) => t != null);
      info.first = Math.min.apply(null, times);
      info.last = Math.max.apply(null, times);
      const firstT = events.find((e) => e.time != null).time;
      const lastT = [...events].reverse().find((e) => e.time != null).time;
      info.descending = firstT > lastT; // Event Viewer exports newest-first
    }
    if (conflict) {
      info.warning = 'Dates in the file are inconsistent (some look day-first, some month-first), so timestamps are not trusted. Time-window analysis and the timeline are switched off and file order is used.';
    } else if (!info.reliable) {
      const sample = (events.find((e) => e.timeText) || {}).timeText || '';
      info.warning = 'Could not read most of the date/time values' + (sample ? ' (for example "' + sample.slice(0, 40) + '")' : '') + '. Time-window analysis and the timeline are switched off and file order is used. Note that Event Viewer exports are usually newest-first.';
    } else if (parsed < events.length) {
      info.warning = (events.length - parsed) + ' event(s) had a date/time that could not be read.';
    } else if (order === 'MDY-assumed') {
      info.warning = 'Every date in this file is ambiguous (for example 03/04/2026 could be March 4 or April 3). Month-first (MM/DD/YYYY) was assumed. This only affects the displayed dates and time gaps across days.';
    }
    return info;
  }

  /* ------------------------------------------------------------------ */
  /* 6. ANALYSIS: DETECTION AND CORRELATION                              */
  /* ------------------------------------------------------------------ */

  const keyOf = (s) => String(s || '').toLowerCase();
  const displayAccount = (s) => s || '(unknown)';

  function groupBy(list, fn) {
    const m = new Map();
    for (const x of list) {
      const k = fn(x);
      if (!m.has(k)) m.set(k, []);
      m.get(k).push(x);
    }
    return m;
  }
  const uniq = (arr) => Array.from(new Set(arr.filter(Boolean)));

  function seqString(ids) {
    const out = [];
    for (let i = 0; i < ids.length;) {
      let j = i;
      while (j < ids.length && ids[j] === ids[i]) j++;
      const n = j - i;
      out.push(n > 6 ? ids[i] + ' ×' + n : Array(n).fill(ids[i]).join(' → '));
      i = j;
    }
    return out.join(' → ');
  }

  function plural(n, one, many) { return n + ' ' + (n === 1 ? one : (many || one + 's')); }

  function analyse(events, cfg, timeInfo) {
    const config = Object.assign({}, DEFAULTS, cfg || {});
    timeInfo = timeInfo || { reliable: false, descending: false };
    const useTime = !!timeInfo.reliable;
    const useWindow = useTime && !!config.useWindow;
    const windowMs = config.windowMinutes * 60000;

    // reset state so we can re-run after settings change
    events.forEach((e) => { e.severity = e.baseSeverity; e.alertIds = []; });

    const sorted = events.slice().sort((a, b) => {
      if (useTime && a.time != null && b.time != null && a.time !== b.time) return a.time - b.time;
      return timeInfo.descending && useTime ? b.idx - a.idx : a.idx - b.idx;
    });
    sorted.forEach((e, i) => { e.seq = i; });

    const alerts = [];
    let alertCounter = 0;
    const covered = new Set(); // events already explained by a correlation alert
    const timeRange = (list) => {
      if (!useTime) return { start: null, end: null };
      const ts = list.map((e) => e.time).filter((t) => t != null);
      return ts.length ? { start: Math.min.apply(null, ts), end: Math.max.apply(null, ts) } : { start: null, end: null };
    };
    function addAlert(a) {
      a.id = 'alert-' + (++alertCounter);
      const tr = timeRange(a.events);
      a.timeStart = tr.start; a.timeEnd = tr.end;
      a.ips = uniq(a.events.map((e) => e.f.ip));
      a.workstations = uniq(a.events.map((e) => e.f.workstation));
      a.eventIds = uniq(a.events.map((e) => e.eventId));
      a.categories = uniq(a.events.map((e) => e.category));
      a.score = a.scoreItems.reduce((t, s) => t + s.points, 0);
      a.related = a.related || [];
      alerts.push(a);
      a.events.forEach((e) => { e.alertIds.push(a.id); e.severity = maxSeverity(e.severity, a.severity); });
      return a;
    }

    /* ---- Authentication grouping ---- */
    const fails = sorted.filter((e) => e.eventId === 4625);
    const succs = sorted.filter((e) => e.eventId === 4624);
    const failBy = groupBy(fails, (e) => keyOf(e.f.account));
    const succBy = groupBy(succs, (e) => keyOf(e.f.account));
    const ipAccounts = new Map();
    for (const e of fails) {
      if (!e.f.ip || !e.f.account) continue;
      if (!ipAccounts.has(e.f.ip)) ipAccounts.set(e.f.ip, new Set());
      ipAccounts.get(e.f.ip).add(keyOf(e.f.account));
    }

    function peakCluster(list) {
      if (!useWindow) return list;
      let best = [0, 0]; let l = 0;
      for (let r = 0; r < list.length; r++) {
        while (list[r].time - list[l].time > windowMs) l++;
        if (r - l > best[1] - best[0]) best = [l, r];
      }
      return list.slice(best[0], best[1] + 1);
    }

    const rule2ByActor = new Map(); // accountKey -> alert (strong failure->success)

    /* ---- RULES 1 and 2: repeated failures, and failures then success ---- */
    for (const [key, list] of failBy) {
      const cluster = peakCluster(list);
      if (cluster.length < config.failThreshold) continue;
      const unknown = key === '';
      const acct = unknown ? '' : cluster[0].f.account;
      const last = cluster[cluster.length - 1];
      const clusterIps = uniq(cluster.map((e) => e.f.ip));
      const otherAccounts = new Set();
      for (const ip of clusterIps) for (const k of (ipAccounts.get(ip) || [])) if (k !== key) otherAccounts.add(k);
      const spread = otherAccounts.size > 0;

      let success = null;
      if (!unknown) {
        success = (succBy.get(key) || []).find((s) => s.seq > last.seq && (!useWindow || s.time - last.time <= windowMs)) || null;
      }

      const windowText = useWindow ? ' within ' + plural(config.windowMinutes, 'minute') : '';
      const totalText = list.length > cluster.length ? ' (' + list.length + ' failures in the whole file)' : '';
      const scoreItems = [{ points: 10, label: 'Repeated failed logons (at or above the threshold of ' + config.failThreshold + ')' }];
      if (cluster.length >= config.failThreshold * 2) scoreItems.push({ points: 5, label: 'Failure count is at least double the threshold' });
      if (spread) scoreItems.push({ points: 10, label: 'Same source IP also failed against ' + plural(otherAccounts.size, 'other account') });

      const sourceText = clusterIps.length ? ' Source IP(s): ' + clusterIps.join(', ') + '.' : ' No source IP was available in these events.';
      const spreadText = spread ? ' The same source IP also had failed logons for ' + plural(otherAccounts.size, 'other account') + ' (' + Array.from(otherAccounts).slice(0, 5).join(', ') + (otherAccounts.size > 5 ? ', …' : '') + '), which can be a sign of password spraying (one source trying a few passwords against many accounts), though shared NAT gateways or proxies can look similar.' : '';

      if (success) {
        scoreItems.push({ points: 20, label: 'Successful logon (4624) followed the failures' });
        const successIp = success.f.ip;
        const sameIp = !!successIp && clusterIps.includes(successIp);
        const differentIp = !!successIp && clusterIps.length > 0 && !sameIp;
        if (sameIp) scoreItems.push({ points: 10, label: 'Success came from the same source IP as the failures' });
        const sev = differentIp ? 'Medium' : 'High';
        const evs = cluster.concat([success]);
        const ipLine = sameIp ? ' The successful logon came from the same source IP as the failures (' + successIp + ').'
          : differentIp ? ' The successful logon came from a different source IP (' + successIp + ') than the failures, which lowers the confidence of this correlation.'
            : ' Source IP could not be compared for the successful logon.';
        const a = addAlert({
          rule: 'rule2', name: 'POSSIBLE PASSWORD GUESSING FOLLOWED BY SUCCESS', severity: sev,
          account: acct, actor: acct,
          events: evs, sequence: seqString(evs.map((e) => e.eventId)),
          facts: [
            ['Failed logins', String(cluster.length)],
            ['Successful login', 'Yes' + (success.f.logonType ? ' (logon type ' + success.f.logonType + (LOGON_TYPES[success.f.logonType] ? ': ' + LOGON_TYPES[success.f.logonType] : '') + ')' : '')]
          ],
          observed: cluster.length + ' failed logon events (4625) were recorded for account "' + acct + '"' + windowText + totalText + ', followed by a successful logon (4624) for the same account at ' + (useTime ? fmtTime(success.time) : 'a later point in the file') + '.' + sourceText + ipLine + spreadText,
          why: 'Repeated failed authentication attempts followed by a successful login may indicate that the password was eventually guessed.',
          benign: 'The legitimate user may simply have entered the wrong password several times before getting it right, or an application retried with an old password and then a person logged in normally.',
          steps: [
            'Verify the source device.',
            'Determine whether the source IP is expected for this user.',
            'Review post-authentication activity for this account.',
            'Check whether other users experienced similar failures.',
            'Review endpoint or MFA telemetry where available.'
          ],
          scoreItems
        });
        rule2ByActor.set(key, a);
      } else {
        addAlert({
          rule: 'rule1', name: 'REPEATED FAILED LOGONS', severity: unknown ? 'Low' : 'Medium',
          account: acct, actor: acct,
          events: cluster, sequence: seqString(cluster.map((e) => e.eventId)),
          facts: [['Failures', String(cluster.length) + (list.length > cluster.length ? ' of ' + list.length + ' in file' : '')]],
          observed: cluster.length + ' failed logon events (4625) were recorded for ' + (unknown ? 'an account that could not be identified' : 'account "' + acct + '"') + windowText + totalText + '.' + sourceText + spreadText + ' No successful logon for this account followed the failures in this file.' + (unknown ? ' Because the account name could not be read (the Message column may be missing or in another language), these failures may belong to many different accounts, so this is only a Low priority hint.' : ''),
          why: 'Repeated authentication failures may indicate password guessing, but could also be caused by a legitimate user entering the wrong password or an application using outdated credentials.',
          benign: 'A user mistyping or forgetting a password, an old password saved in a service, scheduled task, mapped drive or phone, or software that keeps retrying a locked account.',
          steps: [
            'Identify the source system (source IP / workstation).',
            'Review the affected account: is it a real person, a service account, or an admin?',
            'Check whether the failures were followed by a successful login.',
            'Determine whether other accounts were targeted from the same source.',
            'Review MFA or endpoint telemetry if available.'
          ],
          scoreItems
        });
      }
    }

    /* ---- RULE 3: account created then privilege added ---- */
    const creations = sorted.filter((e) => e.eventId === 4720 && e.f.account);
    const groupAdds = sorted.filter((e) => (e.eventId === 4728 || e.eventId === 4732) && e.f.account);
    const rule3Alerts = [];
    for (const c of creations) {
      const key = keyOf(c.f.account);
      const adds = groupAdds.filter((e) => e.seq > c.seq && keyOf(e.f.account) === key);
      if (!adds.length) continue;
      const privileged = adds.filter((e) => isPrivilegedGroup(e.f.group));
      const first = adds[0];
      const elapsed = useTime && c.time != null && first.time != null ? first.time - c.time : null;
      const quick = elapsed != null && elapsed <= PRIVILEGE_QUICK_MINUTES * 60000;
      const evs = [c].concat(adds);
      const groupList = uniq(adds.map((e) => e.f.group)).join(', ') || 'a security group';
      const scoreItems = [{ points: 10, label: 'User account created (4720)' }];
      if (privileged.length) scoreItems.push({ points: 25, label: 'Added to a privileged group (' + uniq(privileged.map((e) => e.f.group)).join(', ') + ')' });
      else scoreItems.push({ points: 10, label: 'Added to a security group (not recognised as privileged by name)' });
      if (quick) scoreItems.push({ points: 10, label: 'Group change happened within ' + PRIVILEGE_QUICK_MINUTES + ' minutes of the account being created' });
      const elapsedText = elapsed != null ? ' The first group change came ' + (elapsed < 60000 ? 'less than a minute' : Math.round(elapsed / 60000) + ' minute(s)') + ' after the account was created.' : '';
      const a = addAlert({
        rule: 'rule3', name: 'NEW ACCOUNT GRANTED PRIVILEGES', severity: privileged.length ? 'High' : 'Medium',
        account: c.f.account, actor: c.f.actor,
        events: evs, sequence: seqString(evs.map((e) => e.eventId)),
        facts: [
          ['Sequence', evs.map((e) => e.eventId + ' — ' + (e.eventId === 4720 ? 'Account created' : 'Added to ' + (e.f.group || 'group'))).join(' → ')],
          ['Created by', c.f.actor || 'unknown']
        ],
        observed: 'Account "' + c.f.account + '" was created (4720)' + (c.f.actor ? ' by "' + c.f.actor + '"' : '') + ' and then added to ' + groupList + ' (' + adds.map((e) => e.eventId).join(', ') + ').' + elapsedText,
        why: 'Creating an account and quickly granting it elevated privileges can be legitimate administration, but it may also indicate persistence or privilege escalation.',
        benign: 'An administrator onboarding a new employee or setting up a service or lab account as part of a normal, approved change.',
        steps: [
          'Confirm whether the account creation was authorised.',
          'Identify the administrator responsible.',
          'Review activity performed by the account.',
          'Check whether the account is still required.'
        ],
        scoreItems
      });
      rule3Alerts.push(a);
      evs.forEach((e) => covered.add(e));
    }

    /* ---- RULE 4: audit log cleared ---- */
    sorted.filter((e) => e.eventId === 1102).forEach((e) => {
      addAlert({
        rule: 'rule4', name: 'SECURITY AUDIT LOG CLEARED', severity: 'High',
        account: e.f.account, actor: e.f.account,
        events: [e], sequence: '1102',
        facts: [['Cleared by', e.f.account || 'unknown']],
        observed: 'The Windows Security audit log was cleared' + (e.f.account ? ' by account "' + e.f.account + '"' : '') + (useTime ? ' at ' + fmtTime(e.time) : '') + '. Events before this point may no longer exist on the machine.',
        why: 'This event means the Windows Security audit log was cleared. This can happen during legitimate maintenance, but because attackers may clear logs to remove evidence, it should normally be investigated.',
        benign: 'Planned maintenance, a lab or test machine being reset, or an administrator freeing disk space.',
        steps: [
          'Identify who cleared the log (the Subject account).',
          'Check change and maintenance records for that time.',
          'Look at events just before the clear, in a copy of the logs if you have one.',
          'Check whether logs are forwarded to a SIEM or central store; copies may still exist there.',
          'Look for other signs of defence evasion or privilege changes around the same time.'
        ],
        scoreItems: [{ points: 30, label: 'Security audit log cleared (1102)' }]
      });
    });

    /* ---- Standalone findings for admin-type events ---- */
    const createdBefore = (e) => creations.some((c) => keyOf(c.f.account) === keyOf(e.f.account) && c.seq < e.seq);
    const standaloneGroups = new Map();
    for (const e of sorted) {
      if (covered.has(e)) continue;
      let def = null;
      if (e.eventId === 4720) {
        def = { key: '4720|' + keyOf(e.f.actor), name: 'USER ACCOUNT CREATED', severity: 'Medium', pts: [{ points: 10, label: 'User account created (4720)' }] };
      } else if (e.eventId === 4726) {
        const short = createdBefore(e);
        def = {
          key: '4726|' + keyOf(e.f.actor) + '|' + short, name: short ? 'SHORT-LIVED ACCOUNT DELETED' : 'USER ACCOUNT DELETED',
          severity: short ? 'Medium' : 'Low',
          pts: short ? [{ points: 5, label: 'User account deleted (4726)' }, { points: 10, label: 'The same account was created earlier in this file' }] : [{ points: 5, label: 'User account deleted (4726)' }]
        };
      } else if (e.eventId === 4728 || e.eventId === 4732) {
        const priv = isPrivilegedGroup(e.f.group);
        def = {
          key: e.eventId + '|' + keyOf(e.f.group) + '|' + keyOf(e.f.actor), name: priv ? 'PRIVILEGED GROUP MEMBERSHIP CHANGE' : 'GROUP MEMBERSHIP CHANGE',
          severity: priv ? 'High' : 'Medium',
          pts: priv ? [{ points: 10, label: 'Member added to a security group (' + e.eventId + ')' }, { points: 15, label: 'Group name looks privileged (' + e.f.group + ')' }] : [{ points: 10, label: 'Member added to a security group (' + e.eventId + ')' }]
        };
      } else if (e.eventId === 7045) {
        const sus = /\\(temp|appdata|users\\public|programdata)\\|\\(cmd|powershell|pwsh|mshta|wscript|cscript)\.exe/i.test(e.f.serviceFile || '');
        def = {
          key: '7045|' + keyOf(e.f.service) + '|' + e.idx, name: sus ? 'SERVICE INSTALLED FROM AN UNUSUAL LOCATION' : 'SERVICE INSTALLED',
          severity: sus ? 'Medium' : 'Low',
          pts: sus ? [{ points: 10, label: 'New service installed (7045)' }, { points: 10, label: 'Service file is in a user-writable folder or is a script host' }] : [{ points: 10, label: 'New service installed (7045)' }]
        };
      } else if (e.eventId === 4104 && e.f.flags.length) {
        def = { key: '4104|' + e.idx, name: 'POWERSHELL SCRIPT BLOCK WITH ENCODED OR OBFUSCATED CONTENT', severity: 'Medium', pts: [{ points: 5, label: 'PowerShell script block logged (4104)' }, { points: 15, label: 'Encoded or heavily obfuscated looking content' }] };
      }
      if (!def) continue;
      if (!standaloneGroups.has(def.key)) standaloneGroups.set(def.key, { def, events: [] });
      standaloneGroups.get(def.key).events.push(e);
    }
    for (const { def, events: evs } of standaloneGroups.values()) {
      const first = evs[0];
      const cat = CATALOG[first.eventId];
      const many = evs.length > 1;
      const accounts = uniq(evs.map((e) => e.f.account));
      let observed;
      if (first.eventId === 4720) observed = plural(evs.length, 'user account') + ' created (4720): ' + accounts.join(', ') + (first.f.actor ? ', by "' + first.f.actor + '"' : '') + '. No group membership change for the new account was found afterwards in this file.';
      else if (first.eventId === 4726) observed = plural(evs.length, 'user account') + ' deleted (4726): ' + accounts.join(', ') + (first.f.actor ? ', by "' + first.f.actor + '"' : '') + '.' + (def.severity === 'Medium' ? ' This account was also created earlier in the same file, so it was short-lived.' : '');
      else if (first.eventId === 4728 || first.eventId === 4732) observed = '"' + (accounts.join(', ') || 'unknown') + '" was added to the group "' + (first.f.group || 'unknown') + '" (' + first.eventId + ')' + (first.f.actor ? ' by "' + first.f.actor + '"' : '') + (many ? ' (' + evs.length + ' changes)' : '') + '.';
      else if (first.eventId === 7045) observed = 'Service "' + (first.f.service || 'unknown') + '" was installed' + (first.f.serviceFile ? ' running "' + first.f.serviceFile + '"' : '') + '.';
      else observed = 'A PowerShell script block (4104) contained: ' + first.f.flags.join('; ') + '. PowerShell itself is not suspicious; the encoding or obfuscation is what makes this worth a look.';

      const why = first.eventId === 4104
        ? 'PowerShell script block logging can provide valuable visibility into commands and scripts executed on the endpoint. Encoded or heavily obfuscated text makes it harder to see what a command does, which is why analysts read it more carefully.'
        : cat.why;
      const benign = first.eventId === 4104 ? 'Some legitimate management tools and installers pass Base64-encoded commands to PowerShell.' : cat.benign;
      const steps = first.eventId === 4104
        ? ['Read the full script text and decode it if it is Base64.', 'Identify which process or user launched it.', 'Check whether this host or user normally runs such scripts.', 'Look for related events around the same time.']
        : cat.steps;

      addAlert({
        rule: 'standalone-' + first.eventId, name: def.name, severity: def.severity,
        account: accounts.join(', '), actor: first.f.actor || first.f.account,
        events: evs, sequence: seqString(evs.map((e) => e.eventId)),
        facts: first.eventId === 4728 || first.eventId === 4732 ? [['Group', first.f.group || 'unknown']] : (first.eventId === 7045 ? [['Service', first.f.service || 'unknown']] : []),
        observed, why, benign, steps, scoreItems: def.pts
      });
    }

    /* ---- Cross-link: did the account performing an admin action also have a failure->success alert? ---- */
    for (const a of alerts) {
      if (!a.actor || a.rule === 'rule1' || a.rule === 'rule2') continue;
      const r2 = rule2ByActor.get(keyOf(a.actor));
      if (r2) {
        a.related.push('The account that performed this action ("' + a.actor + '") also appears in the finding "' + r2.name + '".');
        a.scoreItems.push({ points: 15, label: 'The acting account also had failed logons followed by a success' });
        a.score += 15;
      }
    }

    alerts.sort((x, y) => (SEV_RANK[y.severity] - SEV_RANK[x.severity]) || (y.score - x.score) || ((x.timeStart || 0) - (y.timeStart || 0)));

    /* ---- Rule 5: administrative / privilege activity summary ---- */
    const ADMIN_IDS = [4720, 4726, 4728, 4732, 7045, 1102];
    const adminEvents = sorted.filter((e) => ADMIN_IDS.includes(e.eventId));
    const adminSummary = [
      ['Account creation (4720)', adminEvents.filter((e) => e.eventId === 4720).length],
      ['Account deletion (4726)', adminEvents.filter((e) => e.eventId === 4726).length],
      ['Privileged / group membership changes (4728, 4732)', adminEvents.filter((e) => e.eventId === 4728 || e.eventId === 4732).length],
      ['Service installation (7045)', adminEvents.filter((e) => e.eventId === 7045).length],
      ['Audit-log clearing (1102)', adminEvents.filter((e) => e.eventId === 1102).length]
    ].filter((x) => x[1] > 0);

    /* ---- Statistics for the dashboard ---- */
    const counts = {};
    const byAccount = new Map();
    const failByAccount = new Map();
    for (const e of events) {
      counts[e.eventId] = (counts[e.eventId] || 0) + 1;
      if (e.f.account) byAccount.set(e.f.account, (byAccount.get(e.f.account) || 0) + 1);
      if (e.eventId === 4625 && e.f.account) failByAccount.set(e.f.account, (failByAccount.get(e.f.account) || 0) + 1);
    }
    const top = (m, n) => Array.from(m.entries()).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, n);
    const stats = {
      total: events.length,
      successfulLogons: counts[4624] || 0,
      failedLogons: counts[4625] || 0,
      accountsCreated: counts[4720] || 0,
      privilegeChanges: (counts[4728] || 0) + (counts[4732] || 0),
      logCleared: counts[1102] || 0,
      processCreated: counts[4688] || 0,
      powershell: counts[4104] || 0,
      services: counts[7045] || 0,
      needInvestigation: events.filter((e) => SEV_RANK[e.severity] >= SEV_RANK.Medium).length,
      topAccounts: top(byAccount, 8),
      topFailed: top(failByAccount, 8),
      topEventIds: Object.keys(counts).map((k) => [Number(k), counts[k]]).sort((a, b) => b[1] - a[1] || a[0] - b[0]).slice(0, 8),
      accountKnown: byAccount.size > 0,
      totalScore: alerts.reduce((t, a) => t + a.score, 0)
    };

    return { alerts, adminEvents, adminSummary, stats, config, useTime, useWindow, sorted };
  }

  const Core = {
    DEFAULTS, LIMITS, SEVERITIES, SEV_RANK, CATEGORIES, CATALOG, REFERENCE_ORDER, LOGON_TYPES, FIELD_LABELS,
    decodeBuffer, parseCsv, buildEvents, analyse, fmtTime, readDateParts, detectObfuscation, parseSections, cleanAccount, isPrivilegedGroup
  };
  root.EventLensCore = Core;
  if (typeof module !== 'undefined' && module.exports) module.exports = Core;

  /* ------------------------------------------------------------------ */
  /* 7. USER INTERFACE (browser only)                                    */
  /* ------------------------------------------------------------------ */

  if (typeof document === 'undefined') return;

  // Tiny DOM helper. Strings are ALWAYS added as text nodes, never parsed as HTML.
  function h(tag, props) {
    const el = document.createElement(tag);
    if (props) {
      for (const k of Object.keys(props)) {
        const v = props[k];
        if (v == null || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k === 'text') el.textContent = v;
        else if (k.slice(0, 2) === 'on' && typeof v === 'function') el.addEventListener(k.slice(2), v);
        else if (v === true) el.setAttribute(k, '');
        else el.setAttribute(k, String(v));
      }
    }
    for (let i = 2; i < arguments.length; i++) {
      const kids = [].concat(arguments[i]);
      for (const c of kids) {
        if (c == null || c === false) continue;
        el.appendChild(typeof c === 'object' ? c : document.createTextNode(String(c)));
      }
    }
    return el;
  }
  const $ = (id) => document.getElementById(id);
  const clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); };

  const state = {
    fileName: '', isDemo: false, demoKey: '', built: null, result: null,
    config: Object.assign({}, DEFAULTS),
    filters: { eventId: '', account: '', severity: '', ip: '', category: '', q: '' },
    page: 0
  };
  const PAGE_SIZE = 50;

  function sevBadge(sev) {
    return h('span', { class: 'badge sev-' + sev.toLowerCase() }, h('span', { class: 'badge-dot', 'aria-hidden': 'true' }), sev);
  }

  /* ---- status panel ---- */
  function showStatus(kind, title, lines, extra) {
    const box = $('status');
    clear(box);
    box.className = 'status status-' + kind;
    box.setAttribute('role', kind === 'error' ? 'alert' : 'status');
    box.appendChild(h('p', { class: 'status-title' }, title));
    (lines || []).forEach((l) => box.appendChild(h('p', { class: 'status-line' }, l)));
    if (extra) box.appendChild(extra);
  }

  function showError(message) {
    $('results').hidden = true;
    state.built = null; state.result = null;
    showStatus('error', 'Could not analyse this file', [message]);
  }

  /* ---- loading ---- */
  function loadText(text, name, demoKey) {
    try {
      const parsed = parseCsv(text);
      if (parsed.error) return showError(parsed.error);
      if (parsed.rows.length < 2) return showError('The file has a header row but no events.');
      const built = buildEvents(parsed.rows);
      if (!built.ok) return showError(built.error);
      state.built = built;
      state.fileName = name;
      state.isDemo = !!demoKey;
      state.demoKey = demoKey || '';
      state.filters = { eventId: '', account: '', severity: '', ip: '', category: '', q: '' };
      state.page = 0;
      runAnalysis(true);
      showParseStatus();
      $('results').hidden = false;
      $('results-heading').focus();
    } catch (err) {
      showError('Something unexpected went wrong while reading this file. It was not uploaded anywhere. (' + (err && err.message ? err.message : 'unknown error') + ')');
    }
  }

  function showParseStatus() {
    const b = state.built;
    const lines = [];
    lines.push('Parsed ' + b.events.length.toLocaleString() + ' events successfully.');
    const found = Object.keys(b.mapping).map((k) => FIELD_LABELS[k] + ' ← "' + b.mapping[k] + '"');
    lines.push('Columns recognised: ' + found.join('; ') + '.');
    if (b.unrecognisedIds.length) lines.push('Event IDs without a built-in explanation (shown as "Other event"): ' + b.unrecognisedIds.slice(0, 12).join(', ') + (b.unrecognisedIds.length > 12 ? ', …' : '') + '.');
    if (b.timeInfo.present && b.timeInfo.reliable) lines.push('Timestamps read OK (' + (b.timeInfo.order === 'ISO' ? 'ISO format' : b.timeInfo.order === 'DMY' ? 'day-first dates' : b.timeInfo.order === 'MDY' ? 'month-first dates' : 'month-first assumed') + '). Times are shown exactly as exported, with no timezone conversion.');
    const extra = b.warnings.length
      ? h('div', { class: 'status-warnings' }, h('p', { class: 'status-subtitle' }, 'Things to be aware of'), h('ul', null, b.warnings.map((w) => h('li', { text: w }))))
      : null;
    const title = h('span', null, h('span', { class: 'file-name' }, state.fileName), ' ', state.isDemo ? h('span', { class: 'tag tag-demo' }, 'Demo Data (fictional)') : h('span', { class: 'tag' }, 'Your file'));
    const box = $('status');
    clear(box);
    box.className = 'status status-ok';
    box.setAttribute('role', 'status');
    box.appendChild(h('p', { class: 'status-title' }, 'File loaded: ', title));
    lines.forEach((l) => box.appendChild(h('p', { class: 'status-line' }, l)));
    if (state.isDemo && DEMO_META[state.demoKey]) {
      box.appendChild(h('p', { class: 'status-line demo-expect' }, h('strong', null, 'What to expect: '), DEMO_META[state.demoKey].expect));
    }
    if (extra) box.appendChild(extra);
  }

  async function handleFile(file) {
    if (!file) return;
    if (/\.evtx$/i.test(file.name)) return showError('This is a raw .evtx file. Version 1 only reads CSV exports. See "How to get your logs" on this page for how to produce a CSV.');
    if (file.size > LIMITS.maxBytes) return showError('This file is larger than ' + Math.round(LIMITS.maxBytes / 1048576) + ' MB, which is too large for a browser-based tool. Export a smaller time range or fewer Event IDs.');
    showStatus('info', 'Reading ' + file.name + ' …', []);
    try {
      const buf = await file.arrayBuffer();
      const dec = decodeBuffer(buf);
      if (dec.error) return showError(dec.error);
      loadText(dec.text, file.name, '');
    } catch (err) {
      showError('The file could not be read by the browser.');
    }
  }

  const DEMO_META = {
    normal: { label: 'Load Normal Sample', expect: 'Mostly informational activity. Two stray failed logons stay below the threshold, so there is no failed-login alert. One routine account deletion appears as a Low finding.' },
    failures: { label: 'Load Failed Logons Sample', expect: 'A "Repeated Failed Logons" alert for one account. Notice there is no success after the failures, so it is not escalated to High.' },
    guessing: { label: 'Load Password Guessing Sample', expect: 'A High "Possible Password Guessing Followed By Success" alert: repeated failures from one source IP, then a successful logon.' },
    privilege: { label: 'Load Privilege Escalation Sample', expect: 'A High "New Account Granted Privileges" alert: an account is created (4720) and added to the local Administrators group (4732).' },
    cleared: { label: 'Load Log Cleared Sample', expect: 'A High "Security Audit Log Cleared" alert from a single 1102 event.' },
    mixed: { label: 'Load Mixed SOC Sample', expect: 'Several correlated findings (failures then success, new privileged account, service install, log cleared) plus the Administrative / Privilege Activity summary. The same account appears in several findings, which is how analysts connect the story.' }
  };

  function loadDemo(key) {
    const samples = root.EVENTLENS_SAMPLES || {};
    const s = samples[key];
    if (!s) return showError('The built-in sample "' + key + '" is missing. (sample-data.js was not loaded.)');
    loadText(s.csv, s.file, key);
  }

  /* ---- analysis + render ---- */
  function runAnalysis(resetFilterOptions) {
    state.result = analyse(state.built.events, state.config, state.built.timeInfo);
    renderResults(resetFilterOptions);
  }

  function renderResults(rebuildFilters) {
    renderDemoBanner();
    renderDashboard();
    if (rebuildFilters) buildFilterOptions();
    renderTimeNote();
    renderFiltered();
  }

  function renderDemoBanner() {
    const b = $('demo-banner');
    b.hidden = !state.isDemo;
    clear(b);
    if (state.isDemo) b.appendChild(h('p', null, h('strong', null, 'Demo Data. '), 'These events are fictional and were made for training. The users, computers and IP addresses do not exist.'));
  }

  function tile(label, value, note, cls) {
    return h('div', { class: 'tile' + (cls ? ' ' + cls : '') },
      h('div', { class: 'tile-value' }, String(value)),
      h('div', { class: 'tile-label' }, label),
      note ? h('div', { class: 'tile-note' }, note) : null);
  }

  function barList(items, labelFn, emptyText) {
    if (!items.length) return h('p', { class: 'muted' }, emptyText);
    const max = Math.max.apply(null, items.map((i) => i[1]));
    const ol = h('ol', { class: 'bars' });
    items.forEach((it) => {
      const fill = h('span', { class: 'bar-fill' });
      fill.style.width = Math.max(4, Math.round((it[1] / max) * 100)) + '%';
      ol.appendChild(h('li', null,
        h('span', { class: 'bar-label' }, labelFn(it)),
        h('span', { class: 'bar-track', 'aria-hidden': 'true' }, fill),
        h('span', { class: 'bar-count' }, String(it[1]))));
    });
    return ol;
  }

  function renderDashboard() {
    const r = state.result; const s = r.stats;
    const tiles = $('tiles'); clear(tiles);
    tiles.appendChild(tile('Total events', s.total.toLocaleString()));
    tiles.appendChild(tile('Successful logons (4624)', s.successfulLogons, 'Normal on their own'));
    tiles.appendChild(tile('Failed logons (4625)', s.failedLogons));
    tiles.appendChild(tile('Accounts created (4720)', s.accountsCreated));
    tiles.appendChild(tile('Privilege changes (4728/4732)', s.privilegeChanges));
    tiles.appendChild(tile('Audit-log clearing (1102)', s.logCleared, null, s.logCleared ? 'tile-high' : ''));
    tiles.appendChild(tile('Process creation (4688)', s.processCreated || 'n/a', s.processCreated ? '' : 'Not in this file (auditing may be off)'));
    tiles.appendChild(tile('Events requiring investigation', s.needInvestigation, 'Events inside Medium or High findings', s.needInvestigation ? 'tile-attn' : ''));
    if (s.powershell) tiles.appendChild(tile('PowerShell script blocks (4104)', s.powershell));
    if (s.services) tiles.appendChild(tile('Services installed (7045)', s.services));

    const top1 = $('top-accounts'); clear(top1);
    top1.appendChild(barList(s.topAccounts, (i) => i[0], s.accountKnown ? 'No accounts.' : 'Account names could not be read from this file (no usable Message column).'));
    const top2 = $('top-failed'); clear(top2);
    top2.appendChild(barList(s.topFailed, (i) => i[0], 'No failed logons with a readable account name.'));
    const top3 = $('top-ids'); clear(top3);
    top3.appendChild(barList(s.topEventIds, (i) => i[0] + ' — ' + (CATALOG[i[0]] ? CATALOG[i[0]].name : 'Other event'), 'No events.'));

    renderTimeline();
    renderScoreSummary();
  }

  function renderTimeline() {
    const r = state.result;
    const box = $('timeline'); clear(box);
    if (!r.useTime) {
      box.appendChild(h('p', { class: 'muted' }, 'A timeline needs readable timestamps. They were missing or could not be read in this file.'));
      return;
    }
    const items = r.alerts.filter((a) => a.timeStart != null).slice().sort((a, b) => a.timeStart - b.timeStart);
    if (!items.length) { box.appendChild(h('p', { class: 'muted' }, 'No findings, so there is nothing noteworthy to place on a timeline.')); return; }
    const ol = h('ol', { class: 'timeline-list' });
    items.forEach((a) => {
      ol.appendChild(h('li', { class: 'tl-item sev-' + a.severity.toLowerCase() },
        h('time', { class: 'tl-time' }, fmtTime(a.timeStart) + (a.timeEnd !== a.timeStart ? ' → ' + fmtTime(a.timeEnd) : '')),
        h('span', { class: 'tl-body' }, sevBadge(a.severity), ' ', h('a', { href: '#' + a.id }, titleCase(a.name)), a.account ? ' — ' + a.account : '')));
    });
    box.appendChild(ol);
  }

  function renderScoreSummary() {
    const r = state.result;
    $('score-total').textContent = String(r.stats.totalScore);
  }

  function renderTimeNote() {
    const r = state.result; const b = state.built;
    const note = $('time-note');
    if (!b.timeInfo.present) note.textContent = 'This file has no date/time column, so time-window analysis is not available. Failed logons are counted across the whole file.';
    else if (!b.timeInfo.reliable) note.textContent = 'Timestamps could not be read reliably in this file, so time-window analysis is switched off. Failed logons are counted across the whole file.';
    else if (!state.config.useWindow) note.textContent = 'Time window is switched off: failed logons are counted across the whole file.';
    else note.textContent = 'Failed logons are counted inside a sliding ' + state.config.windowMinutes + '-minute window.';
    $('window-enabled').disabled = !b.timeInfo.reliable;
    $('window-minutes').disabled = !b.timeInfo.reliable || !state.config.useWindow;
    void r;
  }

  /* ---- filters ---- */
  function fillSelect(sel, firstLabel, options) {
    const keep = sel.value;
    clear(sel);
    sel.appendChild(h('option', { value: '' }, firstLabel));
    options.forEach((o) => sel.appendChild(h('option', { value: o.value }, o.label)));
    sel.value = options.some((o) => o.value === keep) ? keep : '';
  }

  function buildFilterOptions() {
    const ev = state.built.events;
    const ids = uniq(ev.map((e) => e.eventId)).sort((a, b) => a - b);
    fillSelect($('f-eventid'), 'All Event IDs', ids.map((i) => ({ value: String(i), label: i + ' — ' + (CATALOG[i] ? CATALOG[i].name : 'Other event') })));
    const accts = Array.from(ev.reduce((m, e) => { if (e.f.account) m.set(e.f.account, (m.get(e.f.account) || 0) + 1); return m; }, new Map()).entries()).sort((a, b) => b[1] - a[1]).slice(0, 300);
    fillSelect($('f-account'), 'All accounts', accts.map((a) => ({ value: a[0], label: a[0] + ' (' + a[1] + ')' })));
    fillSelect($('f-severity'), 'All severities', SEVERITIES.slice().reverse().map((s) => ({ value: s, label: s })));
    const ips = uniq(ev.map((e) => e.f.ip)).slice(0, 300);
    fillSelect($('f-ip'), ips.length ? 'All source IPs' : 'No source IPs in this file', ips.map((i) => ({ value: i, label: i })));
    $('f-ip').disabled = !ips.length;
    fillSelect($('f-category'), 'All event types', CATEGORIES.filter((c) => ev.some((e) => e.category === c)).map((c) => ({ value: c, label: c })));
    $('f-search').value = '';
    state.filters = { eventId: '', account: '', severity: '', ip: '', category: '', q: '' };
  }

  function readFilters() {
    state.filters = {
      eventId: $('f-eventid').value, account: $('f-account').value, severity: $('f-severity').value,
      ip: $('f-ip').value, category: $('f-category').value, q: $('f-search').value.trim().toLowerCase()
    };
    state.page = 0;
    renderFiltered();
  }

  function anyFilter() { return Object.keys(state.filters).some((k) => state.filters[k] !== ''); }

  function eventMatches(e) {
    const f = state.filters;
    if (f.eventId && String(e.eventId) !== f.eventId) return false;
    if (f.account && e.f.account !== f.account) return false;
    if (f.severity && e.severity !== f.severity) return false;
    if (f.ip && e.f.ip !== f.ip) return false;
    if (f.category && e.category !== f.category) return false;
    if (f.q) {
      const hay = [e.eventId, e.name, e.f.account, e.f.actor, e.f.ip, e.f.workstation, e.f.group, e.f.process, e.f.command, e.f.service, e.computer, e.source, e.timeText, e.message].join(' ').toLowerCase();
      if (!hay.includes(f.q)) return false;
    }
    return true;
  }

  function alertMatches(a) {
    const f = state.filters;
    if (f.eventId && !a.eventIds.includes(Number(f.eventId))) return false;
    if (f.account) {
      const accts = a.events.map((e) => e.f.account).concat([a.account, a.actor]);
      if (!accts.includes(f.account)) return false;
    }
    if (f.severity && a.severity !== f.severity) return false;
    if (f.ip && !a.ips.includes(f.ip)) return false;
    if (f.category && !a.categories.includes(f.category)) return false;
    if (f.q) {
      const hay = [a.name, a.account, a.actor, a.observed, a.why, a.sequence, a.ips.join(' '), a.workstations.join(' ')].join(' ').toLowerCase();
      if (!hay.includes(f.q)) return false;
    }
    return true;
  }

  function titleCase(s) {
    return s.toLowerCase().replace(/(^|\s)\S/g, (m) => m.toUpperCase());
  }

  function renderFiltered() {
    renderAlerts();
    renderAdmin();
    renderEvents();
  }

  /* ---- alerts ---- */
  function fact(label, value) {
    return h('div', { class: 'fact' }, h('dt', null, label), h('dd', null, value));
  }

  function miniEventTable(evs) {
    const shown = evs.slice(0, 30);
    const tbl = h('table', { class: 'data-table compact' },
      h('caption', { class: 'sr-only' }, 'Events behind this finding'),
      h('thead', null, h('tr', null, ['Time', 'Event ID', 'Account', 'Source IP', 'Workstation'].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, shown.map((e) => h('tr', null,
        h('td', null, e.timeText || 'n/a'), h('td', { class: 'mono' }, String(e.eventId)), h('td', null, e.f.account || '—'), h('td', { class: 'mono' }, e.f.ip || '—'), h('td', null, e.f.workstation || '—')))));
    const wrap = h('div', { class: 'table-wrap' }, tbl);
    if (evs.length > shown.length) wrap.appendChild(h('p', { class: 'muted' }, 'Showing the first ' + shown.length + ' of ' + evs.length + ' events.'));
    return wrap;
  }

  function alertCard(a, index) {
    const cfg = state.result.config;
    void cfg;
    const timeText = a.timeStart != null ? (a.timeStart === a.timeEnd ? fmtTime(a.timeStart) : fmtTime(a.timeStart) + ' → ' + fmtTime(a.timeEnd)) : null;
    const facts = h('dl', { class: 'facts' },
      fact('Event IDs', h('span', { class: 'mono' }, a.sequence)),
      fact('Account', a.account || 'Unknown'),
      timeText ? fact('Time range', timeText) : null,
      a.ips.length ? fact('Source IP', h('span', { class: 'mono' }, a.ips.join(', '))) : null,
      a.workstations.length ? fact('Workstation', a.workstations.join(', ')) : null,
      a.facts.map((kv) => fact(kv[0], kv[1])));
    const scoreTable = h('table', { class: 'data-table compact score-table' },
      h('caption', { class: 'sr-only' }, 'How the investigation score was calculated'),
      h('thead', null, h('tr', null, h('th', { scope: 'col' }, 'Points'), h('th', { scope: 'col' }, 'Why'))),
      h('tbody', null, a.scoreItems.map((s) => h('tr', null, h('td', { class: 'mono' }, '+' + s.points), h('td', null, s.label))),
        h('tr', { class: 'score-total-row' }, h('td', { class: 'mono' }, String(a.score)), h('td', null, 'Total investigation score'))));
    return h('article', { class: 'alert sev-' + a.severity.toLowerCase(), id: a.id, 'aria-labelledby': a.id + '-title' },
      h('header', { class: 'alert-head' },
        sevBadge(a.severity),
        h('h4', { id: a.id + '-title' }, a.name),
        h('span', { class: 'score-pill' }, 'Investigation score: ' + a.score)),
      facts,
      h('div', { class: 'alert-body' },
        h('section', null, h('h5', null, 'Observed activity'), h('p', null, a.observed)),
        h('section', null, h('h5', null, 'Why this matters'), h('p', null, a.why)),
        h('section', null, h('h5', null, 'Possible benign explanation'), h('p', null, a.benign)),
        h('section', null, h('h5', null, 'Suggested investigation'), h('ol', null, a.steps.map((st) => h('li', null, st)))),
        a.related.length ? h('section', { class: 'related' }, h('h5', null, 'Related findings'), h('ul', null, a.related.map((r) => h('li', null, r)))) : null),
      h('details', null, h('summary', null, 'How this score was calculated'), scoreTable,
        h('p', { class: 'muted' }, 'This is an educational prioritisation aid, not a probability of compromise. A higher score means "look at this sooner", not "this is more likely malicious".')),
      h('details', null, h('summary', null, 'Show the ' + a.events.length + ' event(s) behind this finding'), miniEventTable(a.events)));
  }

  function renderAlerts() {
    const r = state.result;
    const box = $('alerts'); clear(box);
    const list = r.alerts.filter(alertMatches);
    const sevCounts = SEVERITIES.slice().reverse().map((s) => [s, r.alerts.filter((a) => a.severity === s).length]).filter((x) => x[1] > 0);
    $('alerts-count').textContent = anyFilter()
      ? 'Showing ' + list.length + ' of ' + r.alerts.length + ' findings (filters active).'
      : r.alerts.length + (r.alerts.length === 1 ? ' finding' : ' findings') + (sevCounts.length ? ': ' + sevCounts.map((x) => x[1] + ' ' + x[0]).join(', ') : '') + '.';
    if (!r.alerts.length) {
      box.appendChild(h('div', { class: 'empty' }, h('p', null, 'No findings were raised for this file.'), h('p', { class: 'muted' }, 'That is a result of the rules in this tool only. It does not prove nothing happened: the logs may not contain the events, auditing may be limited, or the activity may not match these rules.')));
      return;
    }
    if (!list.length) { box.appendChild(h('div', { class: 'empty' }, h('p', null, 'No findings match the current filters.'))); return; }
    list.forEach((a, i) => box.appendChild(alertCard(a, i)));
  }

  /* ---- administrative / privilege activity ---- */
  function renderAdmin() {
    const r = state.result;
    const box = $('admin'); clear(box);
    if (!r.adminEvents.length) {
      box.appendChild(h('p', { class: 'muted' }, 'No account creation, privilege changes, service installs or log clearing were found in this file.'));
      return;
    }
    const types = r.adminSummary.length;
    box.appendChild(h('p', null, 'This file contains ' + plural(types, 'type') + ' of administrative activity: ' + r.adminSummary.map((x) => x[1] + ' × ' + x[0].toLowerCase()).join('; ') + '.'));
    box.appendChild(h('p', { class: 'muted' }, 'These are listed together for context only. The tool does not assume that events by different users are connected. Look at who performed each action and decide for yourself.'));
    const rows = r.adminEvents.filter(eventMatches);
    if (!rows.length) { box.appendChild(h('p', { class: 'muted' }, 'No administrative events match the current filters.')); return; }
    const tbl = h('table', { class: 'data-table' },
      h('caption', { class: 'sr-only' }, 'Administrative and privilege activity in time order'),
      h('thead', null, h('tr', null, ['Time', 'Event ID', 'Activity', 'Affected account', 'Performed by', 'Detail'].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, rows.slice(0, 200).map((e) => h('tr', null,
        h('td', null, e.timeText || 'n/a'), h('td', { class: 'mono' }, String(e.eventId)), h('td', null, e.name),
        h('td', null, (e.eventId === 1102 || e.eventId === 7045) ? '—' : (e.f.account || '—')),
        h('td', null, e.eventId === 1102 ? (e.f.account || '—') : (e.f.actor || (e.eventId === 7045 ? e.f.account : '') || '—')),
        h('td', null, e.eventId === 4728 || e.eventId === 4732 ? 'Group: ' + (e.f.group || 'unknown') : e.eventId === 7045 ? (e.f.service || '') + (e.f.serviceFile ? ' (' + e.f.serviceFile + ')' : '') : '—')))));
    box.appendChild(h('div', { class: 'table-wrap' }, tbl));
  }

  /* ---- event table ---- */
  function eventDetail(e) {
    const bits = [];
    if (e.f.logonType) bits.push('Logon type ' + e.f.logonType + (LOGON_TYPES[e.f.logonType] ? ' (' + LOGON_TYPES[e.f.logonType].split(' (')[0] + ')' : ''));
    if (e.f.failureReason) bits.push(e.f.failureReason);
    if (e.f.group) bits.push('Group: ' + e.f.group);
    if (e.f.process) bits.push('Process: ' + e.f.process);
    if (e.f.parent) bits.push('Parent: ' + e.f.parent);
    if (e.f.service) bits.push('Service: ' + e.f.service);
    return bits.join(' · ');
  }

  function renderEvents() {
    const r = state.result;
    const list = r.sorted.filter(eventMatches);
    const box = $('events'); clear(box);
    const pages = Math.max(1, Math.ceil(list.length / PAGE_SIZE));
    if (state.page >= pages) state.page = pages - 1;
    const slice = list.slice(state.page * PAGE_SIZE, (state.page + 1) * PAGE_SIZE);
    $('events-count').textContent = anyFilter()
      ? 'Showing ' + list.length.toLocaleString() + ' of ' + r.sorted.length.toLocaleString() + ' events (filters active), oldest first.'
      : r.sorted.length.toLocaleString() + ' events, oldest first.';
    if (!slice.length) { box.appendChild(h('div', { class: 'empty' }, h('p', null, 'No events match the current filters.'))); return; }
    const tbl = h('table', { class: 'data-table events-table' },
      h('caption', { class: 'sr-only' }, 'Parsed events'),
      h('thead', null, h('tr', null, ['Time (as exported)', 'Event ID', 'Severity', 'Event', 'Account', 'Source IP', 'Workstation / host', 'Details'].map((c) => h('th', { scope: 'col' }, c)))),
      h('tbody', null, slice.map((e) => {
        const detail = eventDetail(e);
        return h('tr', null,
          h('td', null, e.timeText || 'n/a'),
          h('td', { class: 'mono' }, String(e.eventId)),
          h('td', null, sevBadge(e.severity)),
          h('td', null, e.name),
          h('td', null, e.f.account || '—'),
          h('td', { class: 'mono' }, e.f.ip || '—'),
          h('td', null, e.f.workstation || e.computer || '—'),
          h('td', null, detail ? h('span', null, detail) : null,
            e.message ? h('details', { class: 'raw' }, h('summary', null, 'Raw message'), h('pre', null, e.message)) : (detail ? null : '—')));
      })));
    box.appendChild(h('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': 'Parsed events table, scrollable' }, tbl));
    box.appendChild(h('div', { class: 'pager' },
      h('button', { type: 'button', class: 'btn', disabled: state.page === 0, onclick: () => { state.page--; renderEvents(); $('events-heading').scrollIntoView(); } }, 'Previous'),
      h('span', { 'aria-live': 'polite' }, 'Page ' + (state.page + 1) + ' of ' + pages),
      h('button', { type: 'button', class: 'btn', disabled: state.page >= pages - 1, onclick: () => { state.page++; renderEvents(); $('events-heading').scrollIntoView(); } }, 'Next')));
  }

  /* ---- static educational content ---- */
  function buildReference() {
    const body = $('ref-body'); clear(body);
    REFERENCE_ORDER.forEach((id) => {
      const c = CATALOG[id];
      body.appendChild(h('tr', null,
        h('th', { scope: 'row', class: 'mono' }, String(id)),
        h('td', null, c.name),
        h('td', null, c.plain),
        h('td', null, c.why)));
    });
  }

  function buildDemoButtons() {
    const box = $('demo-buttons'); clear(box);
    ['normal', 'failures', 'guessing', 'privilege', 'cleared', 'mixed'].forEach((k, i) => {
      box.appendChild(h('button', { type: 'button', class: 'btn btn-demo', 'data-demo': k, onclick: () => loadDemo(k) },
        h('span', { class: 'btn-step', 'aria-hidden': 'true' }, String(i + 1)), DEMO_META[k].label));
    });
  }

  /* ---- settings ---- */
  function syncSettingsInputs() {
    $('fail-threshold').value = String(state.config.failThreshold);
    $('window-minutes').value = String(state.config.windowMinutes);
    $('window-enabled').checked = state.config.useWindow;
  }

  function onSettingsChange() {
    const msg = $('settings-msg');
    const t = parseInt($('fail-threshold').value, 10);
    const w = parseInt($('window-minutes').value, 10);
    let problem = '';
    if (!(t >= 1 && t <= 1000)) problem = 'Failed login threshold must be a whole number from 1 to 1000.';
    else if (!$('window-minutes').disabled && !(w >= 1 && w <= 1440)) problem = 'Time window must be a whole number of minutes from 1 to 1440.';
    msg.textContent = problem;
    if (problem) return;
    state.config.failThreshold = t;
    if (w >= 1 && w <= 1440) state.config.windowMinutes = w;
    state.config.useWindow = $('window-enabled').checked;
    if (state.built) { runAnalysis(false); }
  }

  function resetDefaults() {
    state.config = Object.assign({}, DEFAULTS);
    syncSettingsInputs();
    $('settings-msg').textContent = 'Settings reset to defaults.';
    if (state.built) runAnalysis(false);
  }

  function clearData() {
    state.built = null; state.result = null; state.fileName = '';
    $('results').hidden = true;
    $('file-input').value = '';
    showStatus('info', 'No file loaded', ['Choose a CSV file or load a demo dataset to begin. Cleared data is gone from this page.']);
  }

  /* ---- init ---- */
  function initUi() {
    buildDemoButtons();
    buildReference();
    syncSettingsInputs();
    showStatus('info', 'No file loaded', ['Choose a CSV file or load a demo dataset to begin.']);

    const input = $('file-input');
    input.addEventListener('change', () => { handleFile(input.files[0]); });

    const zone = $('dropzone');
    ['dragenter', 'dragover'].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.add('drag'); }));
    ['dragleave', 'drop'].forEach((ev) => zone.addEventListener(ev, (e) => { e.preventDefault(); zone.classList.remove('drag'); }));
    zone.addEventListener('drop', (e) => { const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]; if (f) handleFile(f); });
    // Stop the browser from navigating to a file that is dropped outside the box.
    ['dragover', 'drop'].forEach((ev) => window.addEventListener(ev, (e) => e.preventDefault()));

    $('fail-threshold').addEventListener('input', onSettingsChange);
    $('window-minutes').addEventListener('input', onSettingsChange);
    $('window-enabled').addEventListener('change', () => { onSettingsChange(); if (state.built) renderTimeNote(); });
    $('reset-defaults').addEventListener('click', resetDefaults);
    $('clear-data').addEventListener('click', clearData);

    ['f-eventid', 'f-account', 'f-severity', 'f-ip', 'f-category'].forEach((id) => $(id).addEventListener('change', readFilters));
    $('f-search').addEventListener('input', readFilters);
    $('f-clear').addEventListener('click', () => {
      ['f-eventid', 'f-account', 'f-severity', 'f-ip', 'f-category'].forEach((id) => { $(id).value = ''; });
      $('f-search').value = '';
      readFilters();
    });

    const copyBtn = $('copy-ps');
    if (copyBtn) {
      copyBtn.addEventListener('click', () => {
        const text = $('ps-command').textContent;
        const done = (m) => { $('copy-msg').textContent = m; };
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(() => done('Command copied.'), () => done('Could not copy automatically. Select the text and copy it.'));
        } else done('Select the text and copy it.');
      });
    }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initUi);
  else initUi();
})(typeof window !== 'undefined' ? window : globalThis);
