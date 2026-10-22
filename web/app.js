'use strict';
const $ = id => document.getElementById(id);
const state = {files: [], job: null, offset: 0, generation: 0, busy: false, running: false, ready: false, output: '', report: null, reportGeneration: 0};
const active = status => ['STARTING', 'RUNNING'].includes(status);
const enc = encodeURIComponent;
const number = (n, unit = '', digits = 1) => n == null ? '—' : `${Number(n).toFixed(digits)}${unit}`;
const bytes = n => n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KiB`;
function text(id, value) { $(id).textContent = value; }
function error(message = '') { text('error', message); $('error').hidden = !message; }
async function api(path, options = {}) {
    const response = await fetch(`/api${path}`, {...options, signal: AbortSignal.timeout(path === '/compile' ? 35000 : 15000), cache: 'no-store'});
    const data = await response.json();
    if (!response.ok) { const e = new Error(data.error || `Request failed (${response.status})`); e.data = data; e.status = response.status; throw e; }
    return data;
}
const post = (path, data = {}) => api(path, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data)});
function controls() {
    const locked = state.busy || state.running;
    $('configuration').disabled = locked;
    $('run').disabled = locked || !state.ready;
    $('stop').disabled = !state.running || state.busy;
    $('compile').disabled = locked || !/\.(c|cpp|cc|cxx)$/i.test($('target').value);
    $('upload').disabled = locked;
    document.querySelectorAll('.file button').forEach(b => b.disabled = locked);
}
async function checkSystem() {
    try {
        const d = await api('/status'); state.ready = d.ready;
        text('connection', d.ready ? '● Kernel ready' : '○ Setup required');
        text('cgroup-ready', d.ready ? 'Ready' : 'Not ready');
        text('system-diagnostics', d.output || d.error || 'No diagnostic output.');
        if (!d.ready) error('Kernel containment is not ready. Inspect raw kernel diagnostics; run sudo ./scripts/setup_cgroups.sh in Linux.');
    } catch (e) {state.ready = false; text('connection', '○ Server disconnected'); text('cgroup-ready', 'Unavailable'); error(`System check: ${e.message}`);}
    controls();
}
function selectFile(name) {
    $('target').value = name;
    $('command-label').hidden = !!name; $('args-label').hidden = !name;
    document.querySelectorAll('.file').forEach(el => el.classList.toggle('selected', el.dataset.name === name));
    controls();
}
async function files() {
    try {
        const loaded = await api('/files');
        const selected = $('target').value;
        state.files = loaded.filter(f => !f.filename.startsWith('.'));
        $('files').replaceChildren(); $('target').replaceChildren(new Option('Custom command', ''));
        for (const file of state.files) {
            $('target').add(new Option(file.filename, file.filename));
            const row = document.createElement('div'); row.className = 'file'; row.dataset.name = file.filename;
            const choose = document.createElement('button'); choose.className = 'file-select';
            const name = document.createElement('strong'); name.textContent = file.filename;
            const info = document.createElement('small'); info.textContent = `${file.file_type.toUpperCase()} · ${bytes(file.size_bytes)}`;
            choose.append(name, info); choose.onclick = () => selectFile(file.filename);
            const remove = document.createElement('button'); remove.className = 'file-remove'; remove.textContent = '×'; remove.setAttribute('aria-label', `Remove ${file.filename}`);
            remove.onclick = async () => {try {await api(`/files/${enc(file.filename)}`, {method: 'DELETE'}); await files();} catch(e) {error(e.message);}};
            row.append(choose, remove); $('files').append(row);
        }
        if (!state.files.length) text('files', 'No staged files. Browse or drop a workload.');
        text('file-count', `${state.files.length} files`); selectFile(state.files.some(f => f.filename === selected) ? selected : '');
    } catch(e) {text('file-message', `Could not load files: ${e.message}`);}
}
async function upload(list) {
    if (state.running || state.busy) return;
    state.busy = true; controls(); error();
    let last = ''; const failures = [];
    for (const file of list) {
        try {
            if (file.size > 10 * 1024 * 1024) throw new Error('Maximum size is 10 MiB.');
            if (!/\.(py|sh|c|cpp|cc|cxx|bin)$/i.test(file.name)) throw new Error('Supported workloads: .py, .sh, .c, .cpp, .cc, .cxx and Linux .bin.');
            text('file-message', `Staging ${file.name}…`);
            const form = new FormData(); form.append('file', file);
            await api('/files/upload', {method: 'POST', body: form}); last = file.name;
        } catch(e) { failures.push(`${file.name}: ${e.message}`); }
    }
    await files(); if (last) selectFile(last);
    text('file-message', last ? `Staged ${last}` : 'No files staged.'); error(failures.join('\n'));
    state.busy = false; $('upload').value = ''; controls();
}
function appendOutput(chunk) {
    // Bound the DOM independently of the backend log; offsets always refer to bytes on disk.
    state.output = (state.output + chunk).slice(-500000);
    text('terminal', state.output);
    if ($('auto-scroll').checked) $('terminal').scrollTop = $('terminal').scrollHeight;
}
function renderJob(d) {
    const r = d.report_data || {}, c = d.config || {}, m = d.metrics || {};
    if (!state.hydrated && d.config) {
        for (const [key, value] of Object.entries(c)) {
            if ($(key) && key !== 'adaptive') $(key).value = value;
        }
        $('adaptive').checked = !!c.adaptive;
        if (d.staged_file) {
            if (![...$('target').options].some(o => o.value === d.staged_file)) $('target').add(new Option(d.staged_file, d.staged_file));
            selectFile(d.staged_file); $('args').value = JSON.stringify(d.args || []);
        } else if (d.command) {
            selectFile(''); $('command').value = Array.isArray(d.command) ? d.command.map(a => "'" + a.replaceAll("'", "'\\''") + "'").join(' ') : d.command;
        }
        state.hydrated = true;
    }
    state.running = active(d.status); text('run-state', d.cancelled && state.running ? 'Stopping…' : d.status.replaceAll('_', ' '));
    text('elapsed', `Elapsed ${number(r.runtime_sec ?? d.runtime_sec, ' s')}`);
    text('exit', `Exit ${r.exit_code ?? d.exit_code ?? '—'}`);
    const measured = d.metrics_valid === true && d.history?.length > 0;
    text('metric-caption', measured ? `${state.running ? 'Measured' : 'Last sample'} · ${new Date(d.sample_received_at * 1000).toLocaleTimeString()}` : 'No valid measured sample available');
    text('isolation-state', (c.isolation || r.isolation) === 'isolated' ? 'Isolated mode required · no network · read-only workspace' : 'Resource-only mode · host access retained');
    const entries = [['cpu', m.cpu_pct, d.current_cpu_limit, '%'], ['memory', m.memory_mb, c.memory_limit, ' MiB'], ['pids', m.pids, c.pids_limit, '']];
    for (const [key, value, ceiling, unit] of entries) {
        text(`${key}-value`, measured ? number(value, unit, key === 'pids' ? 0 : 1) : '—');
        text(`${key}-ceiling`, `${key === 'cpu' ? 'Current quota' : key === 'memory' ? 'Ceiling' : 'PID limit'} ${number(ceiling, unit, 0)}`);
        $(`${key}-meter`).value = measured && ceiling > 0 ? Math.min(100, value / ceiling * 100) : 0;
    }
    text('attached', d.pid_attached === 'YES' ? 'Confirmed by supervisor' : 'Unconfirmed');
    text('pid', d.pid ?? r.pid ?? '—');
    text('timeout-status', c.timeout === 0 ? 'Unlimited' : number(c.timeout, ' s'));
    text('kernel', `${d.cgroup_path || r.cgroup_path || 'Cgroup unavailable'}\n\n${Object.entries(d.kernel_controls || {}).map(([k,v]) => `${k}: ${v ?? 'unavailable'}`).join('\n') || 'Live control files unavailable (job may have ended).'}`);
    text('policy-state', c.adaptive === false ? 'Disabled for this execution' : d.adaptive_triggered || r.adaptive_triggered ? 'Triggered · CPU quota reduced' : c.adaptive ? `Watching ≥ ${c.cpu_threshold}% for ${c.consecutive} samples` : 'Policy state unavailable');
    text('events', (d.events || r.events || []).join('\n') || 'No policy events recorded.');
    controls();
}
async function poll(id, generation) {
    if (generation !== state.generation) return;
    let delay = 500;
    try {
        const d = await api(`/job/${enc(id)}`);
        if (generation !== state.generation) return;
        renderJob(d);
        let chunk;
        try { chunk = await api(`/job/${enc(id)}/output?offset=${state.offset}&limit=65536`); }
        catch(e) { if (e.status === 404 && !active(d.status)) chunk = {output: '', next_offset: state.offset, eof: true}; else throw e; }
        if (generation !== state.generation) return;
        appendOutput(chunk.output); state.offset = chunk.next_offset; text('output-size', `${bytes(state.offset)} read`);
        text('stream-status', state.running ? 'Connected · polling stdout + stderr' : chunk.eof ? 'Execution ended · captured output complete. Display retains the last 500,000 characters.' : 'Reading remaining output…');
        if (!active(d.status) && chunk.eof) { localStorage.removeItem('axes.activeJob'); await history(); return; }
        if (chunk.output.length >= 60000) delay = 30;
    } catch(e) {
        if (generation !== state.generation) return;
        text('stream-status', `Telemetry/output unavailable: ${e.message}. Retrying…`); delay = 2000;
        if (e.status === 404) {state.running = false; controls(); localStorage.removeItem('axes.activeJob'); text('run-state', 'Job unavailable'); return;}
    }
    setTimeout(() => poll(id, generation), delay);
}
function watch(id) {
    state.job = id; state.offset = 0; state.output = ''; state.running = true; state.hydrated = false;
    text('terminal', ''); text('job-id', id); localStorage.setItem('axes.activeJob', id);
    controls(); poll(id, ++state.generation);
}
async function run(event) {
    event.preventDefault(); error(); state.busy = true; controls(); text('run-state', 'Launching…');
    try {
        const payload = {};
        for (const key of ['cpu_limit','memory_limit','pids_limit','timeout','cpu_threshold','consecutive','reduced_cpu','sample_interval']) payload[key] = Number($(key).value);
        payload.adaptive = $('adaptive').checked;
        payload.isolation = $('isolation').value;
        if ($('target').value) {
            let targetFile = $('target').value;
            if (/\.(c|cpp|cc|cxx)$/i.test(targetFile)) {
                text('run-state', 'Compiling source…');
                const comp = await post('/compile', {source_file: targetFile});
                appendOutput(comp.stdout + comp.stderr);
                if (!comp.success) throw new Error(comp.error || 'Compilation failed');
                await files();
                targetFile = comp.binary;
                selectFile(targetFile);
            }
            payload.staged_file = targetFile;
            payload.args = JSON.parse($('args').value || '[]');
            if (!Array.isArray(payload.args) || payload.args.some(a => typeof a !== 'string')) throw new Error('Arguments must be a JSON array of strings, for example ["--count", "10"].');
        } else payload.command = $('command').value;
        const d = await post('/run', payload); watch(d.job_id);
    } catch(e) {error(`Launch failed: ${e.message}`); text('run-state', 'Launch failed');}
    finally {state.busy = false; controls();}
}
async function compile() {
    state.busy = true; controls(); error(); text('run-state', 'Compiling…');
    try { const d = await post('/compile', {source_file: $('target').value}); appendOutput(d.stdout + d.stderr); text('stream-status', `Compilation completed · exit ${d.exit_code} · ${number(d.compile_time_sec, ' s')}`); await files(); selectFile(d.binary); text('run-state', 'Compiled · ready to run'); }
    catch(e) {appendOutput((e.data?.stdout || '') + (e.data?.stderr || '')); error(e.message); text('run-state', 'Compilation failed');}
    finally {state.busy = false; controls();}
}
async function history() {
    text('history-count', 'Loading…');
    try {
        const rows = await api('/history'); $('history-body').replaceChildren(); text('history-count', `${rows.length} executions`);
        for (const r of rows) {
            const tr = document.createElement('tr');
            for (const value of [(Array.isArray(r.command) ? r.command.join(' ') : r.command) || r.job_id, r.final_status || r.status, number(r.runtime_sec, ' s'), r.exit_code ?? '—', r.start_time || '—']) {const td = document.createElement('td'); td.textContent = value; tr.append(td);}
            if (r.command) {const small = document.createElement('small'); small.textContent = r.job_id; tr.firstChild.append(small);}
            const td = document.createElement('td'), b = document.createElement('button'); b.textContent = 'Open report'; b.onclick = () => openReport(r.job_id); td.append(b); tr.append(td); $('history-body').append(tr);
        }
        if (!rows.length) {const td = document.createElement('td'); td.colSpan = 6; td.textContent = 'No executions recorded yet. Run a workload to create a report.'; const tr = document.createElement('tr'); tr.append(td); $('history-body').append(tr);}
    } catch(e) {text('history-count', `Failed to load: ${e.message}`);}
}
async function openReport(id) {state.report = id; text('report-title', id); $('report-dialog').showModal(); await reportView(false);}
async function reportView(output) {
    const generation = ++state.reportGeneration; text('report-content', 'Loading…');
    try {const d = await api(`/report/${enc(state.report)}${output ? '/output' : ''}`); if(generation === state.reportGeneration) text('report-content', output ? d.output || '(No captured output)' : d.raw_text || JSON.stringify(d, null, 2));}
    catch(e) {if(generation === state.reportGeneration) text('report-content', e.message);}
}
$('run-form').onsubmit = run; $('compile').onclick = compile;
$('stop').onclick = async () => {state.busy = true; controls(); try {await post(`/job/${enc(state.job)}/stop`); text('run-state', 'Cancellation requested');} catch(e) {error(`Stop failed: ${e.message}`);} finally {state.busy = false; controls();}};
$('isolation').onchange = () => text('isolation-help', $('isolation').value === 'isolated' ? 'Read-only /workspace and system runtime; ephemeral /tmp. Setup failure prevents execution.' : 'Trusted workloads only: host files, processes and network remain accessible.');
$('compile').title = 'Compiles trusted source on the host. Compilation is not sandboxed; only subsequent isolated execution is contained.';
$('target').onchange = () => selectFile($('target').value);
$('upload').onchange = e => upload([...e.target.files]);
$('drop-zone').onkeydown = e => {if (e.key === 'Enter' || e.key === ' ') {e.preventDefault(); $('upload').click();}};
for (const name of ['dragover','dragleave','drop']) $('drop-zone').addEventListener(name, e => {e.preventDefault(); $('drop-zone').classList.toggle('dragging', name === 'dragover'); if (name === 'drop') upload([...e.dataTransfer.files]);});
$('refresh-files').onclick = files; $('refresh-history').onclick = history;
$('refresh-status').onclick = () => {error(); checkSystem();};
$('clear').onclick = () => {state.output = ''; text('terminal', '');};
$('copy').onclick = async () => {try {await navigator.clipboard.writeText(state.output); text('stream-status', 'Visible output copied.');} catch(e) {error(`Copy failed: ${e.message}`);}};
$('close-report').onclick = () => $('report-dialog').close();
$('report-data').onclick = () => reportView(false); $('report-output').onclick = () => reportView(true);
Promise.allSettled([checkSystem(), files(), history()]);
const restored = localStorage.getItem('axes.activeJob'); if (restored) watch(restored);
setInterval(checkSystem, 15000);
