let currentJobId = null;
let pollTimer = null;
let chartData = { timestamps: [], cpu: [], memory: [] };

document.addEventListener("DOMContentLoaded", () => {
    checkSystemStatus();
    fetchHistory();
    initChart();
});

function checkSystemStatus() {
    fetch("/api/status")
        .then(r => r.json())
        .then(data => {
            const dot = document.getElementById("system-status-dot");
            const text = document.getElementById("system-status-text");
            if (data.ready) {
                dot.className = "status-dot";
                text.textContent = "SYSTEM READY (cgroups v2 Active)";
                text.style.color = "var(--accent-green)";
            } else {
                dot.className = "status-dot error";
                text.textContent = "DELEGATION REQUIRED (Run sudo ./scripts/setup_cgroups.sh)";
                text.style.color = "var(--accent-red)";
            }
        })
        .catch(err => {
            const dot = document.getElementById("system-status-dot");
            const text = document.getElementById("system-status-text");
            dot.className = "status-dot error";
            text.textContent = "AXES Server Disconnected";
            text.style.color = "var(--accent-red)";
        });
}

function loadPreset(type) {
    if (type === 'cpu') {
        document.getElementById("cmd-input").value = "python3 workloads/cpu_burn.py";
        document.getElementById("cpu-limit-input").value = 200;
        document.getElementById("mem-limit-input").value = 512;
        document.getElementById("pids-limit-input").value = 64;
        document.getElementById("threshold-input").value = 100;
        document.getElementById("consecutive-input").value = 2;
        document.getElementById("reduced-cpu-input").value = 100;
        document.getElementById("interval-input").value = 0.8;
    } else if (type === 'mem') {
        document.getElementById("cmd-input").value = "python3 workloads/memory_stress.py";
        document.getElementById("cpu-limit-input").value = 200;
        document.getElementById("mem-limit-input").value = 256;
        document.getElementById("pids-limit-input").value = 64;
        document.getElementById("threshold-input").value = 150;
        document.getElementById("consecutive-input").value = 3;
        document.getElementById("reduced-cpu-input").value = 100;
        document.getElementById("interval-input").value = 0.5;
    } else if (type === 'proc') {
        document.getElementById("cmd-input").value = "./build/process_stress";
        document.getElementById("cpu-limit-input").value = 200;
        document.getElementById("mem-limit-input").value = 512;
        document.getElementById("pids-limit-input").value = 15;
        document.getElementById("threshold-input").value = 150;
        document.getElementById("consecutive-input").value = 3;
        document.getElementById("reduced-cpu-input").value = 100;
        document.getElementById("interval-input").value = 0.5;
    } else if (type === 'normal') {
        document.getElementById("cmd-input").value = "python3 workloads/normal_workload.py";
        document.getElementById("cpu-limit-input").value = 200;
        document.getElementById("mem-limit-input").value = 512;
        document.getElementById("pids-limit-input").value = 64;
        document.getElementById("threshold-input").value = 150;
        document.getElementById("consecutive-input").value = 3;
        document.getElementById("reduced-cpu-input").value = 100;
        document.getElementById("interval-input").value = 1.0;
    }
}

function handleRunJob(event) {
    event.preventDefault();
    const btn = document.getElementById("btn-run");
    btn.disabled = true;
    btn.innerHTML = "<span>⏳ Launching AXES Sandbox...</span>";

    const payload = {
        command: document.getElementById("cmd-input").value,
        job_id: document.getElementById("job-id-input").value,
        cpu_limit: parseFloat(document.getElementById("cpu-limit-input").value),
        memory_limit: parseInt(document.getElementById("mem-limit-input").value),
        pids_limit: parseInt(document.getElementById("pids-limit-input").value),
        cpu_threshold: parseFloat(document.getElementById("threshold-input").value),
        consecutive: parseInt(document.getElementById("consecutive-input").value),
        reduced_cpu: parseFloat(document.getElementById("reduced-cpu-input").value),
        sample_interval: parseFloat(document.getElementById("interval-input").value),
        adaptive: true
    };

    fetch("/api/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    })
    .then(r => r.json())
    .then(res => {
        btn.disabled = false;
        btn.innerHTML = "<span>▶ RUN JOB IN AXES SANDBOX</span>";

        if (res.success) {
            currentJobId = res.job_id;
            resetJobUI(currentJobId, payload);
            if (pollTimer) clearInterval(pollTimer);
            pollTimer = setInterval(() => pollJobStatus(currentJobId), 500);
        } else {
            alert("Error launching job: " + (res.error || "Unknown error"));
        }
    })
    .catch(err => {
        btn.disabled = false;
        btn.innerHTML = "<span>▶ RUN JOB IN AXES SANDBOX</span>";
        alert("Server error launching job: " + err);
    });
}

function resetJobUI(jobId, payload) {
    document.getElementById("active-job-id-badge").textContent = jobId;
    document.getElementById("info-status").textContent = "RUNNING";
    document.getElementById("info-status").style.color = "var(--accent-blue)";
    document.getElementById("info-cgroup").textContent = `/sys/fs/cgroup/axes/${jobId}`;
    document.getElementById("info-attached").textContent = "YES (Verified)";

    document.getElementById("limit-cpu-cfg").textContent = payload.cpu_limit + "%";
    document.getElementById("limit-mem-cfg").textContent = payload.memory_limit + " MB";
    document.getElementById("limit-pids-cfg").textContent = payload.pids_limit + " PIDs";

    const period = 100000;
    const quota = Math.round((payload.cpu_limit / 100.0) * period);
    document.getElementById("raw-cpu-max").textContent = `${quota} ${period}`;
    document.getElementById("raw-mem-max").textContent = `${payload.memory_limit * 1024 * 1024}`;
    document.getElementById("raw-swap-max").textContent = "0";
    document.getElementById("raw-pids-max").textContent = `${payload.pids_limit}`;

    document.getElementById("adapt-initial").textContent = payload.cpu_limit + "%";
    document.getElementById("adapt-current").textContent = payload.cpu_limit + "%";
    document.getElementById("adapt-threshold").textContent = "> " + payload.cpu_threshold + "%";
    document.getElementById("adapt-consecutive").textContent = payload.consecutive + " samples";

    const badge = document.getElementById("adaptive-badge");
    badge.className = "adaptive-status-badge normal";
    badge.textContent = "NORMAL";

    const terminal = document.getElementById("event-terminal");
    terminal.innerHTML = `<div class="log-entry">[0.0s] AXES Sandbox job ${jobId} initialized. CGroup /sys/fs/cgroup/axes/${jobId} created.</div>`;

    chartData = { timestamps: [], cpu: [], memory: [] };
    drawChart();
}

function pollJobStatus(jobId) {
    fetch(`/api/job/${jobId}`)
        .then(r => r.json())
        .then(data => {
            if (!data) return;

            if (data.pid) {
                document.getElementById("info-pid").textContent = data.pid;
            }

            const metrics = data.metrics || {};
            const cpuPct = metrics.cpu_pct || 0.0;
            const memMb = metrics.memory_mb || 0.0;
            const pids = metrics.pids || 1;
            const runtime = data.runtime_sec || 0.0;

            document.getElementById("val-cpu").textContent = cpuPct.toFixed(1) + "%";
            document.getElementById("val-mem").textContent = memMb.toFixed(1) + " MB";
            document.getElementById("val-pids").textContent = pids;
            document.getElementById("info-runtime").textContent = runtime.toFixed(1) + " s";

            if (chartData.timestamps.length === 0 || chartData.timestamps[chartData.timestamps.length - 1] !== runtime) {
                chartData.timestamps.push(runtime);
                chartData.cpu.push(cpuPct);
                chartData.memory.push(memMb);
                drawChart();
            }

            // Update events terminal
            if (data.events && data.events.length > 0) {
                const terminal = document.getElementById("event-terminal");
                let html = "";
                data.events.forEach(ev => {
                    let cls = "log-entry";
                    if (ev.includes("ADAPTIVE TRIGGER")) cls += " event-adapt";
                    else if (ev.includes("High CPU detected")) cls += " event-high";
                    html += `<div class="${cls}">${ev}</div>`;
                });
                terminal.innerHTML = html;
                terminal.scrollTop = terminal.scrollHeight;
            }

            // Adaptive status
            const badge = document.getElementById("adaptive-badge");
            if (data.adaptive_triggered) {
                badge.className = "adaptive-status-badge triggered";
                badge.textContent = "TRIGGERED (Reduced)";
                const currentCpu = data.current_cpu_limit || 100.0;
                document.getElementById("adapt-current").textContent = currentCpu + "%";
                const period = 100000;
                const quota = Math.round((currentCpu / 100.0) * period);
                document.getElementById("raw-cpu-max").textContent = `${quota} ${period}`;
            }

            // Status check
            if (data.status === "FINISHED" || data.status === "TERMINATED") {
                clearInterval(pollTimer);
                document.getElementById("info-status").textContent = data.status;
                document.getElementById("info-status").style.color = (data.status === "FINISHED") ? "var(--accent-green)" : "var(--accent-red)";
                fetchHistory();
            }
        })
        .catch(err => console.error("Poll error:", err));
}

function fetchHistory() {
    fetch("/api/history")
        .then(r => r.json())
        .then(list => {
            const tbody = document.getElementById("history-table-body");
            if (!list || list.length === 0) {
                tbody.innerHTML = `<tr><td colspan="9" style="text-align: center; color: var(--text-muted);">No execution history recorded yet.</td></tr>`;
                return;
            }

            let html = "";
            list.forEach(item => {
                const isKilled = item.status.includes("KILLED") || item.status.includes("TERMINATED");
                const statusColor = isKilled ? "var(--accent-red)" : "var(--accent-green)";
                const adaptColor = item.adaptive_triggered ? "var(--accent-amber)" : "var(--text-muted)";
                
                html += `
                <tr>
                    <td><code>${item.job_id}</code></td>
                    <td><code>${item.command}</code></td>
                    <td style="color: ${statusColor}; font-weight: 600;">${item.status}</td>
                    <td>${item.runtime_sec.toFixed(2)} s</td>
                    <td>${item.peak_cpu_pct.toFixed(1)}%</td>
                    <td>${item.peak_memory_mb.toFixed(1)} MB</td>
                    <td>${item.peak_pids}</td>
                    <td style="color: ${adaptColor}; font-weight: 600;">${item.adaptive_triggered ? 'TRIGGERED' : 'NORMAL'}</td>
                    <td><button class="btn-preset" onclick="openReportModal('${item.job_id}')">📄 View Report</button></td>
                </tr>
                `;
            });
            tbody.innerHTML = html;
        })
        .catch(err => console.error("History fetch error:", err));
}

function openReportModal(jobId) {
    document.getElementById("modal-title").textContent = `AXES Execution Report — ${jobId}`;
    document.getElementById("modal-report-body").textContent = "Loading report content...";
    document.getElementById("report-modal").classList.add("open");

    fetch(`/api/report/${jobId}`)
        .then(r => r.json())
        .then(data => {
            if (data && data.raw_text) {
                document.getElementById("modal-report-body").textContent = data.raw_text;
            } else {
                document.getElementById("modal-report-body").textContent = "Report text unavailable.";
            }
        })
        .catch(err => {
            document.getElementById("modal-report-body").textContent = "Failed to load report: " + err;
        });
}

function closeModal() {
    document.getElementById("report-modal").classList.remove("open");
}

/* Simple Canvas Line Chart */
function initChart() {
    drawChart();
}

function drawChart() {
    const canvas = document.getElementById("resource-chart");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const width = canvas.width = canvas.parentElement.clientWidth - 20;
    const height = canvas.height = 160;

    ctx.clearRect(0, 0, width, height);

    // Grid lines
    ctx.strokeStyle = "#21262d";
    ctx.lineWidth = 1;
    for (let y = 30; y < height; y += 40) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
    }

    if (chartData.timestamps.length < 2) {
        ctx.fillStyle = "#8b949e";
        ctx.font = "12px sans-serif";
        ctx.fillText("Waiting for real-time metric stream...", width / 2 - 100, height / 2);
        return;
    }

    const n = chartData.timestamps.length;
    const maxCpu = Math.max(200, ...chartData.cpu);

    // Draw CPU Line (Blue)
    ctx.strokeStyle = "#58a6ff";
    ctx.lineWidth = 2;
    ctx.beginPath();
    for (let i = 0; i < n; i++) {
        const x = (i / (n - 1)) * (width - 40) + 20;
        const y = height - 20 - (chartData.cpu[i] / maxCpu) * (height - 40);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    }
    ctx.stroke();

    // Draw Memory Line (Purple)
    const maxMem = Math.max(512, ...chartData.memory);
    ctx.strokeStyle = "#bc8cff";
    ctx.lineWidth = 2;
    ctx.beginPath();
    for (let i = 0; i < n; i++) {
        const x = (i / (n - 1)) * (width - 40) + 20;
        const y = height - 20 - (chartData.memory[i] / maxMem) * (height - 40);
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    }
    ctx.stroke();

    // Legend
    ctx.fillStyle = "#58a6ff";
    ctx.fillText("— CPU Usage (%)", 20, 15);
    ctx.fillStyle = "#bc8cff";
    ctx.fillText("— Memory (MB)", 140, 15);
}
