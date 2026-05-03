/* Analysis page JS */

/* ── File Size Benchmark ─────────────────────────────────────────── */
document.getElementById("btn-bench-filesize").addEventListener("click", async () => {
  const status = document.getElementById("bench-fs-status");
  status.textContent = "Running (may take ~15 seconds)…";
  try {
    const res  = await fetch("/api/performance", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: "file_size" }),
    });
    const data = await res.json();
    if (data.error) { status.textContent = "Error: " + data.error; return; }

    const results = data.results;
    const labels  = results.map(r => r.file_size_kb + " KB");
    buildPerfChart("fileSizeChart", labels, [
      { label: "Hashing",      data: results.map(r => r.hash_avg),   borderColor: "#6c757d", tension: 0.3 },
      { label: "Signing",      data: results.map(r => r.sign_avg),   borderColor: "#0d6efd", tension: 0.3 },
      { label: "Verification", data: results.map(r => r.verify_avg), borderColor: "#198754", tension: 0.3 },
    ]);
    document.getElementById("fileSizeChart").dataset.xlabel = "File Size";
    status.textContent = "Done. Averaged over 5 runs per file size.";
  } catch (e) {
    status.textContent = "Failed: " + e.message;
  }
});

/* ── Key Size Benchmark ──────────────────────────────────────────── */
document.getElementById("btn-bench-keysize").addEventListener("click", async () => {
  const status = document.getElementById("bench-ks-status");
  status.textContent = "Running (generating keys for each size)…";
  try {
    const res  = await fetch("/api/performance", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode: "key_size" }),
    });
    const data = await res.json();
    if (data.error) { status.textContent = "Error: " + data.error; return; }

    const results = data.results;
    const labels  = results.map(r => r.key_size + "-bit");
    buildPerfChart("keySizeChart", labels, [
      { label: "Signing",      data: results.map(r => r.sign_avg),   borderColor: "#0d6efd", tension: 0.3, fill: false },
      { label: "Verification", data: results.map(r => r.verify_avg), borderColor: "#198754", tension: 0.3, fill: false },
    ]);
    status.textContent = "Done. Averaged over 5 runs per key size.";
  } catch (e) {
    status.textContent = "Failed: " + e.message;
  }
});

/* ── Manual Avalanche ────────────────────────────────────────────── */
document.getElementById("btn-run-avalanche").addEventListener("click", async () => {
  const f1 = document.getElementById("av-orig-file").files[0];
  const f2 = document.getElementById("av-mod-file").files[0];
  if (!f1 || !f2) return alert("Select both original and modified files.");

  const fd = new FormData();
  fd.append("file1", f1);
  fd.append("file2", f2);

  try {
    const res  = await fetch("/api/compare", { method: "POST", body: fd });
    const data = await res.json();
    if (data.error) return alert(data.error);

    const av = data.avalanche;
    document.getElementById("av-analysis-result").classList.remove("d-none");
    document.getElementById("av-a-hash1").textContent      = av.original_hash;
    document.getElementById("av-a-hash2").textContent      = av.modified_hash;
    document.getElementById("av-a-flip-count").textContent = av.flip_count;
    document.getElementById("av-a-flip-pct").textContent   = av.flip_percent;
    renderAvalancheGrid("av-analysis-grid", av.cells);
  } catch (e) {
    alert("Error: " + e.message);
  }
});

/* ── Attack Simulation ───────────────────────────────────────────── */
document.getElementById("btn-load-attack-analysis").addEventListener("click", async () => {
  try {
    const res  = await fetch("/api/attack_sim");
    const data = await res.json();
    const levels = data.levels;

    // Table
    let html = `<table class="table table-bordered table-sm security-table">
      <thead class="table-dark"><tr>
        <th>Key Size</th><th>Security Bits</th><th>Status</th><th>Factoring Estimate</th><th>NIST</th>
      </tr></thead><tbody>`;
    levels.forEach(l => {
      const rowCls = l.color === "danger" ? "table-danger" : l.color === "warning" ? "table-warning" : l.color === "success" ? "table-success" : "";
      html += `<tr class="${rowCls}">
        <td><strong>${l.key_size}-bit</strong></td>
        <td>${l.security_bits}</td>
        <td><span class="badge bg-${l.color}">${l.status}</span></td>
        <td class="small">${l.factoring_time}</td>
        <td class="small">${l.nist_status}</td>
      </tr>`;
    });
    html += "</tbody></table>";
    document.getElementById("attack-analysis-table").innerHTML = html;

    // Security bits bar chart
    const chart = document.getElementById("securityChart");
    chart.classList.remove("d-none");
    if (chart._chart) chart._chart.destroy();
    chart._chart = new Chart(chart, {
      type: "bar",
      data: {
        labels: levels.map(l => l.key_size + "-bit"),
        datasets: [{
          label: "Security Bits",
          data: levels.map(l => l.security_bits),
          backgroundColor: levels.map(l =>
            l.color === "danger" ? "#dc354588" : l.color === "warning" ? "#ffc10788" : l.color === "success" ? "#19875488" : "#0d6efd88"
          ),
          borderColor: levels.map(l =>
            l.color === "danger" ? "#dc3545" : l.color === "warning" ? "#ffc107" : l.color === "success" ? "#198754" : "#0d6efd"
          ),
          borderWidth: 2,
        }],
      },
      options: {
        responsive: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { title: { display: true, text: "RSA Key Size" } },
          y: { title: { display: true, text: "Equivalent Security (bits)" }, beginAtZero: true },
        },
      },
    });
  } catch (e) {
    document.getElementById("attack-analysis-table").innerHTML = "<p class='text-danger'>Failed to load: " + e.message + "</p>";
  }
});
