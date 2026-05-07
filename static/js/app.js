document.addEventListener('DOMContentLoaded', () => {
    const url1Input = document.getElementById('url1');
    const url2Input = document.getElementById('url2');
    const error1 = document.getElementById('error1');
    const error2 = document.getElementById('error2');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const toggleCompareBtn = document.getElementById('toggleCompareBtn');
    const compareGroup = document.getElementById('compareGroup');
    const loadingIndicator = document.getElementById('loadingIndicator');
    const resultsContainer = document.getElementById('resultsContainer');
    const resultCard2 = document.getElementById('resultCard2');
    const diffAlert = document.getElementById('diffAlert');

    let compareMode = false;

    // Chart instances to destroy before re-rendering
    let charts = [];

    // URL Validation
    const isValidUrl = (string) => {
        try {
            const url = new URL(string);
            return url.protocol === "http:" || url.protocol === "https:";
        } catch (_) {
            return false;
        }
    }

    url1Input.addEventListener('input', () => {
        if (!isValidUrl(url1Input.value)) {
            error1.textContent = "Please enter a valid URL starting with http:// or https://";
        } else {
            error1.textContent = "";
        }
    });

    url2Input.addEventListener('input', () => {
        if (!isValidUrl(url2Input.value)) {
            error2.textContent = "Please enter a valid URL starting with http:// or https://";
        } else {
            error2.textContent = "";
        }
    });

    toggleCompareBtn.addEventListener('click', () => {
        compareMode = !compareMode;
        if (compareMode) {
            compareGroup.style.display = 'flex';
            toggleCompareBtn.textContent = 'Disable Compare Mode';
            resultCard2.style.display = 'block';
            resultsContainer.style.gridTemplateColumns = '1fr 1fr';
        } else {
            compareGroup.style.display = 'none';
            toggleCompareBtn.textContent = 'Toggle Compare Mode';
            resultCard2.style.display = 'none';
            resultsContainer.style.gridTemplateColumns = '1fr';
            diffAlert.style.display = 'none';
            document.getElementById('compareTimelineContainer').style.display = 'none';
        }
    });

    analyzeBtn.addEventListener('click', async () => {
        const url1 = url1Input.value.trim();
        const url2 = url2Input.value.trim();

        if (!isValidUrl(url1)) {
            error1.textContent = "Valid URL required.";
            return;
        }

        if (compareMode && !isValidUrl(url2)) {
            error2.textContent = "Valid URL required.";
            return;
        }

        // Show loading
        loadingIndicator.style.display = 'block';
        resultsContainer.style.display = 'none';
        diffAlert.style.display = 'none';
        document.getElementById('compareTimelineContainer').style.display = 'none';

        // Clear previous charts
        charts.forEach(c => c.destroy());
        charts = [];

        try {
            if (compareMode) {
                const response = await fetch('/api/compare', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url1, url2 })
                });

                const data = await response.json();
                if (data.error) throw new Error(data.error);

                renderFingerprint(data.fingerprint1, 1, true);
                renderFingerprint(data.fingerprint2, 2, true);
                document.getElementById('compareTimelineContainer').style.display = 'block';
                renderCompareTimeline(data.fingerprint1.bytes_per_sec, data.fingerprint2.bytes_per_sec, 'compareTimelineChart');
                renderDiff(data.diff, data.fingerprint1, data.fingerprint2);

            } else {
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: url1 })
                });

                const data = await response.json();
                if (data.error) throw new Error(data.error);

                renderFingerprint(data, 1);
            }

            loadingIndicator.style.display = 'none';
            resultsContainer.style.display = compareMode ? 'grid' : 'block';

        } catch (err) {
            loadingIndicator.style.display = 'none';
            alert(`Error: ${err.message}`);
        }
    });

    function renderFingerprint(fp, index, isCompare = false) {
        // Render Stats
        const statsDiv = document.getElementById(`stats1`).cloneNode(false);
        statsDiv.id = `stats${index}`;

        const statsHtml = `
            <div class="stat-item"><span class="stat-label">Behavior</span><span class="stat-value">${fp.behavior_label.label} (${(fp.behavior_label.confidence * 100).toFixed(0)}%)</span></div>
            <div class="stat-item"><span class="stat-label">Total Packets</span><span class="stat-value">${fp.total_packets}</span></div>
            <div class="stat-item"><span class="stat-label">Total Bytes</span><span class="stat-value">${fp.total_bytes}</span></div>
            <div class="stat-item"><span class="stat-label">Mean Packet Size</span><span class="stat-value">${fp.mean_packet_size} B</span></div>
            <div class="stat-item"><span class="stat-label">Unique IPs</span><span class="stat-value">${fp.unique_ips}</span></div>
            <div class="stat-item"><span class="stat-label">Top Protocol</span><span class="stat-value">${fp.top_protocol}</span></div>
        `;
        document.getElementById(`stats${index}`).innerHTML = statsHtml;

        // Render Charts
        renderProtocolChart(fp.protocol_distribution, `protocolPieChart${index}`);
        renderPacketSizeChart(fp.size_histogram, `packetSizeHist${index}`);
        if (!isCompare) {
            renderTrafficTimeline(fp.bytes_per_sec, `trafficTimeline${index}`);
            document.getElementById(`trafficTimeline${index}`).parentElement.style.display = 'block';
        } else {
            document.getElementById(`trafficTimeline${index}`).parentElement.style.display = 'none';
        }
    }

    function renderDiff(diff, fp1, fp2) {
        diffAlert.style.display = 'block';
        diffAlert.innerHTML = `Comparison Summary: Difference highlights are shown on the cards below.`;

        function addDiffIndicator(index, labelText, val1, val2) {
            const statsDiv = document.getElementById(`stats${index}`);
            const items = statsDiv.getElementsByClassName('stat-item');
            for (let item of items) {
                const labelSpan = item.querySelector('.stat-label');
                if (labelSpan && labelSpan.textContent === labelText) {
                    const isHigher = val1 > val2;
                    const isLower = val1 < val2;
                    if (isHigher || isLower) {
                        const color = isHigher ? 'var(--danger)' : 'var(--success)';
                        const arrow = isHigher ? 'Higher ↑' : 'Lower ↓';
                        const indicator = document.createElement('div');
                        indicator.style.color = color;
                        indicator.style.fontSize = '0.8rem';
                        indicator.style.marginTop = '4px';
                        indicator.textContent = arrow;
                        item.appendChild(indicator);
                    }
                }
            }
        }

        addDiffIndicator(1, 'Total Bytes', fp1.total_bytes, fp2.total_bytes);
        addDiffIndicator(2, 'Total Bytes', fp2.total_bytes, fp1.total_bytes);
        addDiffIndicator(1, 'Unique IPs', fp1.unique_ips, fp2.unique_ips);
        addDiffIndicator(2, 'Unique IPs', fp2.unique_ips, fp1.unique_ips);
        addDiffIndicator(1, 'Mean Packet Size', fp1.mean_packet_size, fp2.mean_packet_size);
        addDiffIndicator(2, 'Mean Packet Size', fp2.mean_packet_size, fp1.mean_packet_size);
    }

    // Chart.js Default styling
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.font.family = 'Inter';

    function renderProtocolChart(distribution, canvasId) {
        const ctx = document.getElementById(canvasId).getContext('2d');
        const labels = Object.keys(distribution);
        const data = Object.values(distribution);

        const chart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6'],
                    borderWidth: 0,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom' },
                    title: { display: true, text: 'Protocol Distribution (%)', color: '#f8fafc' }
                }
            }
        });
        charts.push(chart);
    }

    function renderPacketSizeChart(histogramData, canvasId) {
        const ctx = document.getElementById(canvasId).getContext('2d');
        const chart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: ['0-100', '101-500', '501-1000', '1001-1500', '1500+'],
                datasets: [{
                    label: 'Packet Counts',
                    data: histogramData,
                    backgroundColor: '#60a5fa',
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: { display: true, text: 'Packet Size Histogram', color: '#f8fafc' }
                }
            }
        });
        charts.push(chart);
    }

    function renderTrafficTimeline(bytesPerSec, canvasId) {
        const ctx = document.getElementById(canvasId).getContext('2d');
        const labels = bytesPerSec.map((_, i) => `${i+1}s`);

        const chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Bytes per second',
                    data: bytesPerSec,
                    borderColor: '#a78bfa',
                    backgroundColor: 'rgba(167, 139, 250, 0.2)',
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: { display: true, text: 'Traffic Timeline', color: '#f8fafc' }
                },
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
        charts.push(chart);
    }

    function renderCompareTimeline(data1, data2, canvasId) {
        const ctx = document.getElementById(canvasId).getContext('2d');
        const maxLen = Math.max(data1.length, data2.length);
        const labels = Array.from({length: maxLen}, (_, i) => `${i+1}s`);

        const chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Site 1 Bytes/s',
                        data: data1,
                        borderColor: '#3b82f6',
                        backgroundColor: 'rgba(59, 130, 246, 0.2)',
                        fill: true,
                        tension: 0.4
                    },
                    {
                        label: 'Site 2 Bytes/s',
                        data: data2,
                        borderColor: '#10b981',
                        backgroundColor: 'rgba(16, 185, 129, 0.2)',
                        fill: true,
                        tension: 0.4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: { display: true, text: 'Comparison Traffic Timeline', color: '#f8fafc' }
                },
                scales: {
                    y: { beginAtZero: true }
                }
            }
        });
        charts.push(chart);
    }
});