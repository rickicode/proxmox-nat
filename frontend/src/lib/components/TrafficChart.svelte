<script>
    import { onMount } from 'svelte';
    import { Chart, registerables } from 'chart.js';
    
    Chart.register(...registerables);

    let { history } = $props();
    let chartCanvas;
    let chart;

    $effect(() => {
        if (chart) {
            updateChart(history);
        }
    });

    onMount(() => {
        const ctx = chartCanvas.getContext('2d');
        chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Download (RX)',
                        data: [],
                        borderColor: 'rgb(59, 130, 246)', // blue-500
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        tension: 0.3,
                        fill: true,
                        pointRadius: 0,
                        borderWidth: 2
                    },
                    {
                        label: 'Upload (TX)',
                        data: [],
                        borderColor: 'rgb(168, 85, 247)', // purple-500
                        backgroundColor: 'rgba(168, 85, 247, 0.1)',
                        tension: 0.3,
                        fill: true,
                        pointRadius: 0,
                        borderWidth: 2
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false, // Diable animation for performance
                interaction: {
                    mode: 'index',
                    intersect: false,
                },
                plugins: {
                    legend: {
                        position: 'top',
                        labels: {
                            color: document.documentElement.classList.contains('dark') ? '#9ca3af' : '#4b5563'
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                let label = context.dataset.label || '';
                                if (label) {
                                    label += ': ';
                                }
                                if (context.parsed.y !== null) {
                                    label += formatBytes(context.parsed.y) + '/s';
                                }
                                return label;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        grid: {
                            color: document.documentElement.classList.contains('dark') ? '#374151' : '#e5e7eb',
                            display: false // Hide x grid for cleaner look
                        },
                        ticks: {
                            color: document.documentElement.classList.contains('dark') ? '#9ca3af' : '#4b5563',
                            maxTicksLimit: 6
                        }
                    },
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: document.documentElement.classList.contains('dark') ? '#374151' : '#e5e7eb'
                        },
                        ticks: {
                            color: document.documentElement.classList.contains('dark') ? '#9ca3af' : '#4b5563',
                            callback: function(value) {
                                return formatBytes(value) + '/s';
                            }
                        }
                    }
                }
            }
        });

        // Initialize with data if available
        if (history) {
            updateChart(history);
        }

        return () => {
            if (chart) chart.destroy();
        };
    });

    function updateChart(data) {
        if (!data || !chart) return;

        // Data is already sorted by time (oldest first) from backend
        // We might want to limit to 60 points if backend sends more
        
        chart.data.labels = data.map(d => formatTime(d.timestamp));
        chart.data.datasets[0].data = data.map(d => d.rx_rate);
        chart.data.datasets[1].data = data.map(d => d.tx_rate);
        
        chart.update('none'); // 'none' mode prevents animation for smooth updates
    }

    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function formatTime(timestamp) {
        const date = new Date(timestamp * 1000);
        return date.toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }
</script>

<div class="w-full h-80">
    <canvas bind:this={chartCanvas}></canvas>
</div>
