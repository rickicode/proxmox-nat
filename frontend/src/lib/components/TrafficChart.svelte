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
                        label: 'RX (Download)',
                        data: [],
                        borderColor: 'rgb(59, 130, 246)', // blue-500
                        backgroundColor: 'rgba(59, 130, 246, 0.1)',
                        tension: 0.4,
                        fill: true
                    },
                    {
                        label: 'TX (Upload)',
                        data: [],
                        borderColor: 'rgb(168, 85, 247)', // purple-500
                        backgroundColor: 'rgba(168, 85, 247, 0.1)',
                        tension: 0.4,
                        fill: true
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
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
                                    label += formatBytes(context.parsed.y);
                                }
                                return label;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        grid: {
                            color: document.documentElement.classList.contains('dark') ? '#374151' : '#e5e7eb'
                        },
                        ticks: {
                            color: document.documentElement.classList.contains('dark') ? '#9ca3af' : '#4b5563'
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
                                return formatBytes(value);
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

        // Process daily history (reverse it so oldest is first)
        const sortedData = [...data].reverse();
        
        chart.data.labels = sortedData.map(d => formatDate(d.date));
        chart.data.datasets[0].data = sortedData.map(d => d.rx_bytes);
        chart.data.datasets[1].data = sortedData.map(d => d.tx_bytes);
        
        chart.update();
    }

    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function formatDate(dateStr) {
        // Simple date formatting (YYYY-MM-DD to DD/MM)
        try {
            const date = new Date(dateStr);
            return `${date.getDate()}/${date.getMonth() + 1}`;
        } catch (e) {
            return dateStr;
        }
    }
</script>

<div class="w-full h-80">
    <canvas bind:this={chartCanvas}></canvas>
</div>
