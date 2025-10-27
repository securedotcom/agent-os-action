// Agent OS Dashboard JavaScript

// Configuration
const CONFIG = {
    dataUrl: 'https://raw.githubusercontent.com/securedotcom/agent-os-metrics/main/data/latest-metrics.json',
    refreshInterval: 300000, // 5 minutes
};

// State
let allMetrics = [];
let charts = {
    trend: null,
    severity: null,
};

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    initializeEventListeners();
    loadDashboardData();
    
    // Auto-refresh every 5 minutes
    setInterval(loadDashboardData, CONFIG.refreshInterval);
});

// Event Listeners
function initializeEventListeners() {
    document.getElementById('refreshBtn').addEventListener('click', loadDashboardData);
    document.getElementById('repoFilter').addEventListener('change', applyFilters);
    document.getElementById('timeFilter').addEventListener('change', applyFilters);
    document.getElementById('typeFilter').addEventListener('change', applyFilters);
}

// Load dashboard data
async function loadDashboardData() {
    try {
        updateLastUpdated();
        
        // For demo purposes, generate sample data
        // In production, fetch from: await fetch(CONFIG.dataUrl)
        allMetrics = generateSampleData();
        
        populateFilters();
        updateOverviewStats();
        updateCharts();
        updateRepositoryHealth();
        updateRecentAudits();
        
    } catch (error) {
        console.error('Error loading dashboard data:', error);
        showError('Failed to load dashboard data. Please try again.');
    }
}

// Generate sample data (replace with actual API call in production)
function generateSampleData() {
    const repositories = [
        'securedotcom/Spring-Backend',
        'securedotcom/spring-fabric',
        'securedotcom/spring-topography-apis',
        'securedotcom/platform-dashboard-apis',
        'securedotcom/siem-agent-provisioning',
        'securedotcom/case_management_pipeline',
        'securedotcom/case-management-backend',
        'securedotcom/Risk-Register',
        'securedotcom/Spring-dashboard',
        'securedotcom/Spring_CIA_algorithm',
        'securedotcom/spring-attack-surface',
        'securedotcom/secure_data_retrieval_agent'
    ];
    
    const reviewTypes = ['audit', 'security', 'review'];
    const data = [];
    
    // Generate last 30 days of data
    for (let i = 0; i < 30; i++) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        
        repositories.forEach(repo => {
            if (Math.random() > 0.3) { // 70% chance of audit on any day
                data.push({
                    repository: repo,
                    timestamp: date.toISOString(),
                    review_type: reviewTypes[Math.floor(Math.random() * reviewTypes.length)],
                    blockers_found: Math.floor(Math.random() * 5),
                    suggestions_found: Math.floor(Math.random() * 15),
                    status: Math.random() > 0.3 ? 'pass' : 'fail',
                    commit: Math.random().toString(36).substring(7),
                    branch: 'main',
                    actor: 'github-actions'
                });
            }
        });
    }
    
    return data.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
}

// Populate filter dropdowns
function populateFilters() {
    const repoFilter = document.getElementById('repoFilter');
    const uniqueRepos = [...new Set(allMetrics.map(m => m.repository))];
    
    repoFilter.innerHTML = '<option value="all">All Repositories</option>';
    uniqueRepos.forEach(repo => {
        const option = document.createElement('option');
        option.value = repo;
        option.textContent = repo.split('/')[1]; // Show only repo name
        repoFilter.appendChild(option);
    });
}

// Apply filters
function applyFilters() {
    updateOverviewStats();
    updateCharts();
    updateRepositoryHealth();
    updateRecentAudits();
}

// Get filtered metrics
function getFilteredMetrics() {
    const repoFilter = document.getElementById('repoFilter').value;
    const timeFilter = parseInt(document.getElementById('timeFilter').value);
    const typeFilter = document.getElementById('typeFilter').value;
    
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - timeFilter);
    
    return allMetrics.filter(metric => {
        const matchesRepo = repoFilter === 'all' || metric.repository === repoFilter;
        const matchesTime = new Date(metric.timestamp) >= cutoffDate;
        const matchesType = typeFilter === 'all' || metric.review_type === typeFilter;
        
        return matchesRepo && matchesTime && matchesType;
    });
}

// Update overview statistics
function updateOverviewStats() {
    const filtered = getFilteredMetrics();
    
    const totalAudits = filtered.length;
    const criticalIssues = filtered.reduce((sum, m) => sum + m.blockers_found, 0);
    const passedAudits = filtered.filter(m => m.status === 'pass').length;
    const passRate = totalAudits > 0 ? Math.round((passedAudits / totalAudits) * 100) : 0;
    const avgFixTime = 12; // Mock data - would calculate from actual fix times
    
    document.getElementById('totalAudits').textContent = totalAudits;
    document.getElementById('criticalIssues').textContent = criticalIssues;
    document.getElementById('passRate').textContent = `${passRate}%`;
    document.getElementById('avgFixTime').textContent = `${avgFixTime}h`;
}

// Update charts
function updateCharts() {
    const filtered = getFilteredMetrics();
    
    updateTrendChart(filtered);
    updateSeverityChart(filtered);
}

// Update trend chart
function updateTrendChart(metrics) {
    const ctx = document.getElementById('trendChart').getContext('2d');
    
    // Group by date
    const dateGroups = {};
    metrics.forEach(m => {
        const date = new Date(m.timestamp).toLocaleDateString();
        if (!dateGroups[date]) {
            dateGroups[date] = { blockers: 0, suggestions: 0 };
        }
        dateGroups[date].blockers += m.blockers_found;
        dateGroups[date].suggestions += m.suggestions_found;
    });
    
    const labels = Object.keys(dateGroups).slice(0, 30).reverse();
    const blockers = labels.map(date => dateGroups[date].blockers);
    const suggestions = labels.map(date => dateGroups[date].suggestions);
    
    if (charts.trend) {
        charts.trend.destroy();
    }
    
    charts.trend = new Chart(ctx, {
        type: 'line',
        data: {
            labels,
            datasets: [
                {
                    label: 'Critical Issues',
                    data: blockers,
                    borderColor: '#ef4444',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    tension: 0.4,
                },
                {
                    label: 'Suggestions',
                    data: suggestions,
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    tension: 0.4,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

// Update severity chart
function updateSeverityChart(metrics) {
    const ctx = document.getElementById('severityChart').getContext('2d');
    
    const totalBlockers = metrics.reduce((sum, m) => sum + m.blockers_found, 0);
    const totalSuggestions = metrics.reduce((sum, m) => sum + m.suggestions_found, 0);
    const totalPass = metrics.filter(m => m.status === 'pass').length;
    
    if (charts.severity) {
        charts.severity.destroy();
    }
    
    charts.severity = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'Suggestions', 'Clean Audits'],
            datasets: [{
                data: [totalBlockers, totalSuggestions, totalPass],
                backgroundColor: ['#ef4444', '#f59e0b', '#10b981'],
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                }
            }
        }
    });
}

// Update repository health grid
function updateRepositoryHealth() {
    const repoGrid = document.getElementById('repoGrid');
    
    // Get metrics for each repository
    const repoStats = {};
    allMetrics.forEach(m => {
        if (!repoStats[m.repository]) {
            repoStats[m.repository] = {
                name: m.repository,
                audits: 0,
                blockers: 0,
                suggestions: 0,
                lastAudit: m.timestamp,
            };
        }
        
        repoStats[m.repository].audits++;
        repoStats[m.repository].blockers += m.blockers_found;
        repoStats[m.repository].suggestions += m.suggestions_found;
        
        if (new Date(m.timestamp) > new Date(repoStats[m.repository].lastAudit)) {
            repoStats[m.repository].lastAudit = m.timestamp;
        }
    });
    
    repoGrid.innerHTML = '';
    
    Object.values(repoStats).forEach(repo => {
        const status = repo.blockers === 0 ? 'healthy' : (repo.blockers < 3 ? 'warning' : 'critical');
        const statusLabel = status === 'healthy' ? 'Healthy' : (status === 'warning' ? 'Warning' : 'Critical');
        
        const repoItem = document.createElement('div');
        repoItem.className = 'repo-item';
        repoItem.innerHTML = `
            <div class="repo-item-header">
                <span class="repo-name">${repo.name.split('/')[1]}</span>
                <span class="repo-status status-${status}">${statusLabel}</span>
            </div>
            <div class="repo-stats">
                <div class="repo-stat">
                    <span class="repo-stat-value">${repo.audits}</span>
                    <span>Audits</span>
                </div>
                <div class="repo-stat">
                    <span class="repo-stat-value">${repo.blockers}</span>
                    <span>Blockers</span>
                </div>
                <div class="repo-stat">
                    <span class="repo-stat-value">${repo.suggestions}</span>
                    <span>Suggestions</span>
                </div>
            </div>
        `;
        
        repoGrid.appendChild(repoItem);
    });
}

// Update recent audits table
function updateRecentAudits() {
    const filtered = getFilteredMetrics();
    const tbody = document.querySelector('#auditsTable tbody');
    
    tbody.innerHTML = '';
    
    filtered.slice(0, 20).forEach(metric => {
        const row = document.createElement('tr');
        const timestamp = new Date(metric.timestamp).toLocaleString();
        const repoName = metric.repository.split('/')[1];
        const statusClass = metric.status === 'pass' ? 'badge-pass' : 'badge-fail';
        const typeClass = `badge-${metric.review_type}`;
        
        row.innerHTML = `
            <td>${timestamp}</td>
            <td>${repoName}</td>
            <td><span class="badge ${typeClass}">${metric.review_type}</span></td>
            <td>${metric.blockers_found}</td>
            <td>${metric.suggestions_found}</td>
            <td><span class="badge ${statusClass}">${metric.status.toUpperCase()}</span></td>
            <td>
                <a href="#" class="btn-sm">View Report</a>
            </td>
        `;
        
        tbody.appendChild(row);
    });
}

// Update last updated timestamp
function updateLastUpdated() {
    const now = new Date().toLocaleString();
    document.getElementById('lastUpdated').textContent = `Last updated: ${now}`;
}

// Show error message
function showError(message) {
    console.error(message);
    // Could implement a toast notification here
}

