/**
 * Debounce functions for better performance
 * (c) 2018 Chris Ferdinandi, MIT License, https://gomakethings.com
 * @param  {Function} fn The function to debounce
 * https://gomakethings.com/debouncing-your-javascript-events/
 */
var debounce=function(a){var e;return function(){var n=this,i=arguments;e&&window.cancelAnimationFrame(e),e=window.requestAnimationFrame(function(){a.apply(n,i)})}};

/**
 * Main code section
 */

// calculate 40rem in px (based off body font size)
var mqw = parseInt(getComputedStyle(document.body).fontSize) * 40;

// Selection of HTML objects
const burger = document.querySelector('.burger i');
const nav = document.querySelector('#header-nav');

// Defining a function
function toggleNav() {
  burger.classList.toggle('fa-bars');
  burger.classList.toggle('fa-times');
  nav.classList.toggle('nav-active');
}
// Calling the function after click event occurs
burger.addEventListener('click', function() {
  toggleNav();
});

/**
 * Onboarding modal functions
 */

function closeOnboarding() {
  const modal = document.getElementById('onboarding-modal');
  if (modal) {
    modal.classList.remove('opened');
  }
}

function openOnboarding() {
  const modal = document.getElementById('onboarding-modal');
  if (modal) {
    modal.classList.add('opened');
  }
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(function() {
    // Could add a toast notification here
    console.log('Copied to clipboard:', text);
  }).catch(function(err) {
    console.error('Failed to copy:', err);
  });
}

async function setPassword() {
  const password = document.getElementById('mqtt-password').value;
  const confirmPassword = document.getElementById('mqtt-password-confirm').value;
  const messageDiv = document.getElementById('password-message');

  // Clear previous messages
  messageDiv.textContent = '';
  messageDiv.className = 'message';

  // Validation
  if (!password || !confirmPassword) {
    messageDiv.textContent = 'Please fill in both password fields';
    messageDiv.classList.add('error');
    return;
  }

  if (password !== confirmPassword) {
    messageDiv.textContent = 'Passwords do not match';
    messageDiv.classList.add('error');
    return;
  }

  if (password.length < 8) {
    messageDiv.textContent = 'Password must be at least 8 characters';
    messageDiv.classList.add('error');
    return;
  }

  // Send password to server
  try {
    const response = await fetch('/api/set-mqtt-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ password: password })
    });

    const data = await response.json();

    if (data.success) {
      messageDiv.textContent = 'Password set successfully!';
      messageDiv.classList.add('success');

      // Show the other sections
      document.getElementById('password-section').style.display = 'none';
      document.getElementById('credentials-section').style.display = 'block';
      document.getElementById('mqtt-settings-section').style.display = 'block';
      document.getElementById('topic-section').style.display = 'block';
      document.getElementById('lora-settings-section').style.display = 'block';
      document.getElementById('channel-section').style.display = 'block';

      // Store password in session for display (not secure but for convenience)
      document.getElementById('user-password').textContent = password;
    } else {
      messageDiv.textContent = data.message || 'Failed to set password';
      messageDiv.classList.add('error');
    }
  } catch (error) {
    messageDiv.textContent = 'Error connecting to server';
    messageDiv.classList.add('error');
    console.error('Error:', error);
  }
}

/**
 * Node table management
 */

let autoRefreshTimeout = null;
let isLoadingNodes = false;

function getFilters() {
  const connectedOnly = document.getElementById('filter-connected')?.checked || false;
  const meshOnly = document.getElementById('filter-mesh')?.checked || false;
  const gatewayOnly = document.getElementById('filter-gateway')?.checked || false;

  return { connectedOnly, meshOnly, gatewayOnly };
}

async function loadNodes(isAdmin = false) {
  // Prevent concurrent requests
  if (isLoadingNodes) {
    return;
  }

  isLoadingNodes = true;

  try {
    const filters = getFilters();
    const params = new URLSearchParams();

    if (filters.connectedOnly) params.append('connected_only', 'true');
    if (filters.meshOnly) params.append('mesh_only', 'true');
    if (filters.gatewayOnly) params.append('valid_gateway_only', 'true');
    if (isAdmin) params.append('all_users', 'true');

    const response = await fetch(`/api/nodes?${params.toString()}`);

    if (!response.ok) {
      throw new Error('Failed to fetch nodes');
    }

    const data = await response.json();

    renderNodesTable(data.nodes, isAdmin);
    renderOtherClientsTable(data.other_clients, isAdmin);

  } catch (error) {
    console.error('Error loading nodes:', error);
    document.getElementById('nodes-tbody').innerHTML =
      '<tr><td colspan="' + (isAdmin ? '11' : '10') + '" class="error-message">Error loading nodes</td></tr>';
    document.getElementById('other-clients-tbody').innerHTML =
      '<tr><td colspan="' + (isAdmin ? '4' : '3') + '" class="error-message">Error loading clients</td></tr>';
  } finally {
    isLoadingNodes = false;

    // Schedule next refresh if auto-refresh is enabled (admin only)
    if (isAdmin) {
      const autoRefresh = document.getElementById('auto-refresh')?.checked || false;
      if (autoRefresh) {
        scheduleNextRefresh(isAdmin);
      }
    }
  }
}

function scheduleNextRefresh(isAdmin) {
  // Clear any existing timeout
  if (autoRefreshTimeout) {
    clearTimeout(autoRefreshTimeout);
  }

  // Schedule next refresh in 15 seconds
  autoRefreshTimeout = setTimeout(() => {
    loadNodes(isAdmin);
  }, 15000);
}

function renderNodesTable(nodes, isAdmin) {
  const tbody = document.getElementById('nodes-tbody');

  if (!nodes || nodes.length === 0) {
    tbody.innerHTML = '<tr><td colspan="' + (isAdmin ? '11' : '10') + '"><i>No nodes found</i></td></tr>';
    return;
  }

  tbody.innerHTML = nodes.map(node => {
    const validationClass = node.validation_errors && node.validation_errors.length > 0 ? 'has-errors' : '';
    const validationTitle = node.validation_errors && node.validation_errors.length > 0
      ? 'Validation errors: ' + node.validation_errors.join(', ')
      : '';

    return `
      <tr class="${validationClass}" title="${validationTitle}">
        <td>${node.node_id || ''}</td>
        <td>${node.short_name || ''}</td>
        <td>${node.long_name || 'unknown'}</td>
        <td>${node.node_role || ''}</td>
        <td>${node.proxy_type || '<i>none</i>'}</td>
        <td>${node.is_connected ? node.address : '<i>disconnected</i>'}</td>
        <td>${node.root_topic || ''}</td>
        <td>${node.last_seen || ''}</td>
        <td>${node.is_downlink ? 'Yes' : 'No'}</td>
        <td>${node.is_valid_gateway ? 'Yes' : 'No'}</td>
        ${isAdmin ? `<td>${node.user_display || ''}</td>` : ''}
      </tr>
    `;
  }).join('');
}

function renderOtherClientsTable(clients, isAdmin) {
  const tbody = document.getElementById('other-clients-tbody');

  if (!clients || clients.length === 0) {
    tbody.innerHTML = '<tr><td colspan="' + (isAdmin ? '4' : '3') + '"><i>No other clients</i></td></tr>';
    return;
  }

  tbody.innerHTML = clients.map(client => `
    <tr>
      <td>${client.client_id}</td>
      <td>${client.address || '<i>disconnected</i>'}</td>
      <td>${client.root_topic || ''}</td>
      ${isAdmin ? `<td>${client.user_display || ''}</td>` : ''}
    </tr>
  `).join('');
}

// Attach event listeners for filters
document.addEventListener('DOMContentLoaded', function() {
  const filterControls = ['filter-connected', 'filter-mesh', 'filter-gateway'];

  filterControls.forEach(id => {
    const element = document.getElementById(id);
    if (element) {
      element.addEventListener('change', function() {
        // Check if page has isAdmin defined
        const isAdmin = typeof window.isAdmin !== 'undefined' ? window.isAdmin : false;
        loadNodes(isAdmin);
      });
    }
  });

  // Auto-refresh toggle (admin only)
  const autoRefreshToggle = document.getElementById('auto-refresh');
  if (autoRefreshToggle) {
    autoRefreshToggle.addEventListener('change', function() {
      if (!this.checked && autoRefreshTimeout) {
        // Stop auto-refresh
        clearTimeout(autoRefreshTimeout);
        autoRefreshTimeout = null;
      } else if (this.checked) {
        // Start auto-refresh
        const isAdmin = typeof window.isAdmin !== 'undefined' ? window.isAdmin : false;
        scheduleNextRefresh(isAdmin);
      }
    });
  }
});