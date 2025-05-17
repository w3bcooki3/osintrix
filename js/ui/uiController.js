import { getNodeTypes, getNodeTypeName } from '../graph/nodeTypes.js';

export function setupUIControls(graph, dataStore) {
  // UI elements
  const newNodeBtn = document.getElementById('new-node-btn');
  const newEdgeBtn = document.getElementById('new-edge-btn');
  const searchInput = document.getElementById('search-input');
  const saveBtn = document.getElementById('save-btn');
  const loadBtn = document.getElementById('load-btn');
  const exportBtn = document.getElementById('export-btn');
  const importBtn = document.getElementById('import-btn');
  const themeToggle = document.getElementById('theme-toggle');
  const filterBtn = document.getElementById('filter-btn');
  const filterOptions = document.querySelector('.filter-options');
  const entityTypeFilters = document.querySelectorAll('.entity-type-filter');
  
  // Set up buttons
  newNodeBtn.addEventListener('click', () => {
    showModal('node-modal');
    document.getElementById('node-modal-title').textContent = 'Add New Node';
    document.getElementById('node-form').reset();
    
    // Clear any existing preview
    const imagePreview = document.getElementById('image-preview');
    imagePreview.style.backgroundImage = '';
    imagePreview.classList.remove('has-image');
    document.getElementById('remove-image').classList.add('hidden');
    
    // Clear metadata fields
    const metadataFields = document.getElementById('metadata-fields');
    metadataFields.innerHTML = '';
  });
  
  newEdgeBtn.addEventListener('click', () => {
    showModal('edge-modal');
    document.getElementById('edge-modal-title').textContent = 'Add New Connection';
    document.getElementById('edge-form').reset();
    
    // Populate node dropdowns
    populateNodeDropdowns();
  });
  
  // Toggle filter options
  filterBtn.addEventListener('click', () => {
    filterOptions.classList.toggle('hidden');
  });
  
  // Apply entity type filters
  entityTypeFilters.forEach(filter => {
    filter.addEventListener('change', () => {
      applyFilters();
    });
  });
  
  // Search functionality
  searchInput.addEventListener('input', debounce(() => {
    const query = searchInput.value.trim();
    
    if (query) {
      const results = dataStore.searchNodes(query);
      
      // Update entity list
      updateEntityList(results);
      
      // Highlight matching nodes on graph
      graph.highlightNodes(results.map(node => node.id));
    } else {
      // Clear search, show all nodes
      updateEntityList(dataStore.getAllNodes());
      graph.clearHighlights();
    }
  }, 300));
  
  // Export/Import functionality
  exportBtn.addEventListener('click', () => {
    const data = dataStore.exportData();
    const json = JSON.stringify(data, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const link = document.getElementById('export-link');
    link.href = url;
    link.download = `investigation_${formatDate(new Date())}.json`;
    link.click();
    
    // Cleanup
    setTimeout(() => {
      URL.revokeObjectURL(url);
    }, 100);
  });
  
  importBtn.addEventListener('click', () => {
    const importInput = document.getElementById('import-input');
    importInput.click();
  });
  
  document.getElementById('import-input').addEventListener('change', (e) => {
    const file = e.target.files[0];
    
    if (file) {
      const reader = new FileReader();
      
      reader.onload = (event) => {
        try {
          const data = JSON.parse(event.target.result);
          dataStore.importData(data);
          
          // Refresh the graph
          graph.renderGraph();
          
          // Show success message
          showNotification('Investigation imported successfully', 'success');
        } catch (error) {
          console.error('Import error:', error);
          showNotification('Error importing file: Invalid format', 'error');
        }
      };
      
      reader.readAsText(file);
      e.target.value = ''; // Reset the input
    }
  });
  
  // Save/Load to local storage
  saveBtn.addEventListener('click', () => {
    const data = dataStore.exportData();
    localStorage.setItem('graphIntel_investigation', JSON.stringify(data));
    showNotification('Investigation saved', 'success');
  });
  
  loadBtn.addEventListener('click', () => {
    const savedData = localStorage.getItem('graphIntel_investigation');
    
    if (savedData) {
      try {
        const data = JSON.parse(savedData);
        dataStore.importData(data);
        
        // Refresh the graph
        graph.renderGraph();
        
        showNotification('Investigation loaded', 'success');
      } catch (error) {
        console.error('Load error:', error);
        showNotification('Error loading saved investigation', 'error');
      }
    } else {
      showNotification('No saved investigation found', 'warning');
    }
  });
  
  // Dark/Light theme toggle
  themeToggle.addEventListener('click', () => {
    const body = document.body;
    const isDarkTheme = body.classList.toggle('dark-theme');
    
    // Update icon
    const themeIcon = themeToggle.querySelector('i');
    themeIcon.className = isDarkTheme ? 'fas fa-sun' : 'fas fa-moon';
    
    // Save preference
    localStorage.setItem('graphIntel_theme', isDarkTheme ? 'dark' : 'light');
  });
  
  // Load theme preference
  function loadThemePreference() {
    const savedTheme = localStorage.getItem('graphIntel_theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    
    if ((savedTheme === 'dark') || (savedTheme === null && prefersDark)) {
      document.body.classList.add('dark-theme');
      themeToggle.querySelector('i').className = 'fas fa-sun';
    } else {
      document.body.classList.remove('dark-theme');
      themeToggle.querySelector('i').className = 'fas fa-moon';
    }
  }
  
  // Close modal buttons
  document.querySelectorAll('.close-modal, .cancel-modal').forEach(button => {
    button.addEventListener('click', () => {
      hideModal();
    });
  });
  
  // Close modal when clicking outside
  document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        hideModal();
      }
    });
  });
  
  // Keyboard shortcuts
  document.addEventListener('keydown', (e) => {
    // Escape key to close modals
    if (e.key === 'Escape') {
      hideModal();
    }
  });
  
  // Helper function to update entity list
  function updateEntityList(nodes) {
    const entityList = document.getElementById('entity-list');
    entityList.innerHTML = '';
    
    nodes.forEach(node => {
      const li = document.createElement('li');
      li.className = 'entity-item';
      li.dataset.id = node.id;
      
      li.innerHTML = `
        <div class="entity-icon ${node.type}">
          <i class="fas fa-${getNodeIcon(node.type)}"></i>
        </div>
        <div class="entity-info">
          <h4 class="entity-label">${node.label}</h4>
          <div class="entity-type">${getNodeTypeName(node.type)}</div>
        </div>
      `;
      
      li.addEventListener('click', () => {
        // Select this node in the graph
        graph.selectNode(node.id);
        graph.centerOnNode(node.id);
        
        // Add selected class
        document.querySelectorAll('.entity-item').forEach(item => {
          item.classList.remove('selected');
        });
        li.classList.add('selected');
      });
      
      entityList.appendChild(li);
    });
  }
  
  // Apply filters to the entity list
  function applyFilters() {
    // Get selected entity types
    const selectedTypes = Array.from(entityTypeFilters)
      .filter(checkbox => checkbox.checked)
      .map(checkbox => checkbox.value);
    
    // Filter nodes by selected types
    const filteredNodes = dataStore.getAllNodes().filter(node => 
      selectedTypes.includes(node.type)
    );
    
    // Update entity list with filtered nodes
    updateEntityList(filteredNodes);
  }
  
  // Populate node dropdowns in the edge form
  function populateNodeDropdowns() {
    const sourceSelect = document.getElementById('source-node');
    const targetSelect = document.getElementById('target-node');
    
    // Clear options
    sourceSelect.innerHTML = '';
    targetSelect.innerHTML = '';
    
    // Add default empty option
    sourceSelect.innerHTML = '<option value="">Select source node</option>';
    targetSelect.innerHTML = '<option value="">Select target node</option>';
    
    // Add all nodes as options
    const nodes = dataStore.getAllNodes();
    
    nodes.forEach(node => {
      const sourceOption = document.createElement('option');
      sourceOption.value = node.id;
      sourceOption.textContent = `${node.label} (${getNodeTypeName(node.type)})`;
      sourceSelect.appendChild(sourceOption);
      
      const targetOption = document.createElement('option');
      targetOption.value = node.id;
      targetOption.textContent = `${node.label} (${getNodeTypeName(node.type)})`;
      targetSelect.appendChild(targetOption);
    });
    
    // If a node is selected in the graph, preselect it as source
    const selectedNodeId = graph.getSelectedNodeId();
    if (selectedNodeId) {
      sourceSelect.value = selectedNodeId;
    }
  }
  
  // Show a modal
  function showModal(modalId) {
    document.getElementById(modalId).classList.remove('hidden');
  }
  
  // Hide all modals
  function hideModal() {
    document.querySelectorAll('.modal').forEach(modal => {
      modal.classList.add('hidden');
    });
  }
  
  // Show notification
  function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.innerHTML = `
      <div class="notification-icon">
        <i class="fas fa-${getNotificationIcon(type)}"></i>
      </div>
      <div class="notification-message">${message}</div>
    `;
    
    // Add to the document
    document.body.appendChild(notification);
    
    // Animate in
    setTimeout(() => {
      notification.classList.add('show');
    }, 10);
    
    // Remove after delay
    setTimeout(() => {
      notification.classList.remove('show');
      setTimeout(() => {
        notification.remove();
      }, 300);
    }, 3000);
  }
  
  // Get icon for notification type
  function getNotificationIcon(type) {
    switch (type) {
      case 'success': return 'check-circle';
      case 'error': return 'exclamation-circle';
      case 'warning': return 'exclamation-triangle';
      default: return 'info-circle';
    }
  }
  
  // Get icon for node type
  function getNodeIcon(type) {
    switch (type) {
      case 'person': return 'user';
      case 'organization': return 'building';
      case 'wallet': return 'wallet';
      case 'ip': return 'network-wired';
      case 'location': return 'map-marker-alt';
      case 'transaction': return 'dollar-sign';
      case 'social': return 'share-alt';
      case 'domain': return 'globe';
      case 'website': return 'link';
      default: return 'circle';
    }
  }
  
  // Format date helper
  function formatDate(date) {
    return date.toISOString().split('T')[0];
  }
  
  // Debounce helper function
  function debounce(func, delay) {
    let timeout;
    return function() {
      const context = this;
      const args = arguments;
      clearTimeout(timeout);
      timeout = setTimeout(() => func.apply(context, args), delay);
    };
  }
  
  // Initialize
  loadThemePreference();
  updateEntityList(dataStore.getAllNodes());
}