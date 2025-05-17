export function setupStorage(graph, dataStore) {
  // File input for import
  const importInput = document.getElementById('import-input');
  const exportBtn = document.getElementById('export-btn');
  const importBtn = document.getElementById('import-btn');
  const saveBtn = document.getElementById('save-btn');
  const loadBtn = document.getElementById('load-btn');
  
  // Handle file import
  importInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    
    if (file) {
      const reader = new FileReader();
      
      reader.onload = (event) => {
        try {
          const data = JSON.parse(event.target.result);
          importData(data);
        } catch (error) {
          console.error('Import error:', error);
          showNotification('Error importing investigation data', 'error');
        }
      };
      
      reader.readAsText(file);
      e.target.value = ''; // Reset input
    }
  });
  
  // Export button click handler
  exportBtn.addEventListener('click', () => {
    exportData();
  });
  
  // Import button click handler
  importBtn.addEventListener('click', () => {
    importInput.click();
  });
  
  // Save button click handler
  saveBtn.addEventListener('click', () => {
    saveToLocalStorage();
  });
  
  // Load button click handler
  loadBtn.addEventListener('click', () => {
    loadFromLocalStorage();
  });
  
  // Import data
  function importData(data) {
    try {
      // Basic validation
      if (!data.nodes || !Array.isArray(data.nodes)) {
        throw new Error('Invalid data format: missing nodes array');
      }
      
      if (!data.edges || !Array.isArray(data.edges)) {
        throw new Error('Invalid data format: missing edges array');
      }
      
      // Import to data store
      dataStore.importData(data);
      
      // Refresh graph
      graph.renderGraph();
      
      showNotification('Investigation data imported successfully', 'success');
    } catch (error) {
      console.error('Import validation error:', error);
      showNotification(`Import error: ${error.message}`, 'error');
    }
  }
  
  // Export data
  function exportData() {
    const data = dataStore.exportData();
    const json = JSON.stringify(data, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const link = document.createElement('a');
    link.href = url;
    link.download = `investigation_${formatDate(new Date())}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    // Cleanup
    setTimeout(() => {
      URL.revokeObjectURL(url);
    }, 100);
    
    showNotification('Investigation exported successfully', 'success');
  }
  
  // Save to localStorage
  function saveToLocalStorage() {
    try {
      const data = dataStore.exportData();
      localStorage.setItem('graphIntel_investigation', JSON.stringify(data));
      showNotification('Investigation saved locally', 'success');
    } catch (error) {
      console.error('Save error:', error);
      showNotification('Error saving investigation', 'error');
    }
  }
  
  // Load from localStorage
  function loadFromLocalStorage() {
    try {
      const savedData = localStorage.getItem('graphIntel_investigation');
      
      if (savedData) {
        const data = JSON.parse(savedData);
        dataStore.importData(data);
        graph.renderGraph();
        showNotification('Investigation loaded', 'success');
      } else {
        showNotification('No saved investigation found', 'warning');
      }
    } catch (error) {
      console.error('Load error:', error);
      showNotification('Error loading investigation', 'error');
    }
  }
  
  // Helper: Format date for filename
  function formatDate(date) {
    return date.toISOString().split('T')[0];
  }
  
  // Helper: Show notification
  function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    notification.innerHTML = `
      <div class="notification-icon">
        <i class="fas fa-${getNotificationIcon(type)}"></i>
      </div>
      <div class="notification-message">${message}</div>
    `;
    
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
  
  // Return public API
  return {
    importData,
    exportData,
    saveToLocalStorage,
    loadFromLocalStorage
  };
}