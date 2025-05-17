export function setupContextMenu(graph, dataStore) {
  const contextMenu = document.getElementById('context-menu');
  let currentNodeId = null;
  let currentEdgeId = null;
  
  // Show context menu for node
  document.addEventListener('graph:nodeContextMenu', (e) => {
    const { nodeId, clientX, clientY } = e.detail;
    showContextMenu(clientX, clientY, 'node');
    currentNodeId = nodeId;
    currentEdgeId = null;
  });
  
  // Show context menu for edge
  document.addEventListener('graph:edgeContextMenu', (e) => {
    const { edgeId, clientX, clientY } = e.detail;
    showContextMenu(clientX, clientY, 'edge');
    currentEdgeId = edgeId;
    currentNodeId = null;
  });
  
  // Hide context menu when clicking anywhere else
  document.addEventListener('click', (e) => {
    if (!contextMenu.contains(e.target)) {
      hideContextMenu();
    }
  });
  
  // Context menu actions
  document.querySelectorAll('#context-menu li').forEach(item => {
    item.addEventListener('click', () => {
      const action = item.dataset.action;
      
      if (currentNodeId) {
        handleNodeAction(action, currentNodeId);
      } else if (currentEdgeId) {
        handleEdgeAction(action, currentEdgeId);
      }
      
      hideContextMenu();
    });
  });
  
  // Handle node actions
  function handleNodeAction(action, nodeId) {
    switch (action) {
      case 'edit':
        editNode(nodeId);
        break;
      case 'connect':
        createConnection(nodeId);
        break;
      case 'delete':
        deleteNode(nodeId);
        break;
      case 'highlight':
        highlightConnections(nodeId);
        break;
    }
  }
  
  // Handle edge actions
  function handleEdgeAction(action, edgeId) {
    switch (action) {
      case 'edit':
        editEdge(edgeId);
        break;
      case 'delete':
        deleteEdge(edgeId);
        break;
    }
  }
  
  // Edit node
  function editNode(nodeId) {
    const node = dataStore.getNode(nodeId);
    
    if (node) {
      // Show node modal with current data
      const modal = document.getElementById('node-modal');
      modal.classList.remove('hidden');
      
      // Set modal title
      document.getElementById('node-modal-title').textContent = 'Edit Node';
      
      // Fill form with node data
      const form = document.getElementById('node-form');
      form.dataset.nodeId = nodeId;
      
      document.getElementById('node-type').value = node.type;
      document.getElementById('node-label').value = node.label;
      document.getElementById('node-description').value = node.description || '';
      document.getElementById('node-date').value = node.date || '';
      document.getElementById('node-time').value = node.time || '';
      document.getElementById('node-location').value = node.location || '';
      document.getElementById('node-tags').value = Array.isArray(node.tags) ? node.tags.join(', ') : node.tags || '';
      document.getElementById('node-notes').value = node.notes || '';
      
      // Handle image
      const imagePreview = document.getElementById('image-preview');
      const removeImageBtn = document.getElementById('remove-image');
      
      if (node.image) {
        imagePreview.style.backgroundImage = `url(${node.image})`;
        imagePreview.classList.add('has-image');
        removeImageBtn.classList.remove('hidden');
      } else {
        imagePreview.style.backgroundImage = '';
        imagePreview.classList.remove('has-image');
        removeImageBtn.classList.add('hidden');
      }
      
      // Add metadata fields
      const metadataFields = document.getElementById('metadata-fields');
      metadataFields.innerHTML = '';
      
      if (node.metadata) {
        for (const key in node.metadata) {
          addMetadataField(key, node.metadata[key]);
        }
      }
    }
  }
  
  // Create connection from a node
  function createConnection(nodeId) {
    // Show edge modal
    const modal = document.getElementById('edge-modal');
    modal.classList.remove('hidden');
    
    // Set modal title
    document.getElementById('edge-modal-title').textContent = 'Add New Connection';
    
    // Reset the form
    const form = document.getElementById('edge-form');
    form.reset();
    
    // Populate node dropdowns
    populateNodeDropdowns(nodeId);
  }
  
  // Delete node
  function deleteNode(nodeId) {
    if (confirm('Are you sure you want to delete this node? This will also delete all connections to/from this node.')) {
      dataStore.deleteNode(nodeId);
      graph.renderGraph();
    }
  }
  
  // Highlight connections
  function highlightConnections(nodeId) {
    // Get all edges connected to this node
    const edges = dataStore.getEdgesByNode(nodeId);
    
    // Get all connected node IDs
    const connectedNodeIds = edges.map(edge => 
      edge.source === nodeId ? edge.target : edge.source
    );
    
    // Highlight nodes and edges
    graph.highlightNodes([nodeId, ...connectedNodeIds]);
    graph.highlightEdges(edges.map(edge => edge.id));
    
    // Add a way to clear highlights (timeout or button)
    setTimeout(() => {
      graph.clearHighlights();
    }, 5000);
  }
  
  // Edit edge
  function editEdge(edgeId) {
    const edge = dataStore.getEdge(edgeId);
    
    if (edge) {
      // Show edge modal with current data
      const modal = document.getElementById('edge-modal');
      modal.classList.remove('hidden');
      
      // Set modal title
      document.getElementById('edge-modal-title').textContent = 'Edit Connection';
      
      // Fill form with edge data
      const form = document.getElementById('edge-form');
      form.dataset.edgeId = edgeId;
      
      // Populate node dropdowns first
      populateNodeDropdowns();
      
      document.getElementById('source-node').value = edge.source;
      document.getElementById('target-node').value = edge.target;
      document.getElementById('edge-label').value = edge.label || '';
      document.getElementById('edge-description').value = edge.description || '';
      document.getElementById('edge-notes').value = edge.notes || '';
    }
  }
  
  // Delete edge
  function deleteEdge(edgeId) {
    if (confirm('Are you sure you want to delete this connection?')) {
      dataStore.deleteEdge(edgeId);
      graph.renderGraph();
    }
  }
  
  // Populate node dropdowns in the edge form
  function populateNodeDropdowns(selectedNodeId = null) {
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
    
    // If a node is selected, set it as source
    if (selectedNodeId) {
      sourceSelect.value = selectedNodeId;
    }
  }
  
  // Add a metadata field to the form
  function addMetadataField(key = '', value = '') {
    const metadataFields = document.getElementById('metadata-fields');
    
    const fieldDiv = document.createElement('div');
    fieldDiv.className = 'metadata-field form-row';
    
    fieldDiv.innerHTML = `
      <div class="form-group half">
        <input type="text" class="metadata-key" placeholder="Key" value="${key}">
      </div>
      <div class="form-group half">
        <div class="metadata-value-container">
          <input type="text" class="metadata-value" placeholder="Value" value="${value}">
          <button type="button" class="btn-icon remove-metadata">
            <i class="fas fa-times"></i>
          </button>
        </div>
      </div>
    `;
    
    // Add remove button handler
    const removeBtn = fieldDiv.querySelector('.remove-metadata');
    removeBtn.addEventListener('click', () => {
      fieldDiv.remove();
    });
    
    metadataFields.appendChild(fieldDiv);
  }
  
  // Show context menu at position
  function showContextMenu(x, y, type) {
    // Position the menu
    contextMenu.style.left = `${x}px`;
    contextMenu.style.top = `${y}px`;
    
    // Show/hide items based on context
    if (type === 'edge') {
      // For edges, hide connect and highlight options
      document.querySelector('#context-menu [data-action="connect"]').style.display = 'none';
      document.querySelector('#context-menu [data-action="highlight"]').style.display = 'none';
    } else {
      // For nodes, show all options
      document.querySelector('#context-menu [data-action="connect"]').style.display = 'flex';
      document.querySelector('#context-menu [data-action="highlight"]').style.display = 'flex';
    }
    
    // Show the menu
    contextMenu.classList.remove('hidden');
  }
  
  // Hide context menu
  function hideContextMenu() {
    contextMenu.classList.add('hidden');
    currentNodeId = null;
    currentEdgeId = null;
  }
  
  // Get display name for a node type
  function getNodeTypeName(type) {
    switch (type) {
      case 'person': return 'Person';
      case 'organization': return 'Organization';
      case 'wallet': return 'Wallet Address';
      case 'ip': return 'IP Address';
      case 'location': return 'Location';
      case 'transaction': return 'Transaction';
      case 'social': return 'Social Media';
      case 'domain': return 'Domain';
      case 'website': return 'Website';
      default: return 'Unknown';
    }
  }
}