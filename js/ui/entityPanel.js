import { getNodeIconClass, getNodeTypeName } from '../graph/nodeTypes.js';

export function setupEntityPanel(graph, dataStore) {
  const panel = document.getElementById('entity-panel');
  const closeBtn = panel.querySelector('.close-panel');
  const detailsContainer = document.getElementById('entity-details');
  
  // Close panel
  closeBtn.addEventListener('click', () => {
    panel.classList.add('hidden');
  });
  
  // Node selection event
  document.addEventListener('graph:nodeSelected', (e) => {
    const { nodeId } = e.detail;
    showNodeDetails(nodeId);
  });
  
  // Edge selection event
  document.addEventListener('graph:edgeSelected', (e) => {
    const { edgeId } = e.detail;
    showEdgeDetails(edgeId);
  });
  
  // Clear selection event
  document.addEventListener('graph:selectionCleared', () => {
    panel.classList.add('hidden');
  });
  
  // DataStore update event
  document.addEventListener('dataStore:updated', () => {
    // If panel is visible, update the current details
    if (!panel.classList.contains('hidden')) {
      const nodeId = graph.getSelectedNodeId();
      const edgeId = graph.getSelectedEdgeId();
      
      if (nodeId) {
        showNodeDetails(nodeId);
      } else if (edgeId) {
        showEdgeDetails(edgeId);
      }
    }
  });
  
  // Show node details
  function showNodeDetails(nodeId) {
    const node = dataStore.getNode(nodeId);
    
    if (!node) {
      panel.classList.add('hidden');
      return;
    }
    
    // Build HTML for node details
    let html = `
      <div class="entity-header">
        <div class="entity-header-icon ${node.type}">
          <i class="fas fa-${getNodeIconClass(node.type)}"></i>
        </div>
        <div class="entity-header-info">
          <h2 class="entity-header-label">${node.label}</h2>
          <div class="entity-header-type">${getNodeTypeName(node.type)}</div>
        </div>
      </div>
    `;
    
    // Description
    if (node.description) {
      html += `
        <div class="entity-section">
          <div class="entity-section-title">Description</div>
          <p>${node.description}</p>
        </div>
      `;
    }
    
    // Tags
    if (node.tags && node.tags.length > 0) {
      html += `
        <div class="entity-section">
          <div class="entity-section-title">Tags</div>
          <div class="entity-tags">
            ${node.tags.map(tag => `<span class="entity-tag">${tag}</span>`).join('')}
          </div>
        </div>
      `;
    }
    
    // Date and Location
    const hasDate = node.date || node.time;
    const hasLocation = node.location;
    
    if (hasDate || hasLocation) {
      html += `<div class="entity-section">`;
      
      if (hasDate) {
        const dateStr = node.date || '';
        const timeStr = node.time || '';
        html += `
          <div class="entity-section-title">Date/Time</div>
          <p>${dateStr} ${timeStr}</p>
        `;
      }
      
      if (hasLocation) {
        html += `
          <div class="entity-section-title">Location</div>
          <p>${node.location}</p>
        `;
      }
      
      html += `</div>`;
    }
    
    // Image
    if (node.image) {
      html += `
        <div class="entity-section">
          <div class="entity-section-title">Image</div>
          <img src="${node.image}" alt="${node.label}" class="entity-image">
        </div>
      `;
    }
    
    // Notes
    if (node.notes) {
      html += `
        <div class="entity-section">
          <div class="entity-section-title">Notes</div>
          <p>${node.notes}</p>
        </div>
      `;
    }
    
    // Metadata
    if (node.metadata && Object.keys(node.metadata).length > 0) {
      html += `
        <div class="entity-section">
          <div class="entity-section-title">Metadata</div>
          <div class="entity-metadata">
      `;
      
      for (const key in node.metadata) {
        html += `
          <div class="entity-metadata-key">${key}</div>
          <div class="entity-metadata-value">${node.metadata[key]}</div>
        `;
      }
      
      html += `
          </div>
        </div>
      `;
    }
    
    // Connections
    const connections = dataStore.getEdgesByNode(nodeId);
    
    if (connections.length > 0) {
      html += `
        <div class="entity-section">
          <div class="entity-section-title">Connections</div>
          <div class="entity-connections">
      `;
      
      connections.forEach(edge => {
        const isSource = edge.source === nodeId;
        const connectedNodeId = isSource ? edge.target : edge.source;
        const connectedNode = dataStore.getNode(connectedNodeId);
        
        if (connectedNode) {
          html += `
            <div class="connection-item" data-node-id="${connectedNodeId}">
              <div class="connection-icon ${connectedNode.type}">
                <i class="fas fa-${getNodeIconClass(connectedNode.type)}"></i>
              </div>
              <div class="connection-info">
                <div class="connection-label">${connectedNode.label}</div>
                <div class="connection-relation">
                  ${isSource ? `${edge.label || 'connected to'} →` : `← ${edge.label || 'connected from'}`}
                </div>
              </div>
            </div>
          `;
        }
      });
      
      html += `
          </div>
        </div>
      `;
    }
    
    // Action buttons
    html += `
      <div class="entity-actions">
        <button class="btn-secondary edit-node" data-id="${nodeId}">
          <i class="fas fa-edit"></i> Edit
        </button>
        <button class="btn-primary delete-node" data-id="${nodeId}">
          <i class="fas fa-trash"></i> Delete
        </button>
      </div>
    `;
    
    // Set the HTML and show the panel
    detailsContainer.innerHTML = html;
    panel.classList.remove('hidden');
    
    // Add event listeners
    
    // Edit button
    const editBtn = detailsContainer.querySelector('.edit-node');
    editBtn.addEventListener('click', () => {
      // Trigger edit node
      const event = new CustomEvent('graph:nodeContextMenu', { 
        detail: { 
          nodeId,
          clientX: 0,
          clientY: 0
        } 
      });
      document.dispatchEvent(event);
      
      // Directly call edit action
      document.querySelector('#context-menu [data-action="edit"]').click();
    });
    
    // Delete button
    const deleteBtn = detailsContainer.querySelector('.delete-node');
    deleteBtn.addEventListener('click', () => {
      if (confirm('Are you sure you want to delete this node? This will also delete all connections to/from this node.')) {
        dataStore.deleteNode(nodeId);
        graph.renderGraph();
        panel.classList.add('hidden');
      }
    });
    
    // Connection items
    const connectionItems = detailsContainer.querySelectorAll('.connection-item');
    connectionItems.forEach(item => {
      item.addEventListener('click', () => {
        const connectedNodeId = item.dataset.nodeId;
        graph.selectNode(connectedNodeId);
        graph.centerOnNode(connectedNodeId);
      });
    });
  }
  
  // Show edge details
  function showEdgeDetails(edgeId) {
    const edge = dataStore.getEdge(edgeId);
    
    if (!edge) {
      panel.classList.add('hidden');
      return;
    }
    
    const sourceNode = dataStore.getNode(edge.source);
    const targetNode = dataStore.getNode(edge.target);
    
    if (!sourceNode || !targetNode) {
      panel.classList.add('hidden');
      return;
    }
    
    // Build HTML for edge details
    let html = `
      <div class="entity-header">
        <div class="entity-header-icon">
          <i class="fas fa-link"></i>
        </div>
        <div class="entity-header-info">
          <h2 class="entity-header-label">${edge.label || 'Connection'}</h2>
          <div class="entity-header-type">Relationship</div>
        </div>
      </div>
      
      <div class="entity-section">
        <div class="entity-section-title">Connection</div>
        <div class="entity-connections">
          <div class="connection-item" data-node-id="${sourceNode.id}">
            <div class="connection-icon ${sourceNode.type}">
              <i class="fas fa-${getNodeIconClass(sourceNode.type)}"></i>
            </div>
            <div class="connection-info">
              <div class="connection-label">${sourceNode.label}</div>
              <div class="connection-relation">Source</div>
            </div>
          </div>
          
          <div style="text-align: center; padding: 8px;">
            <i class="fas fa-arrow-down"></i>
            <div>${edge.label || 'connected to'}</div>
          </div>
          
          <div class="connection-item" data-node-id="${targetNode.id}">
            <div class="connection-icon ${targetNode.type}">
              <i class="fas fa-${getNodeIconClass(targetNode.type)}"></i>
            </div>
            <div class="connection-info">
              <div class="connection-label">${targetNode.label}</div>
              <div class="connection-relation">Target</div>
            </div>
          </div>
        </div>
      </div>
    `;
    
    // Description
    if (edge.description) {
      html += `
        <div class="entity-section">
          <div class="entity-section-title">Description</div>
          <p>${edge.description}</p>
        </div>
      `;
    }
    
    // Notes
    if (edge.notes) {
      html += `
        <div class="entity-section">
          <div class="entity-section-title">Notes</div>
          <p>${edge.notes}</p>
        </div>
      `;
    }
    
    // Metadata
    if (edge.metadata && Object.keys(edge.metadata).length > 0) {
      html += `
        <div class="entity-section">
          <div class="entity-section-title">Metadata</div>
          <div class="entity-metadata">
      `;
      
      for (const key in edge.metadata) {
        html += `
          <div class="entity-metadata-key">${key}</div>
          <div class="entity-metadata-value">${edge.metadata[key]}</div>
        `;
      }
      
      html += `
          </div>
        </div>
      `;
    }
    
    // Action buttons
    html += `
      <div class="entity-actions">
        <button class="btn-secondary edit-edge" data-id="${edgeId}">
          <i class="fas fa-edit"></i> Edit
        </button>
        <button class="btn-primary delete-edge" data-id="${edgeId}">
          <i class="fas fa-trash"></i> Delete
        </button>
      </div>
    `;
    
    // Set the HTML and show the panel
    detailsContainer.innerHTML = html;
    panel.classList.remove('hidden');
    
    // Add event listeners
    
    // Edit button
    const editBtn = detailsContainer.querySelector('.edit-edge');
    editBtn.addEventListener('click', () => {
      // Trigger edit edge
      const event = new CustomEvent('graph:edgeContextMenu', { 
        detail: { 
          edgeId,
          clientX: 0,
          clientY: 0
        } 
      });
      document.dispatchEvent(event);
      
      // Directly call edit action
      document.querySelector('#context-menu [data-action="edit"]').click();
    });
    
    // Delete button
    const deleteBtn = detailsContainer.querySelector('.delete-edge');
    deleteBtn.addEventListener('click', () => {
      if (confirm('Are you sure you want to delete this connection?')) {
        dataStore.deleteEdge(edgeId);
        graph.renderGraph();
        panel.classList.add('hidden');
      }
    });
    
    // Node links
    const connectionItems = detailsContainer.querySelectorAll('.connection-item');
    connectionItems.forEach(item => {
      item.addEventListener('click', () => {
        const nodeId = item.dataset.nodeId;
        graph.selectNode(nodeId);
        graph.centerOnNode(nodeId);
      });
    });
  }
}