// Generate a unique ID for entities
function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).substring(2);
}

export function initDataStore() {
  // Internal data storage
  let nodes = [];
  let edges = [];
  let investigationNotes = '';
  
  // Add a new node
  function addNode(nodeData) {
    const id = nodeData.id || generateId();
    
    const node = {
      id,
      type: nodeData.type || 'person',
      label: nodeData.label || 'Untitled',
      description: nodeData.description || '',
      notes: nodeData.notes || '',
      location: nodeData.location || '',
      date: nodeData.date || '',
      time: nodeData.time || '',
      tags: nodeData.tags || [],
      metadata: nodeData.metadata || {},
      image: nodeData.image || null,
      createdAt: nodeData.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    
    // Convert tags from string to array if needed
    if (typeof node.tags === 'string') {
      node.tags = node.tags.split(',').map(tag => tag.trim()).filter(tag => tag);
    }
    
    nodes.push(node);
    notifyUpdate();
    
    return node;
  }
  
  // Update an existing node
  function updateNode(id, nodeData) {
    const index = nodes.findIndex(node => node.id === id);
    
    if (index !== -1) {
      // Convert tags from string to array if needed
      let tags = nodeData.tags || nodes[index].tags;
      if (typeof tags === 'string') {
        tags = tags.split(',').map(tag => tag.trim()).filter(tag => tag);
      }
      
      nodes[index] = {
        ...nodes[index],
        ...nodeData,
        tags,
        updatedAt: new Date().toISOString()
      };
      
      notifyUpdate();
      return nodes[index];
    }
    
    return null;
  }
  
  // Delete a node and all its connected edges
  function deleteNode(id) {
    // Delete all edges connected to this node
    edges = edges.filter(edge => edge.source !== id && edge.target !== id);
    
    // Delete the node
    const index = nodes.findIndex(node => node.id === id);
    
    if (index !== -1) {
      nodes.splice(index, 1);
      notifyUpdate();
      return true;
    }
    
    return false;
  }
  
  // Get a node by ID
  function getNode(id) {
    return nodes.find(node => node.id === id);
  }
  
  // Get all nodes
  function getAllNodes() {
    return [...nodes];
  }
  
  // Get nodes filtered by type
  function getNodesByType(type) {
    return nodes.filter(node => node.type === type);
  }
  
  // Get nodes filtered by tag
  function getNodesByTag(tag) {
    return nodes.filter(node => node.tags.includes(tag));
  }
  
  // Search nodes
  function searchNodes(query) {
    if (!query) return [];
    
    query = query.toLowerCase();
    
    return nodes.filter(node => {
      // Search in basic properties
      if (node.label.toLowerCase().includes(query)) return true;
      if (node.description.toLowerCase().includes(query)) return true;
      if (node.notes.toLowerCase().includes(query)) return true;
      if (node.type.toLowerCase().includes(query)) return true;
      if (node.location && node.location.toLowerCase().includes(query)) return true;
      
      // Search in tags
      if (node.tags.some(tag => tag.toLowerCase().includes(query))) return true;
      
      // Search in metadata
      if (node.metadata) {
        for (const key in node.metadata) {
          const value = node.metadata[key];
          if (value && value.toString().toLowerCase().includes(query)) return true;
        }
      }
      
      return false;
    });
  }
  
  // Add a new edge (connection)
  function addEdge(edgeData) {
    const id = edgeData.id || generateId();
    
    const edge = {
      id,
      source: edgeData.source,
      target: edgeData.target,
      label: edgeData.label || '',
      description: edgeData.description || '',
      notes: edgeData.notes || '',
      metadata: edgeData.metadata || {},
      createdAt: edgeData.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    
    edges.push(edge);
    notifyUpdate();
    
    return edge;
  }
  
  // Update an existing edge
  function updateEdge(id, edgeData) {
    const index = edges.findIndex(edge => edge.id === id);
    
    if (index !== -1) {
      edges[index] = {
        ...edges[index],
        ...edgeData,
        updatedAt: new Date().toISOString()
      };
      
      notifyUpdate();
      return edges[index];
    }
    
    return null;
  }
  
  // Delete an edge
  function deleteEdge(id) {
    const index = edges.findIndex(edge => edge.id === id);
    
    if (index !== -1) {
      edges.splice(index, 1);
      notifyUpdate();
      return true;
    }
    
    return false;
  }
  
  // Get an edge by ID
  function getEdge(id) {
    return edges.find(edge => edge.id === id);
  }
  
  // Get all edges
  function getAllEdges() {
    return [...edges];
  }
  
  // Get edges connected to a node
  function getEdgesByNode(nodeId) {
    return edges.filter(edge => edge.source === nodeId || edge.target === nodeId);
  }
  
  // Get edges between two nodes
  function getEdgesBetweenNodes(source, target) {
    return edges.filter(edge => 
      (edge.source === source && edge.target === target) || 
      (edge.source === target && edge.target === source)
    );
  }
  
  // Save investigation notes
  function saveInvestigationNotes(notes) {
    investigationNotes = notes;
    notifyUpdate();
  }
  
  // Get investigation notes
  function getInvestigationNotes() {
    return investigationNotes;
  }
  
  // Export all data as JSON
  function exportData() {
    return {
      nodes,
      edges,
      investigationNotes,
      metadata: {
        version: '1.0',
        exportedAt: new Date().toISOString()
      }
    };
  }
  
  // Import data from JSON
  function importData(data) {
    if (data.nodes) nodes = data.nodes;
    if (data.edges) edges = data.edges;
    if (data.investigationNotes) investigationNotes = data.investigationNotes;
    
    notifyUpdate();
  }
  
  // Clear all data
  function clearData() {
    nodes = [];
    edges = [];
    investigationNotes = '';
    
    notifyUpdate();
  }
  
  // Notify listeners that data has been updated
  function notifyUpdate() {
    document.dispatchEvent(new CustomEvent('dataStore:updated'));
  }
  
  // Return public API
  return {
    // Node operations
    addNode,
    updateNode,
    deleteNode,
    getNode,
    getAllNodes,
    getNodesByType,
    getNodesByTag,
    searchNodes,
    
    // Edge operations
    addEdge,
    updateEdge,
    deleteEdge,
    getEdge,
    getAllEdges,
    getEdgesByNode,
    getEdgesBetweenNodes,
    
    // Investigation notes
    saveInvestigationNotes,
    getInvestigationNotes,
    
    // Data management
    exportData,
    importData,
    clearData
  };
}