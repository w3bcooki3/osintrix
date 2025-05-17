import { getCommonRelationshipTypes } from '../graph/edgeTypes.js';

export function setupEdgeModal(graph, dataStore) {
  const modal = document.getElementById('edge-modal');
  const form = document.getElementById('edge-form');
  const edgeLabelInput = document.getElementById('edge-label');
  
  // Add datalist with common relationship types
  const relationships = getCommonRelationshipTypes();
  const datalist = document.createElement('datalist');
  datalist.id = 'relationship-types';
  
  relationships.forEach(type => {
    const option = document.createElement('option');
    option.value = type;
    datalist.appendChild(option);
  });
  
  document.body.appendChild(datalist);
  edgeLabelInput.setAttribute('list', 'relationship-types');
  
  // Form submission
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    
    const formData = {
      source: document.getElementById('source-node').value,
      target: document.getElementById('target-node').value,
      label: document.getElementById('edge-label').value,
      description: document.getElementById('edge-description').value,
      notes: document.getElementById('edge-notes').value
    };
    
    // Validate source and target
    if (!formData.source || !formData.target) {
      alert('Please select both source and target nodes.');
      return;
    }
    
    // Prevent self-connections
    if (formData.source === formData.target) {
      alert('Source and target nodes must be different.');
      return;
    }
    
    // Save edge
    if (form.dataset.edgeId) {
      // Update existing edge
      dataStore.updateEdge(form.dataset.edgeId, formData);
      graph.selectEdge(form.dataset.edgeId);
    } else {
      // Create new edge
      const edge = dataStore.addEdge(formData);
      graph.selectEdge(edge.id);
    }
    
    // Update graph and close modal
    graph.renderGraph();
    closeModal();
  });
  
  // Close the modal
  function closeModal() {
    modal.classList.add('hidden');
    form.reset();
    form.dataset.edgeId = '';
  }
}