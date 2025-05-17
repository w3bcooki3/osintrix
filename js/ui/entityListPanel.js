import { getNodeIconClass, getNodeTypeName } from '../graph/nodeTypes.js';

export function setupEntityListPanel(graph, dataStore) {
  const panel = document.getElementById('entity-list-panel');
  const toggleBtn = panel.querySelector('.toggle-panel');
  const entityList = document.getElementById('entity-list');
  
  // Toggle panel
  toggleBtn.addEventListener('click', () => {
    panel.classList.toggle('collapsed');
    toggleBtn.querySelector('i').classList.toggle('fa-chevron-left');
    toggleBtn.querySelector('i').classList.toggle('fa-chevron-right');
  });
  
  // Update entity list when data changes
  document.addEventListener('dataStore:updated', () => {
    updateEntityList();
  });
  
  // Update entity list when node is selected
  document.addEventListener('graph:nodeSelected', (e) => {
    const { nodeId } = e.detail;
    highlightSelectedEntity(nodeId);
  });
  
  // Update entity list when selection is cleared
  document.addEventListener('graph:selectionCleared', () => {
    clearEntityHighlight();
  });
  
  // Update entity list
  function updateEntityList() {
    const nodes = dataStore.getAllNodes();
    
    entityList.innerHTML = '';
    
    nodes.forEach(node => {
      const li = document.createElement('li');
      li.className = 'entity-item';
      li.dataset.id = node.id;
      
      li.innerHTML = `
        <div class="entity-icon ${node.type}">
          <i class="fas fa-${getNodeIconClass(node.type)}"></i>
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
        highlightSelectedEntity(node.id);
      });
      
      entityList.appendChild(li);
    });
    
    // Highlight currently selected node if any
    const selectedNodeId = graph.getSelectedNodeId();
    if (selectedNodeId) {
      highlightSelectedEntity(selectedNodeId);
    }
  }
  
  // Highlight selected entity in the list
  function highlightSelectedEntity(nodeId) {
    clearEntityHighlight();
    
    const item = entityList.querySelector(`[data-id="${nodeId}"]`);
    if (item) {
      item.classList.add('selected');
      item.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }
  }
  
  // Clear entity highlight
  function clearEntityHighlight() {
    const items = entityList.querySelectorAll('.entity-item');
    items.forEach(item => {
      item.classList.remove('selected');
    });
  }
  
  // Initialize
  updateEntityList();
}