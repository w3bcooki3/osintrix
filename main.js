import { initGraph } from './js/graph/graphRenderer.js';
import { setupUIControls } from './js/ui/uiController.js';
import { initDataStore } from './js/data/dataStore.js';
import { initThemeManager } from './js/utils/themeManager.js';
import { setupContextMenu } from './js/ui/contextMenu.js';
import { setupEntityPanel } from './js/ui/entityPanel.js';
import { setupEntityListPanel } from './js/ui/entityListPanel.js';
import { setupNodeModal } from './js/ui/nodeModal.js';
import { setupEdgeModal } from './js/ui/edgeModal.js';
import { setupStorage } from './js/utils/storage.js';

// Initialize the application
document.addEventListener('DOMContentLoaded', () => {
  // Initialize core components
  const dataStore = initDataStore();
  const graph = initGraph('graph-container', dataStore);
  
  // Initialize UI components
  initThemeManager();
  setupContextMenu(graph, dataStore);
  setupEntityPanel(graph, dataStore);
  setupEntityListPanel(graph, dataStore);
  setupNodeModal(graph, dataStore);
  setupEdgeModal(graph, dataStore);
  setupStorage(graph, dataStore);
  
  // Set up UI controls
  setupUIControls(graph, dataStore);
  
  // Load demo data for testing
  loadDemoData(dataStore, graph);
});

// Load some initial demo data for testing purposes
function loadDemoData(dataStore, graph) {
  // Create some example nodes
  const person1 = dataStore.addNode({
    type: 'person',
    label: 'John Doe',
    description: 'Primary suspect',
    tags: ['suspect', 'key-person'],
    notes: 'Involved in multiple suspicious transactions',
    date: '2023-08-15',
    location: 'New York, USA'
  });
  
  const organization1 = dataStore.addNode({
    type: 'organization',
    label: 'Acme Corp',
    description: 'Shell company',
    tags: ['company', 'shell'],
    notes: 'Suspected shell company for money laundering'
  });
  
  const wallet1 = dataStore.addNode({
    type: 'wallet',
    label: '0x1234...5678',
    description: 'Ethereum wallet',
    tags: ['crypto', 'ethereum'],
    notes: 'Wallet used for suspicious transactions'
  });
  
  const ip1 = dataStore.addNode({
    type: 'ip',
    label: '192.168.1.1',
    description: 'IP address used for login',
    tags: ['network', 'access-point'],
    location: 'Russia'
  });
  
  // Create some example edges
  dataStore.addEdge({
    source: person1.id,
    target: organization1.id,
    label: 'owns',
    description: 'Primary shareholder',
    notes: 'Ownership confirmed through business registry'
  });
  
  dataStore.addEdge({
    source: organization1.id,
    target: wallet1.id,
    label: 'controls',
    description: 'Company wallet',
    notes: 'Transactions match company activities'
  });
  
  dataStore.addEdge({
    source: person1.id,
    target: ip1.id,
    label: 'accessed from',
    description: 'Login session',
    notes: 'Multiple logins recorded from this IP'
  });
  
  // Render the graph with the initial data
  graph.renderGraph();
}