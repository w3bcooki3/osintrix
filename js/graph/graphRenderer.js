import { createForceLayout } from './graphPhysics.js';
import { getNodeTypeConfig } from './nodeTypes.js';
import { getEdgeTypeConfig } from './edgeTypes.js';

export function initGraph(containerId, dataStore) {
  // DOM element for graph rendering
  const container = document.getElementById(containerId);
  
  // Canvas for rendering
  const canvas = document.createElement('canvas');
  canvas.width = container.clientWidth;
  canvas.height = container.clientHeight;
  container.appendChild(canvas);
  
  const ctx = canvas.getContext('2d');
  
  // Graph state
  let nodes = [];
  let edges = [];
  let selectedNodeId = null;
  let selectedEdgeId = null;
  let hoveredNodeId = null;
  let hoveredEdgeId = null;
  let transform = { x: 0, y: 0, scale: 1 };
  let isDragging = false;
  let draggedNodeId = null;
  let lastMousePos = { x: 0, y: 0 };
  let highlightedNodeIds = new Set();
  let highlightedEdgeIds = new Set();
  
  // Physics simulation
  const physics = createForceLayout();
  
  // Initialize the graph with data
  function initGraphData() {
    nodes = dataStore.getAllNodes().map(node => ({
      ...node,
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      radius: 20
    }));
    
    edges = dataStore.getAllEdges();
    
    // Initialize physics
    physics.setNodes(nodes);
    physics.setEdges(edges);
  }
  
  // Render the graph
  function render() {
    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    // Apply transformation
    ctx.save();
    ctx.translate(transform.x, transform.y);
    ctx.scale(transform.scale, transform.scale);
    
    // Draw edges
    edges.forEach(edge => {
      const source = nodes.find(node => node.id === edge.source);
      const target = nodes.find(node => node.id === edge.target);
      
      if (source && target) {
        const isSelected = edge.id === selectedEdgeId;
        const isHovered = edge.id === hoveredEdgeId;
        const isHighlighted = highlightedEdgeIds.has(edge.id);
        
        drawEdge(source, target, edge, isSelected, isHovered, isHighlighted);
      }
    });
    
    // Draw nodes
    nodes.forEach(node => {
      const isSelected = node.id === selectedNodeId;
      const isHovered = node.id === hoveredNodeId;
      const isHighlighted = highlightedNodeIds.has(node.id);
      const isDragged = node.id === draggedNodeId;
      
      drawNode(node, isSelected, isHovered, isHighlighted, isDragged);
    });
    
    ctx.restore();
  }
  
  // Draw a node
  function drawNode(node, isSelected, isHovered, isHighlighted, isDragged) {
    const config = getNodeTypeConfig(node.type);
    const x = node.x;
    const y = node.y;
    const radius = node.radius;
    
    // Node shadow
    ctx.beginPath();
    ctx.arc(x, y, radius + 2, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(0, 0, 0, 0.2)';
    ctx.fill();
    
    // Node background
    ctx.beginPath();
    ctx.arc(x, y, radius, 0, Math.PI * 2);
    
    if (isSelected) {
      ctx.fillStyle = '#3B82F6';
    } else if (isHovered) {
      ctx.fillStyle = config.hoverColor;
    } else if (isHighlighted) {
      ctx.fillStyle = config.highlightColor;
    } else if (isDragged) {
      ctx.fillStyle = config.dragColor;
    } else {
      ctx.fillStyle = config.color;
    }
    
    ctx.fill();
    
    // Node border
    ctx.beginPath();
    ctx.arc(x, y, radius, 0, Math.PI * 2);
    
    if (isSelected) {
      ctx.strokeStyle = '#1D4ED8';
      ctx.lineWidth = 3;
    } else if (isHovered || isHighlighted) {
      ctx.strokeStyle = '#4B5563';
      ctx.lineWidth = 2;
    } else {
      ctx.strokeStyle = '#9CA3AF';
      ctx.lineWidth = 1;
    }
    
    ctx.stroke();
    
    // Draw icon
    ctx.fillStyle = 'white';
    ctx.font = '12px FontAwesome';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(config.icon, x, y);
    
    // Draw label
    ctx.font = 'bold 12px Inter, sans-serif';
    ctx.fillStyle = '#1F2937';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    ctx.fillText(node.label, x, y + radius + 8);
  }
  
  // Draw an edge
  function drawEdge(source, target, edge, isSelected, isHovered, isHighlighted) {
    const config = getEdgeTypeConfig(edge.label);
    
    // Calculate edge path
    const angle = Math.atan2(target.y - source.y, target.x - source.x);
    const sourceX = source.x + Math.cos(angle) * source.radius;
    const sourceY = source.y + Math.sin(angle) * source.radius;
    const targetX = target.x - Math.cos(angle) * target.radius;
    const targetY = target.y - Math.sin(angle) * target.radius;
    
    // Draw line
    ctx.beginPath();
    ctx.moveTo(sourceX, sourceY);
    ctx.lineTo(targetX, targetY);
    
    if (isSelected) {
      ctx.strokeStyle = '#3B82F6';
      ctx.lineWidth = 3;
    } else if (isHovered) {
      ctx.strokeStyle = config.hoverColor;
      ctx.lineWidth = 2;
    } else if (isHighlighted) {
      ctx.strokeStyle = config.highlightColor;
      ctx.lineWidth = 2;
    } else {
      ctx.strokeStyle = config.color;
      ctx.lineWidth = 1;
    }
    
    ctx.stroke();
    
    // Draw direction arrow
    const arrowSize = 8;
    const arrowAngle = Math.PI / 8;
    
    // Adjust arrow position to be closer to the target node
    const arrowX = targetX - Math.cos(angle) * 5;
    const arrowY = targetY - Math.sin(angle) * 5;
    
    ctx.beginPath();
    ctx.moveTo(arrowX, arrowY);
    ctx.lineTo(
      arrowX - arrowSize * Math.cos(angle - arrowAngle),
      arrowY - arrowSize * Math.sin(angle - arrowAngle)
    );
    ctx.lineTo(
      arrowX - arrowSize * Math.cos(angle + arrowAngle),
      arrowY - arrowSize * Math.sin(angle + arrowAngle)
    );
    ctx.closePath();
    
    if (isSelected || isHovered || isHighlighted) {
      ctx.fillStyle = isSelected ? '#3B82F6' : config.hoverColor;
    } else {
      ctx.fillStyle = config.color;
    }
    
    ctx.fill();
    
    // Draw label
    if (edge.label) {
      const midX = (sourceX + targetX) / 2;
      const midY = (sourceY + targetY) / 2;
      
      // Draw background for label
      const labelWidth = ctx.measureText(edge.label).width + 10;
      const labelHeight = 16;
      
      ctx.fillStyle = 'rgba(255, 255, 255, 0.8)';
      ctx.fillRect(midX - labelWidth / 2, midY - labelHeight / 2, labelWidth, labelHeight);
      
      ctx.font = '11px Inter, sans-serif';
      ctx.fillStyle = '#4B5563';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText(edge.label, midX, midY);
    }
  }
  
  // Update the simulation
  function update() {
    physics.update();
    render();
    requestAnimationFrame(update);
  }
  
  // Handle window resize
  function handleResize() {
    canvas.width = container.clientWidth;
    canvas.height = container.clientHeight;
    render();
  }
  
  // Convert screen coordinates to graph coordinates
  function screenToGraphCoords(x, y) {
    return {
      x: (x - transform.x) / transform.scale,
      y: (y - transform.y) / transform.scale
    };
  }
  
  // Get node at coordinates
  function getNodeAt(x, y) {
    const coords = screenToGraphCoords(x, y);
    
    // Check in reverse order (to select nodes drawn on top first)
    for (let i = nodes.length - 1; i >= 0; i--) {
      const node = nodes[i];
      const dx = node.x - coords.x;
      const dy = node.y - coords.y;
      const distance = Math.sqrt(dx * dx + dy * dy);
      
      if (distance <= node.radius) {
        return node;
      }
    }
    
    return null;
  }
  
  // Get edge at coordinates
  function getEdgeAt(x, y) {
    const coords = screenToGraphCoords(x, y);
    const threshold = 5; // Distance threshold for edge selection
    
    for (let i = edges.length - 1; i >= 0; i--) {
      const edge = edges[i];
      const source = nodes.find(node => node.id === edge.source);
      const target = nodes.find(node => node.id === edge.target);
      
      if (source && target) {
        // Calculate distance from point to line segment
        const dx = target.x - source.x;
        const dy = target.y - source.y;
        const length = Math.sqrt(dx * dx + dy * dy);
        
        if (length === 0) continue;
        
        const t = Math.max(0, Math.min(1, ((coords.x - source.x) * dx + (coords.y - source.y) * dy) / (length * length)));
        const projX = source.x + t * dx;
        const projY = source.y + t * dy;
        
        const distToLine = Math.sqrt((coords.x - projX) ** 2 + (coords.y - projY) ** 2);
        
        if (distToLine <= threshold) {
          return edge;
        }
      }
    }
    
    return null;
  }
  
  // Mouse event handlers
  function handleMouseDown(e) {
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    
    lastMousePos = { x, y };
    
    const node = getNodeAt(x, y);
    
    if (node) {
      draggedNodeId = node.id;
      physics.fixNodePosition(node.id, true);
      
      // Trigger node selection
      selectNode(node.id);
    } else {
      const edge = getEdgeAt(x, y);
      
      if (edge) {
        // Trigger edge selection
        selectEdge(edge.id);
      } else {
        // Start panning the canvas
        isDragging = true;
        
        // Clear selection if clicking on empty space
        selectNode(null);
        selectEdge(null);
      }
    }
  }
  
  function handleMouseMove(e) {
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    
    if (draggedNodeId) {
      const coords = screenToGraphCoords(x, y);
      const node = nodes.find(n => n.id === draggedNodeId);
      
      if (node) {
        node.x = coords.x;
        node.y = coords.y;
        physics.updateNodePosition(node.id, coords.x, coords.y);
      }
    } else if (isDragging) {
      // Pan the canvas
      transform.x += (x - lastMousePos.x);
      transform.y += (y - lastMousePos.y);
    } else {
      // Hover effects
      const node = getNodeAt(x, y);
      
      if (node) {
        hoveredNodeId = node.id;
        hoveredEdgeId = null;
        canvas.style.cursor = 'pointer';
      } else {
        const edge = getEdgeAt(x, y);
        
        if (edge) {
          hoveredNodeId = null;
          hoveredEdgeId = edge.id;
          canvas.style.cursor = 'pointer';
        } else {
          hoveredNodeId = null;
          hoveredEdgeId = null;
          canvas.style.cursor = 'default';
        }
      }
    }
    
    lastMousePos = { x, y };
  }
  
  function handleMouseUp() {
    if (draggedNodeId) {
      physics.fixNodePosition(draggedNodeId, false);
      draggedNodeId = null;
    }
    
    isDragging = false;
  }
  
  function handleWheel(e) {
    e.preventDefault();
    
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;
    
    // Convert mouse position to graph space before scaling
    const graphPosBeforeZoom = screenToGraphCoords(mouseX, mouseY);
    
    // Update scale with zoom factor
    const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
    transform.scale *= zoomFactor;
    
    // Limit scale
    transform.scale = Math.max(0.1, Math.min(transform.scale, 5));
    
    // Convert mouse position to graph space after scaling
    const graphPosAfterZoom = screenToGraphCoords(mouseX, mouseY);
    
    // Adjust translation to zoom into/out of mouse position
    transform.x += (graphPosAfterZoom.x - graphPosBeforeZoom.x) * transform.scale;
    transform.y += (graphPosAfterZoom.y - graphPosBeforeZoom.y) * transform.scale;
  }
  
  function handleContextMenu(e) {
    e.preventDefault();
    
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    
    const node = getNodeAt(x, y);
    
    if (node) {
      // Select the node first
      selectNode(node.id);
      
      // Show context menu for node
      const event = new CustomEvent('graph:nodeContextMenu', { 
        detail: { 
          nodeId: node.id, 
          clientX: e.clientX, 
          clientY: e.clientY 
        } 
      });
      document.dispatchEvent(event);
    } else {
      const edge = getEdgeAt(x, y);
      
      if (edge) {
        // Select the edge first
        selectEdge(edge.id);
        
        // Show context menu for edge
        const event = new CustomEvent('graph:edgeContextMenu', { 
          detail: { 
            edgeId: edge.id, 
            clientX: e.clientX, 
            clientY: e.clientY 
          } 
        });
        document.dispatchEvent(event);
      }
    }
  }
  
  // Selection handlers
  function selectNode(nodeId) {
    selectedNodeId = nodeId;
    selectedEdgeId = null;
    
    if (nodeId) {
      const node = nodes.find(n => n.id === nodeId);
      
      if (node) {
        // Dispatch selection event
        const event = new CustomEvent('graph:nodeSelected', { detail: { nodeId } });
        document.dispatchEvent(event);
      }
    } else {
      // Dispatch deselection event
      const event = new CustomEvent('graph:selectionCleared');
      document.dispatchEvent(event);
    }
  }
  
  function selectEdge(edgeId) {
    selectedEdgeId = edgeId;
    selectedNodeId = null;
    
    if (edgeId) {
      const edge = edges.find(e => e.id === edgeId);
      
      if (edge) {
        // Dispatch selection event
        const event = new CustomEvent('graph:edgeSelected', { detail: { edgeId } });
        document.dispatchEvent(event);
      }
    } else {
      // Dispatch deselection event
      const event = new CustomEvent('graph:selectionCleared');
      document.dispatchEvent(event);
    }
  }
  
  // Highlighting
  function highlightNodes(nodeIds) {
    highlightedNodeIds = new Set(nodeIds);
  }
  
  function highlightEdges(edgeIds) {
    highlightedEdgeIds = new Set(edgeIds);
  }
  
  function clearHighlights() {
    highlightedNodeIds.clear();
    highlightedEdgeIds.clear();
  }
  
  // Refresh graph data from data store
  function refreshGraph() {
    nodes = dataStore.getAllNodes().map(node => {
      // Preserve positions for existing nodes
      const existingNode = nodes.find(n => n.id === node.id);
      
      if (existingNode) {
        return {
          ...node,
          x: existingNode.x,
          y: existingNode.y,
          radius: 20
        };
      }
      
      return {
        ...node,
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        radius: 20
      };
    });
    
    edges = dataStore.getAllEdges();
    
    // Update physics
    physics.setNodes(nodes);
    physics.setEdges(edges);
  }
  
  // Center the view on a specific node
  function centerOnNode(nodeId) {
    const node = nodes.find(n => n.id === nodeId);
    
    if (node) {
      transform.x = canvas.width / 2 - node.x * transform.scale;
      transform.y = canvas.height / 2 - node.y * transform.scale;
    }
  }
  
  // Initialize event listeners
  function initEventListeners() {
    canvas.addEventListener('mousedown', handleMouseDown);
    canvas.addEventListener('mousemove', handleMouseMove);
    canvas.addEventListener('mouseup', handleMouseUp);
    canvas.addEventListener('mouseleave', handleMouseUp);
    canvas.addEventListener('wheel', handleWheel);
    canvas.addEventListener('contextmenu', handleContextMenu);
    window.addEventListener('resize', handleResize);
    
    // Listen for changes in the data store
    document.addEventListener('dataStore:updated', () => {
      refreshGraph();
    });
  }
  
  // Initialize graph
  initGraphData();
  initEventListeners();
  update();
  
  // Return public API
  return {
    renderGraph: refreshGraph,
    selectNode,
    selectEdge,
    highlightNodes,
    highlightEdges,
    clearHighlights,
    centerOnNode,
    getSelectedNodeId: () => selectedNodeId,
    getSelectedEdgeId: () => selectedEdgeId
  };
}