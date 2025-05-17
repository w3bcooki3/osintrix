export function createForceLayout() {
  // Simulation parameters
  const parameters = {
    repulsion: 1000,        // Strong node repulsion
    springLength: 200,      // Longer edge length
    springStrength: 0.02,   // Weak spring force
    damping: 0.95,         // High damping to reduce movement
    centerGravity: 0.0001,  // Very weak center gravity
    maxVelocity: 30,       // Lower max velocity
    friction: 0.9          // High friction to slow movement
  };
  
  // Node and edge data
  let nodes = [];
  let edges = [];
  
  // Initialize physics state for nodes
  function initPhysicsState() {
    nodes.forEach(node => {
      if (!node.vx) node.vx = 0;
      if (!node.vy) node.vy = 0;
      if (!node.fixed) node.fixed = false;
      if (!node.mass) node.mass = 1; // Add mass property
    });
  }
  
  // Calculate forces and update positions
  function update() {
    if (nodes.length === 0) return;
    
    // Calculate barycenter
    let barycenterX = 0;
    let barycenterY = 0;
    
    nodes.forEach(node => {
      barycenterX += node.x;
      barycenterY += node.y;
    });
    
    barycenterX /= nodes.length;
    barycenterY /= nodes.length;
    
    // Calculate forces
    nodes.forEach(node => {
      if (node.fixed) {
        node.vx = 0;
        node.vy = 0;
        return;
      }
      
      // Initialize forces
      let fx = 0;
      let fy = 0;
      
      // Repulsion forces (node-node)
      nodes.forEach(otherNode => {
        if (node === otherNode) return;
        
        const dx = node.x - otherNode.x;
        const dy = node.y - otherNode.y;
        const distance = Math.sqrt(dx * dx + dy * dy) + 0.1;
        
        // Stronger repulsion at close distances
        const force = parameters.repulsion / (distance * distance);
        
        fx += (dx / distance) * force;
        fy += (dy / distance) * force;
      });
      
      // Spring forces (edges)
      edges.forEach(edge => {
        if (edge.source === node.id || edge.target === node.id) {
          const otherNodeId = edge.source === node.id ? edge.target : edge.source;
          const otherNode = nodes.find(n => n.id === otherNodeId);
          
          if (otherNode) {
            const dx = node.x - otherNode.x;
            const dy = node.y - otherNode.y;
            const distance = Math.sqrt(dx * dx + dy * dy) + 0.1;
            
            // Weaker spring force
            const displacement = distance - parameters.springLength;
            const force = parameters.springStrength * displacement;
            
            fx -= (dx / distance) * force;
            fy -= (dy / distance) * force;
          }
        }
      });
      
      // Very weak center gravity
      const gdx = node.x - barycenterX;
      const gdy = node.y - barycenterY;
      const gDistance = Math.sqrt(gdx * gdx + gdy * gdy) + 0.1;
      
      fx -= (gdx / gDistance) * parameters.centerGravity;
      fy -= (gdy / gDistance) * parameters.centerGravity;
      
      // Apply forces with high damping and friction
      node.vx = (node.vx + fx) * parameters.damping * parameters.friction;
      node.vy = (node.vy + fy) * parameters.damping * parameters.friction;
      
      // Limit velocity
      const velocity = Math.sqrt(node.vx * node.vx + node.vy * node.vy);
      if (velocity > parameters.maxVelocity) {
        node.vx = (node.vx / velocity) * parameters.maxVelocity;
        node.vy = (node.vy / velocity) * parameters.maxVelocity;
      }
      
      // Apply very small random force to prevent complete stasis
      if (Math.abs(node.vx) < 0.01 && Math.abs(node.vy) < 0.01) {
        node.vx = (Math.random() - 0.5) * 0.02;
        node.vy = (Math.random() - 0.5) * 0.02;
      }
      
      // Update position
      node.x += node.vx;
      node.y += node.vy;
    });
  }
  
  // Set nodes data
  function setNodes(newNodes) {
    nodes = newNodes;
    initPhysicsState();
  }
  
  // Set edges data
  function setEdges(newEdges) {
    edges = newEdges;
  }
  
  // Fix or release a node's position
  function fixNodePosition(nodeId, fixed) {
    const node = nodes.find(n => n.id === nodeId);
    
    if (node) {
      node.fixed = fixed;
      if (fixed) {
        node.vx = 0;
        node.vy = 0;
      }
    }
  }
  
  // Update a node's position manually
  function updateNodePosition(nodeId, x, y) {
    const node = nodes.find(n => n.id === nodeId);
    
    if (node) {
      node.x = x;
      node.y = y;
      node.vx = 0;
      node.vy = 0;
    }
  }
  
  // Set a simulation parameter
  function setParameter(name, value) {
    if (parameters.hasOwnProperty(name)) {
      parameters[name] = value;
    }
  }
  
  // Get a simulation parameter
  function getParameter(name) {
    return parameters[name];
  }
  
  // Return public API
  return {
    update,
    setNodes,
    setEdges,
    fixNodePosition,
    updateNodePosition,
    setParameter,
    getParameter
  };
}