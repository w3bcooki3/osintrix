// Edge type configurations for different relationship types
const edgeTypes = {
  // Default edge type
  default: {
    color: '#9CA3AF',
    hoverColor: '#4B5563',
    highlightColor: '#374151',
    lineStyle: 'solid',
    lineWidth: 1
  },
  
  // Ownership relationships
  owns: {
    color: '#3B82F6',
    hoverColor: '#2563EB',
    highlightColor: '#1D4ED8',
    lineStyle: 'solid',
    lineWidth: 2
  },
  
  // Association relationships
  knows: {
    color: '#10B981',
    hoverColor: '#059669',
    highlightColor: '#047857',
    lineStyle: 'solid',
    lineWidth: 1
  },
  
  // Transaction relationships
  'sent to': {
    color: '#F59E0B',
    hoverColor: '#D97706',
    highlightColor: '#B45309',
    lineStyle: 'solid',
    lineWidth: 1
  },
  'received from': {
    color: '#F59E0B',
    hoverColor: '#D97706',
    highlightColor: '#B45309',
    lineStyle: 'dashed',
    lineWidth: 1
  },
  
  // Control relationships
  controls: {
    color: '#EF4444',
    hoverColor: '#DC2626',
    highlightColor: '#B91C1C',
    lineStyle: 'solid',
    lineWidth: 2
  },
  
  // Access relationships
  'accessed from': {
    color: '#8B5CF6',
    hoverColor: '#7C3AED',
    highlightColor: '#6D28D9',
    lineStyle: 'solid',
    lineWidth: 1
  },
  
  // Hosting relationships
  hosts: {
    color: '#EC4899',
    hoverColor: '#DB2777',
    highlightColor: '#BE185D',
    lineStyle: 'solid',
    lineWidth: 1
  },
  
  // Communication relationships
  'communicated with': {
    color: '#0EA5E9',
    hoverColor: '#0284C7',
    highlightColor: '#0369A1',
    lineStyle: 'solid',
    lineWidth: 1
  }
};

// Get configuration for a specific edge type (or default if not found)
export function getEdgeTypeConfig(type) {
  if (!type) return edgeTypes.default;
  
  // Try to find exact match
  if (edgeTypes[type]) {
    return edgeTypes[type];
  }
  
  // Try to find a partial match
  for (const key in edgeTypes) {
    if (type.includes(key)) {
      return edgeTypes[key];
    }
  }
  
  // Return default if no match found
  return edgeTypes.default;
}

// Get list of common relationship types
export function getCommonRelationshipTypes() {
  return [
    'owns',
    'knows',
    'sent to',
    'received from',
    'controls',
    'accessed from',
    'hosts',
    'communicated with',
    'related to',
    'member of',
    'works for',
    'lives at',
    'registered to',
    'connected to'
  ];
}