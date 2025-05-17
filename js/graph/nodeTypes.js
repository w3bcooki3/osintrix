// Node type configurations
const nodeTypes = {
  person: {
    icon: '\uf007', // fa-user
    color: '#3B82F6',
    hoverColor: '#60A5FA',
    highlightColor: '#93C5FD',
    dragColor: '#2563EB'
  },
  organization: {
    icon: '\uf1ad', // fa-building
    color: '#10B981',
    hoverColor: '#34D399',
    highlightColor: '#6EE7B7',
    dragColor: '#059669'
  },
  wallet: {
    icon: '\uf555', // fa-wallet
    color: '#F59E0B',
    hoverColor: '#FBBF24',
    highlightColor: '#FCD34D',
    dragColor: '#D97706'
  },
  ip: {
    icon: '\uf6ff', // fa-network-wired
    color: '#EF4444',
    hoverColor: '#F87171',
    highlightColor: '#FCA5A5',
    dragColor: '#DC2626'
  },
  location: {
    icon: '\uf3c5', // fa-map-marker-alt
    color: '#8B5CF6',
    hoverColor: '#A78BFA',
    highlightColor: '#C4B5FD',
    dragColor: '#7C3AED'
  },
  transaction: {
    icon: '\uf155', // fa-dollar-sign
    color: '#EC4899',
    hoverColor: '#F472B6',
    highlightColor: '#F9A8D4',
    dragColor: '#DB2777'
  },
  social: {
    icon: '\uf099', // fa-twitter
    color: '#0EA5E9',
    hoverColor: '#38BDF8',
    highlightColor: '#7DD3FC',
    dragColor: '#0284C7'
  },
  domain: {
    icon: '\uf0ac', // fa-globe
    color: '#14B8A6',
    hoverColor: '#2DD4BF',
    highlightColor: '#5EEAD4',
    dragColor: '#0D9488'
  },
  website: {
    icon: '\uf0c1', // fa-link
    color: '#6366F1',
    hoverColor: '#818CF8',
    highlightColor: '#A5B4FC',
    dragColor: '#4F46E5'
  }
};

// Get configuration for a specific node type (or default if not found)
export function getNodeTypeConfig(type) {
  return nodeTypes[type] || {
    icon: '\uf111', // fa-circle
    color: '#9CA3AF',
    hoverColor: '#D1D5DB',
    highlightColor: '#E5E7EB',
    dragColor: '#6B7280'
  };
}

// Get list of all supported node types
export function getNodeTypes() {
  return Object.keys(nodeTypes);
}

// Get node icon for a specific type
export function getNodeIconClass(type) {
  switch (type) {
    case 'person': return 'fa-user';
    case 'organization': return 'fa-building';
    case 'wallet': return 'fa-wallet';
    case 'ip': return 'fa-network-wired';
    case 'location': return 'fa-map-marker-alt';
    case 'transaction': return 'fa-dollar-sign';
    case 'social': return 'fa-share-alt';
    case 'domain': return 'fa-globe';
    case 'website': return 'fa-link';
    default: return 'fa-circle';
  }
}

// Get display name for a node type
export function getNodeTypeName(type) {
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