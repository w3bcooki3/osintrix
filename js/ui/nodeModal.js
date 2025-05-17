import { getCommonRelationshipTypes } from '../graph/edgeTypes.js';

export function setupNodeModal(graph, dataStore) {
  const modal = document.getElementById('node-modal');
  const form = document.getElementById('node-form');
  const imageInput = document.getElementById('node-image');
  const browseImageBtn = document.getElementById('browse-image');
  const removeImageBtn = document.getElementById('remove-image');
  const imagePreview = document.getElementById('image-preview');
  const addMetadataBtn = document.getElementById('add-metadata');
  
  // Add metadata field button
  addMetadataBtn.addEventListener('click', () => {
    addMetadataField();
  });
  
  // Browse image button
  browseImageBtn.addEventListener('click', () => {
    imageInput.click();
  });
  
  // Remove image button
  removeImageBtn.addEventListener('click', () => {
    imageInput.value = '';
    imagePreview.style.backgroundImage = '';
    imagePreview.classList.remove('has-image');
    removeImageBtn.classList.add('hidden');
  });
  
  // Handle image selection
  imageInput.addEventListener('change', () => {
    const file = imageInput.files[0];
    
    if (file) {
      const reader = new FileReader();
      
      reader.onload = (e) => {
        imagePreview.style.backgroundImage = `url(${e.target.result})`;
        imagePreview.classList.add('has-image');
        removeImageBtn.classList.remove('hidden');
      };
      
      reader.readAsDataURL(file);
    } else {
      imagePreview.style.backgroundImage = '';
      imagePreview.classList.remove('has-image');
      removeImageBtn.classList.add('hidden');
    }
  });
  
  // Support for drag and drop of images
  imagePreview.addEventListener('dragover', (e) => {
    e.preventDefault();
    imagePreview.classList.add('dragover');
  });
  
  imagePreview.addEventListener('dragleave', () => {
    imagePreview.classList.remove('dragover');
  });
  
  imagePreview.addEventListener('drop', (e) => {
    e.preventDefault();
    imagePreview.classList.remove('dragover');
    
    const file = e.dataTransfer.files[0];
    
    if (file && file.type.startsWith('image/')) {
      // Manually set the file in the input
      const dT = new DataTransfer();
      dT.items.add(file);
      imageInput.files = dT.files;
      
      const reader = new FileReader();
      
      reader.onload = (e) => {
        imagePreview.style.backgroundImage = `url(${e.target.result})`;
        imagePreview.classList.add('has-image');
        removeImageBtn.classList.remove('hidden');
      };
      
      reader.readAsDataURL(file);
    }
  });
  
  // Form submission
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    
    const formData = {
      type: document.getElementById('node-type').value,
      label: document.getElementById('node-label').value,
      description: document.getElementById('node-description').value,
      date: document.getElementById('node-date').value,
      time: document.getElementById('node-time').value,
      location: document.getElementById('node-location').value,
      tags: document.getElementById('node-tags').value,
      notes: document.getElementById('node-notes').value
    };
    
    // Process image
    const file = imageInput.files[0];
    if (file) {
      const reader = new FileReader();
      
      reader.onload = (e) => {
        formData.image = e.target.result;
        saveNodeWithImage(formData);
      };
      
      reader.readAsDataURL(file);
    } else {
      // If editing and there's already an image
      if (form.dataset.nodeId && imagePreview.classList.contains('has-image')) {
        formData.image = imagePreview.style.backgroundImage.slice(5, -2); // Remove url() wrapper
      }
      saveNodeWithImage(formData);
    }
  });
  
  function saveNodeWithImage(formData) {
    // Process metadata
    const metadata = {};
    const metadataFields = document.querySelectorAll('.metadata-field');
    
    metadataFields.forEach(field => {
      const key = field.querySelector('.metadata-key').value.trim();
      const value = field.querySelector('.metadata-value').value.trim();
      
      if (key && value) {
        metadata[key] = value;
      }
    });
    
    formData.metadata = metadata;
    
    // Save node
    if (form.dataset.nodeId) {
      // Update existing node
      dataStore.updateNode(form.dataset.nodeId, formData);
      graph.selectNode(form.dataset.nodeId);
    } else {
      // Create new node
      const node = dataStore.addNode(formData);
      graph.selectNode(node.id);
      graph.centerOnNode(node.id);
    }
    
    // Update graph and close modal
    graph.renderGraph();
    closeModal();
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
        <div style="display: flex; gap: 8px;">
          <input type="text" class="metadata-value" placeholder="Value" value="${value}" style="flex-grow: 1;">
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
  
  // Close the modal
  function closeModal() {
    modal.classList.add('hidden');
    form.reset();
    form.dataset.nodeId = '';
    
    // Clear image preview
    imagePreview.style.backgroundImage = '';
    imagePreview.classList.remove('has-image');
    removeImageBtn.classList.add('hidden');
    
    // Clear metadata fields
    const metadataFields = document.getElementById('metadata-fields');
    metadataFields.innerHTML = '';
  }
}