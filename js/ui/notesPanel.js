export function setupNotesPanel(dataStore) {
  const panel = document.getElementById('notes-panel');
  const toggleBtn = panel.querySelector('.toggle-panel');
  const notesTextarea = document.getElementById('investigation-notes');
  const saveBtn = document.getElementById('save-notes');
  
  // Toggle panel
  toggleBtn.addEventListener('click', () => {
    panel.classList.toggle('collapsed');
    panel.classList.toggle('right');
    toggleBtn.querySelector('i').classList.toggle('fa-chevron-right');
    toggleBtn.querySelector('i').classList.toggle('fa-chevron-left');
  });
  
  // Save notes
  saveBtn.addEventListener('click', () => {
    const notes = notesTextarea.value;
    dataStore.saveInvestigationNotes(notes);
    
    // Show confirmation
    saveBtn.textContent = 'Saved!';
    saveBtn.classList.add('success');
    
    setTimeout(() => {
      saveBtn.textContent = 'Save Notes';
      saveBtn.classList.remove('success');
    }, 2000);
  });
  
  // Load notes from data store
  document.addEventListener('dataStore:updated', () => {
    const notes = dataStore.getInvestigationNotes();
    notesTextarea.value = notes;
  });
  
  // Autosave notes when typing stops
  let autosaveTimeout;
  notesTextarea.addEventListener('input', () => {
    clearTimeout(autosaveTimeout);
    
    autosaveTimeout = setTimeout(() => {
      const notes = notesTextarea.value;
      dataStore.saveInvestigationNotes(notes);
    }, 2000);
  });
  
  // Initialize notes
  const notes = dataStore.getInvestigationNotes();
  notesTextarea.value = notes;
}