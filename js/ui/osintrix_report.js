 // OSINTrix Report Panel JavaScript
    document.addEventListener('DOMContentLoaded', function() {
      // DOM Elements
      const container = document.getElementById('osintrix_report_container');
      const minimizeBtn = document.getElementById('osintrix_report_btn_minimize');
      const expandBtn = document.getElementById('osintrix_report_btn_expand');
      const tabs = document.querySelectorAll('.osintrix_report_tab');
      const tabContents = document.querySelectorAll('.osintrix_report_tab_content');
      const saveBtn = document.getElementById('osintrix_report_save');
      const clearBtn = document.getElementById('osintrix_report_clear');
      const notesTextarea = document.getElementById('osintrix_notes_textarea');
      const addEventBtn = document.getElementById('osintrix_report_add_event');
      const eventInput = document.getElementById('osintrix_report_event');
      const eventDetails = document.getElementById('osintrix_report_event_details');
      const dateInput = document.getElementById('osintrix_report_date');
      const timeline = document.getElementById('osintrix_report_timeline');
      const header = document.getElementById('osintrix_report_header');
      const resizerH = document.getElementById('osintrix_report_resizer_h');
      const resizerV = document.getElementById('osintrix_report_resizer_v');
      const priorityBtn = document.getElementById('osintrix_priority_btn');
      const priorityMenu = document.getElementById('osintrix_priority_menu');
      const imageButton = document.getElementById('osintrix_image_button');
      const imageUploader = document.getElementById('osintrix_image_uploader');
      const imageUploadArea = document.getElementById('osintrix_image_upload_area');
      const imageFileInput = document.getElementById('osintrix_image_file_input');
      const imageUrlInput = document.getElementById('osintrix_image_url_input');
      const imageCancel = document.getElementById('osintrix_image_cancel');
      const imageInsert = document.getElementById('osintrix_image_insert');

      // Panel state
      let isMinimized = false;
      let isExpanded = false;
      let currentWidth = 420;
      let currentHeight = container.offsetHeight;
      let initialHeight;
      let originalPosition;
      let selectedPriority = 'low';
      
      // Formatting toolbar state
      const formattingTools = document.querySelectorAll('.osintrix_notes_tool[data-format]');

      // Initialize with current date in the date input
      const today = new Date();
      dateInput.value = today.toISOString().split('T')[0];

      // Minimize/maximize panel
      minimizeBtn.addEventListener('click', function() {
        isMinimized = !isMinimized;
        container.classList.toggle('osintrix_report_minimized', isMinimized);
        minimizeBtn.innerHTML = isMinimized ? 
          '<span class="osintrix-icon">+</span>' : 
          '<span class="osintrix-icon">−</span>';
      });

      // Expand/restore panel
      expandBtn.addEventListener('click', function() {
        isExpanded = !isExpanded;
        
        if (isExpanded) {
          initialHeight = container.style.height || `${container.offsetHeight}px`;
          originalPosition = {
            bottom: container.style.bottom || 'var(--space-4, 16px)',
            transform: container.style.transform
          };
          
          container.style.width = '80%';
          container.style.height = '80vh';
          container.style.bottom = '10vh';
          container.style.transform = 'translateX(-50%)';
          expandBtn.innerHTML = '<span class="osintrix-icon">⤓</span>';
        } else {
          container.style.width = currentWidth + 'px';
          container.style.height = initialHeight;
          container.style.bottom = originalPosition.bottom;
          container.style.transform = originalPosition.transform;
          expandBtn.innerHTML = '<span class="osintrix-icon">⤢</span>';
        }
      });

      // Tab switching
      tabs.forEach(tab => {
        tab.addEventListener('click', function() {
          const tabName = this.getAttribute('data-tab');
          
          // Update active tab
          tabs.forEach(t => t.classList.remove('active'));
          this.classList.add('active');
          
          // Show active content
          tabContents.forEach(content => {
            if (content.getAttribute('data-tab') === tabName) {
              content.classList.add('active');
            } else {
              content.classList.remove('active');
            }
          });
        });
      });

      // Save notes (localStorage for demo)
      saveBtn.addEventListener('click', function() {
        const notes = notesTextarea.value;
        localStorage.setItem('osintrixNotes', notes);
        
        // Update saved status
        document.querySelector('.osintrix_report_status span').textContent = 'Last saved: just now';
        
        // Show quick save animation
        saveBtn.classList.add('saving');
        setTimeout(() => saveBtn.classList.remove('saving'), 500);
      });

      // Clear notes
      clearBtn.addEventListener('click', function() {
        if (confirm('Are you sure you want to clear all notes?')) {
          notesTextarea.value = '';
        }
      });

      // Load saved notes
      const savedNotes = localStorage.getItem('osintrixNotes');
      if (savedNotes) {
        notesTextarea.value = savedNotes;
      }

      // Priority dropdown functionality
      priorityBtn.addEventListener('click', function() {
        priorityMenu.classList.toggle('active');
      });

      // Close priority dropdown when clicking elsewhere
      document.addEventListener('click', function(e) {
        if (!e.target.closest('#osintrix_priority_dropdown')) {
          priorityMenu.classList.remove('active');
        }
      });

      // Select priority
      document.querySelectorAll('.osintrix_priority_option').forEach(option => {
        option.addEventListener('click', function() {
          selectedPriority = this.getAttribute('data-priority');
          priorityMenu.classList.remove('active');
          priorityBtn.innerHTML = `<span>Priority: ${selectedPriority.charAt(0).toUpperCase() + selectedPriority.slice(1)}</span> <span class="osintrix-icon">▼</span>`;
        });
      });

      // Add timeline entry
      addEventBtn.addEventListener('click', function() {
        const event = eventInput.value.trim();
        const date = dateInput.value;
        const details = eventDetails.value.trim();
        
        if (!event) {
          // Highlight the input field to indicate it's required
          eventInput.style.borderColor = 'var(--danger, #e53e3e)';
          eventInput.focus();
          setTimeout(() => {
            eventInput.style.borderColor = '';
          }, 2000);
          return;
        }
        
        const now = new Date();
        const timeString = `${date} ${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`;
        
        let priorityHTML = '';
        if (selectedPriority !== 'low') {
          priorityHTML = `<span class="osintrix_priority_tag osintrix_priority_${selectedPriority}">${selectedPriority.charAt(0).toUpperCase() + selectedPriority.slice(1)}</span>`;
        }
        
        let content = event;
        if (details) {
          content += `<br><div style="margin-top:4px; font-size:0.8rem; color:var(--text-secondary);">${details}</div>`;
        }
        
        const entryHTML = `
          <div class="osintrix_report_timeline_entry ${selectedPriority}-priority">
            <div class="osintrix_report_timeline_time">
              ${timeString}
              <div class="osintrix_report_timeline_actions">
                <button class="osintrix_timeline_action" title="Edit"><span class="osintrix-icon">✎</span></button>
                <button class="osintrix_timeline_action" title="Delete"><span class="osintrix-icon">×</span></button>
              </div>
            </div>
            <div class="osintrix_report_timeline_content">${content} ${priorityHTML}</div>
          </div>
        `;
        
        timeline.insertAdjacentHTML('afterbegin', entryHTML);
        eventInput.value = '';
        eventDetails.value = '';
        
        // Add event listeners to new buttons
        const newEntry = timeline.firstElementChild;
        const deleteBtn = newEntry.querySelector('.osintrix_timeline_action[title="Delete"]');
        if (deleteBtn) {
          deleteBtn.addEventListener('click', function() {
            if (confirm('Are you sure you want to delete this entry?')) {
              newEntry.remove();
            }
          });
        }
      });

      // Format text functions
      formattingTools.forEach(tool => {
        tool.addEventListener('click', function() {
          const format = this.getAttribute('data-format');
          const textarea = notesTextarea;
          const start = textarea.selectionStart;
          const end = textarea.selectionEnd;
          const selectedText = textarea.value.substring(start, end);
          let replacement = '';
          
          switch(format) {
            case 'bold':
              replacement = `**${selectedText}**`;
              break;
            case 'italic':
              replacement = `*${selectedText}*`;
              break;
            case 'underline':
              replacement = `_${selectedText}_`;
              break;
            case 'h1':
              replacement = `\n# ${selectedText}\n`;
              break;
            case 'h2':
              replacement = `\n## ${selectedText}\n`;
              break;
            case 'h3':
              replacement = `\n### ${selectedText}\n`;
              break;
            case 'bullet':
              // Split by line and add bullet points
              if (selectedText) {
                const lines = selectedText.split('\n');
                replacement = lines.map(line => `• ${line}`).join('\n');
              } else {
                replacement = '• ';
              }
              break;
            case 'number':
              if (selectedText) {
                const lines = selectedText.split('\n');
                replacement = lines.map((line, i) => `${i+1}. ${line}`).join('\n');
              } else {
                replacement = '1. ';
              }
              break;
            case 'check':
              if (selectedText) {
                const lines = selectedText.split('\n');
                replacement = lines.map(line => `[ ] ${line}`).join('\n');
              } else {
                replacement = '[ ] ';
              }
              break;
            case 'highlight':
              replacement = `==${selectedText}==`;
              break;
            case 'code':
              if (selectedText.includes('\n')) {
                replacement = `\`\`\`\n${selectedText}\n\`\`\``;
              } else {
                replacement = `\`${selectedText}\``;
              }
              break;
            case 'quote':
              // Split by line and add quote prefix
              if (selectedText) {
                const lines = selectedText.split('\n');
                replacement = lines.map(line => `> ${line}`).join('\n');
              } else {
                replacement = '> ';
              }
              break;
            case 'link':
              if (selectedText) {
                replacement = `[${selectedText}](url)`;
              } else {
                replacement = '[](url)';
              }
              break;
          }
          
          // Insert the formatted text
          textarea.value = textarea.value.substring(0, start) + replacement + textarea.value.substring(end);
          
          // Set the cursor position
          textarea.focus();
          if (format === 'link' && selectedText) {
            // Place cursor at the URL position
            textarea.selectionStart = start + selectedText.length + 3;
            textarea.selectionEnd = start + selectedText.length + 6;
          } else {
            textarea.selectionStart = start + replacement.length;
            textarea.selectionEnd = start + replacement.length;
          }
        });
      });

      // Image uploader functionality
      imageButton.addEventListener('click', function(e) {
        e.preventDefault();
        e.stopPropagation();
        
        // Calculate position for the uploader
        const rect = imageButton.getBoundingClientRect();
        imageUploader.style.display = 'block';
        imageUploader.style.top = `${rect.bottom + 10}px`;
        imageUploader.style.left = `${rect.left}px`;
      });
      
      // Close image uploader when clicking cancel
      imageCancel.addEventListener('click', function() {
        imageUploader.style.display = 'none';
        imageUrlInput.value = '';
      });
      
      // Open file browser when clicking upload area
      imageUploadArea.addEventListener('click', function() {
        imageFileInput.click();
      });
      
      // Handle file selection
      imageFileInput.addEventListener('change', function() {
        // In a real app, this would upload the file to a server
        // Here we'll just use it as a demo
        if (this.files && this.files[0]) {
          // Would normally upload file here
          imageUploadArea.innerHTML = `<div>Selected: ${this.files[0].name}</div>`;
        }
      });
      
      // Handle image insertion
      imageInsert.addEventListener('click', function() {
        const urlValue = imageUrlInput.value.trim();
        const fileSelected = imageFileInput.files && imageFileInput.files[0];
        
        // For demo purposes, just insert the URL or filename
        let imgMarkdown = '';
        
        if (urlValue) {
          imgMarkdown = `![Image](${urlValue})`;
        } else if (fileSelected) {
          // In a real app, this would use the uploaded file URL
          imgMarkdown = `![${fileSelected.name}](uploaded-file)`;
        } else {
          imgMarkdown = '![placeholder image](https://via.placeholder.com/300x200)';
        }
        
        // Insert at cursor position
        const textarea = notesTextarea;
        const curPos = textarea.selectionStart;
        
        textarea.value = 
          textarea.value.substring(0, curPos) + 
          imgMarkdown + 
          textarea.value.substring(textarea.selectionEnd);
        
        // Reset and close uploader
        imageUploader.style.display = 'none';
        imageUrlInput.value = '';
        imageFileInput.value = '';
        imageUploadArea.innerHTML = `
          <div class="osintrix_image_upload_text">Drop image here or click to upload</div>
          <span class="osintrix-icon" style="font-size: 24px;">📁</span>
        `;
      });

      // Close image uploader when clicking outside
      document.addEventListener('click', function(e) {
        if (imageUploader.style.display === 'block' && 
            !e.target.closest('#osintrix_image_uploader') && 
            !e.target.closest('#osintrix_image_button')) {
          imageUploader.style.display = 'none';
        }
      });

      // Timeline entry action handlers
      document.addEventListener('click', function(e) {
        // Delete button handler
        if (e.target.closest('.osintrix_timeline_action[title="Delete"]')) {
          const entry = e.target.closest('.osintrix_report_timeline_entry');
          if (confirm('Are you sure you want to delete this entry?')) {
            entry.remove();
          }
        }
        
        // Edit button handler (just a placeholder - would be more complex in real app)
        if (e.target.closest('.osintrix_timeline_action[title="Edit"]')) {
          const entry = e.target.closest('.osintrix_report_timeline_entry');
          const content = entry.querySelector('.osintrix_report_timeline_content').textContent;
          
          // For demo purposes we'll just populate the form fields
          eventInput.value = content.split('Medium')[0].split('Low')[0].split('High')[0].trim();
          tabs[1].click(); // Switch to timeline tab
          eventInput.focus();
        }
      });

      // Draggable header
      let isDragging = false;
      let dragStartX, dragStartY;
      let initialLeft, initialBottom;

      header.addEventListener('mousedown', startDrag);

      function startDrag(e) {
        // Only allow dragging from header (not from buttons)
        if (e.target.closest('.osintrix_report_btn')) return;
        
        isDragging = true;
        dragStartX = e.clientX;
        dragStartY = e.clientY;
        
        const rect = container.getBoundingClientRect();
        initialLeft = rect.left;
        initialBottom = window.innerHeight - rect.bottom;
        
        document.addEventListener('mousemove', drag);
        document.addEventListener('mouseup', stopDrag);
        
        // Prevent text selection during drag
        e.preventDefault();
      }

      function drag(e) {
        if (!isDragging) return;
        
        const deltaX = e.clientX - dragStartX;
        const deltaY = e.clientY - dragStartY;
        
        const viewportWidth = window.innerWidth;
        const viewportHeight = window.innerHeight;
        
        // Calculate new position
        const newLeft = Math.max(10, Math.min(viewportWidth - 100, initialLeft + deltaX));
        const newBottom = Math.max(10, Math.min(viewportHeight - 50, initialBottom - deltaY));
        
        // Center horizontally
        container.style.left = `${newLeft}px`;
        container.style.bottom = `${newBottom}px`;
        container.style.transform = 'none'; // Remove centering transform during drag
      }

      function stopDrag() {
        isDragging = false;
        document.removeEventListener('mousemove', drag);
        document.removeEventListener('mouseup', stopDrag);
      }

      // Resizable panel
      let isResizingH = false;
      let isResizingV = false;
      let startResizeX, startResizeY;
      let initialResizeWidth, initialResizeHeight;

      resizerH.addEventListener('mousedown', startResizeH);
      resizerV.addEventListener('mousedown', startResizeV);

      function startResizeH(e) {
        isResizingH = true;
        startResizeX = e.clientX;
        initialResizeWidth = container.offsetWidth;
        
        document.addEventListener('mousemove', resizeH);
        document.addEventListener('mouseup', stopResizeH);
        
        // Prevent text selection during resize
        e.preventDefault();
      }

      function startResizeV(e) {
        isResizingV = true;
        startResizeY = e.clientY;
        initialResizeHeight = container.offsetHeight;
        
        document.addEventListener('mousemove', resizeV);
        document.addEventListener('mouseup', stopResizeV);
        
        // Prevent text selection during resize
        e.preventDefault();
      }

      function resizeH(e) {
        if (!isResizingH) return;
        
        const deltaX = startResizeX - e.clientX;
        const newWidth = Math.max(300, Math.min(800, initialResizeWidth + deltaX * 2));
        
        container.style.width = newWidth + 'px';
        currentWidth = newWidth;
      }

      function resizeV(e) {
        if (!isResizingV) return;
        
        const deltaY = e.clientY - startResizeY;
        const newHeight = Math.max(300, Math.min(window.innerHeight * 0.8, initialResizeHeight + deltaY));
        
        container.style.height = newHeight + 'px';
        currentHeight = newHeight;
      }

      function stopResizeH() {
        isResizingH = false;
        document.removeEventListener('mousemove', resizeH);
        document.removeEventListener('mouseup', stopResizeH);
      }

      function stopResizeV() {
        isResizingV = false;
        document.removeEventListener('mousemove', resizeV);
        document.removeEventListener('mouseup', stopResizeV);
      }
    });