export function initThemeManager() {
  const themeToggle = document.getElementById('theme-toggle');
  const themeIcon = themeToggle.querySelector('i');
  const body = document.body;
  
  // Check if user has a saved preference
  const savedTheme = localStorage.getItem('graphIntel_theme');
  
  // Check if browser has a preferred color scheme
  const prefersDarkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;
  
  // Set initial theme
  if (savedTheme === 'dark' || (savedTheme === null && prefersDarkMode)) {
    body.classList.add('dark-theme');
    themeIcon.className = 'fas fa-sun';
  } else {
    body.classList.remove('dark-theme');
    themeIcon.className = 'fas fa-moon';
  }
  
  // Toggle theme
  themeToggle.addEventListener('click', () => {
    const isDarkTheme = body.classList.toggle('dark-theme');
    
    // Update icon
    themeIcon.className = isDarkTheme ? 'fas fa-sun' : 'fas fa-moon';
    
    // Save preference
    localStorage.setItem('graphIntel_theme', isDarkTheme ? 'dark' : 'light');
  });
  
  // Listen for system preference changes
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
    // Only auto-switch if the user hasn't saved a preference
    if (localStorage.getItem('graphIntel_theme') === null) {
      const shouldBeDark = e.matches;
      
      body.classList.toggle('dark-theme', shouldBeDark);
      themeIcon.className = shouldBeDark ? 'fas fa-sun' : 'fas fa-moon';
    }
  });
}