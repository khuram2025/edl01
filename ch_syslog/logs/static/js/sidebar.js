document.addEventListener('DOMContentLoaded', function() {
    const toggleButton = document.getElementById('sidebar-toggle');
    const sidebar = document.getElementById('sidebar');
    const topbar = document.getElementById('topbar');
    const mainContent = document.getElementById('main-content');
    const mobileMenuButton = document.getElementById('mobile-menu-button');

    // Toggle sidebar on button click
    toggleButton.addEventListener('click', function() {
        sidebar.classList.toggle('sidebar-collapsed');
        topbar.classList.toggle('topbar-collapsed');
        mainContent.classList.toggle('main-content-collapsed');
    });

    // Handle mobile menu
    mobileMenuButton.addEventListener('click', function() {
        sidebar.classList.toggle('mobile-open');
    });

    // Close sidebar on mobile when clicking outside
    document.addEventListener('click', function(event) {
        if (window.innerWidth <= 768) {
            if (!sidebar.contains(event.target) && 
                !mobileMenuButton.contains(event.target) && 
                sidebar.classList.contains('mobile-open')) {
                sidebar.classList.remove('mobile-open');
            }
        }
    });

    // Set active menu item based on current URL
    const currentPath = window.location.pathname;
    const menuItems = document.querySelectorAll('.sidebar-menu-item');
    menuItems.forEach(item => {
        if (item.getAttribute('href') === currentPath) {
            item.classList.add('active');
        }
    });
});
