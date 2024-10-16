// Side bar collapse/expand
document.addEventListener('DOMContentLoaded', function() {
    const sidebarToggle = document.querySelector('.sidebar-toggle');
    const sidebar = document.querySelector('.sidebar');
    const toggleArrow = document.querySelector('.toggle-arrow');

    sidebarToggle.addEventListener('click', function() {
        sidebar.classList.toggle('collapsed');
        if (sidebar.classList.contains('collapsed')) {
            toggleArrow.innerHTML = '&raquo;';
        } else {
            toggleArrow.innerHTML = '&laquo;';
        }
    });
});
