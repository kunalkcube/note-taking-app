document.addEventListener('DOMContentLoaded', function () {
    const toggleFormBtn = document.getElementById('toggleFormBtn');
    const noteForm = document.getElementById('noteForm');
    const userMenuButton = document.getElementById('user-menu-button');
    const userDropdown = document.getElementById('user-dropdown');

    // Toggle note form
    toggleFormBtn?.addEventListener('click', function () {
        noteForm.classList.toggle('hidden');
    });

    // Toggle user dropdown
    userMenuButton?.addEventListener('click', function () {
        userDropdown.classList.toggle('hidden');
    });

    // Hide dropdown when clicking outside
    document.addEventListener('click', function (event) {
        if (!userMenuButton.contains(event.target) && !userDropdown.contains(event.target)) {
            userDropdown.classList.add('hidden');
        }
    });
});
