document.addEventListener('DOMContentLoaded', function () {
    const toggleFormBtn = document.getElementById('toggleFormBtn');
    const noteForm = document.getElementById('noteForm');

    toggleFormBtn.addEventListener('click', function () {
        noteForm.classList.toggle('hidden');
    });
});
