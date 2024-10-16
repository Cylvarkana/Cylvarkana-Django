document.addEventListener("DOMContentLoaded", function() {
    const passwordFields = document.querySelectorAll("input[type='password']");

    passwordFields.forEach(field => {
        const toggleButton = document.createElement('img');
        toggleButton.style.cursor = 'pointer';
        toggleButton.style.marginLeft = '10px';
        toggleButton.src = '/static/images/eye.svg';

        toggleButton.addEventListener('click', function() {
            if (field.type === 'password') {
                field.type = 'text';
                toggleButton.src = '/static/images/eye-slash.svg';
            } else {
                field.type = 'password';
                toggleButton.src = '/static/images/eye.svg';
            }
        });

        field.parentElement.appendChild(toggleButton);
    });
});
