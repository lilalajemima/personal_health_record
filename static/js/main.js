// Initialize tooltips
document.addEventListener('DOMContentLoaded', function() {
    // Enable Bootstrap tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Flash message auto-dismiss
    var alerts = document.querySelectorAll('.alert');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            bootstrap.Alert.getInstance(alert).close();
        }, 5000);
    });
    
    // Form validation
    var forms = document.querySelectorAll('.needs-validation');
    Array.prototype.slice.call(forms).forEach(function(form) {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });
    
    // Timezone detection
    if (document.getElementById('timezone')) {
        document.getElementById('timezone').value = Intl.DateTimeFormat().resolvedOptions().timeZone;
    }
    
    // Password strength meter
    if (document.getElementById('password')) {
        document.getElementById('password').addEventListener('input', function() {
            var password = this.value;
            var strength = 0;
            
            if (password.length >= 8) strength++;
            if (password.match(/[a-z]/)) strength++;
            if (password.match(/[A-Z]/)) strength++;
            if (password.match(/[0-9]/)) strength++;
            if (password.match(/[^a-zA-Z0-9]/)) strength++;
            
            var meter = document.getElementById('password-strength-meter');
            if (meter) {
                meter.value = strength;
                meter.className = 'form-range strength-' + strength;
            }
        });
    }
    
    // File input preview
    document.querySelectorAll('.file-input-preview').forEach(function(input) {
        input.addEventListener('change', function() {
            var preview = document.getElementById(this.dataset.previewTarget);
            if (preview) {
                if (this.files && this.files[0]) {
                    var reader = new FileReader();
                    reader.onload = function(e) {
                        preview.src = e.target.result;
                        preview.style.display = 'block';
                    };
                    reader.readAsDataURL(this.files[0]);
                } else {
                    preview.style.display = 'none';
                }
            }
        });
    });
    
    // Dark mode toggle
    var darkModeToggle = document.getElementById('darkModeToggle');
    if (darkModeToggle) {
        darkModeToggle.addEventListener('click', function() {
            document.body.classList.toggle('dark-mode');
            localStorage.setItem('darkMode', document.body.classList.contains('dark-mode'));
        });
        
        // Check for saved dark mode preference
        if (localStorage.getItem('darkMode') === 'true') {
            document.body.classList.add('dark-mode');
            darkModeToggle.checked = true;
        }
    }
});