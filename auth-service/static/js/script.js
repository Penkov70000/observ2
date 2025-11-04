// Simple JavaScript for enhanced interactivity
document.addEventListener('DOMContentLoaded', function() {
    // Auto-hide alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 300);
        }, 5000);
    });

    // Copy token to clipboard
    const copyButtons = document.querySelectorAll('.copy-token');
    copyButtons.forEach(button => {
        button.addEventListener('click', function() {
            const token = this.getAttribute('data-token');
            navigator.clipboard.writeText(token).then(() => {
                const originalText = this.textContent;
                this.textContent = 'Copied!';
                setTimeout(() => {
                    this.textContent = originalText;
                }, 2000);
            });
        });
    });
});