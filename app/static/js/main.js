// CyberGuard AI - NextGen Interactive SOC Interactions

document.addEventListener('DOMContentLoaded', () => {
    console.log('CyberGuard AI Obsidian SOC Engine Initialized.');

    // 1. Auto-dismiss alerts with smooth fade
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
            alert.style.opacity = '0';
            alert.style.transform = 'translateY(-8px)';
            setTimeout(() => {
                const closeButton = alert.querySelector('.btn-close');
                if (closeButton) {
                    closeButton.click();
                } else {
                    alert.remove();
                }
            }, 400);
        }, 5000);
    });

    // 2. Animated KPI Counters on Overview Screens
    const counterElements = document.querySelectorAll('[data-counter-target]');
    counterElements.forEach(counter => {
        const target = +counter.getAttribute('data-counter-target');
        const duration = 1200; // ms
        const startTime = performance.now();

        const updateCounter = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            // Ease out quad
            const easeOutProgress = 1 - (1 - progress) * (1 - progress);
            const currentVal = Math.floor(easeOutProgress * target);
            counter.innerText = currentVal.toLocaleString();

            if (progress < 1) {
                requestAnimationFrame(updateCounter);
            } else {
                counter.innerText = target.toLocaleString();
            }
        };

        requestAnimationFrame(updateCounter);
    });

    // 3. Live UTC Clock in Navbar or Telemetry Header if container exists
    const clockElement = document.getElementById('socLiveUtcClock');
    if (clockElement) {
        const updateClock = () => {
            const now = new Date();
            clockElement.innerText = now.toUTCString().replace('GMT', 'UTC');
        };
        updateClock();
        setInterval(updateClock, 1000);
    }
});
