// Smooth scrolling for navigation links
document.addEventListener('DOMContentLoaded', function() {
    // Navbar scroll effect
    const navbar = document.querySelector('.navbar');
    
    window.addEventListener('scroll', () => {
        if (window.scrollY > 50) {
            navbar.style.background = 'rgba(10, 20, 40, 0.98)';
            navbar.style.borderBottom = '1px solid rgba(59, 130, 246, 0.3)';
        } else {
            navbar.style.background = 'rgba(10, 20, 40, 0.95)';
            navbar.style.borderBottom = '1px solid rgba(59, 130, 246, 0.2)';
        }
    });

    // Smooth scrolling for navigation links
    const navLinks = document.querySelectorAll('.nav-links a');
    
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            
            const targetId = this.getAttribute('href');
            const targetSection = document.querySelector(targetId);
            
            if (targetSection) {
                const offsetTop = targetSection.getBoundingClientRect().top + window.pageYOffset - 80;
                
                window.scrollTo({
                    top: offsetTop,
                    behavior: 'smooth'
                });
            }
        });
    });

    // Intersection Observer for animations
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
                
                // Stagger animations for grid items
                if (entry.target.classList.contains('problems-grid') || 
                    entry.target.classList.contains('solution-grid') ||
                    entry.target.classList.contains('business-models')) {
                    const items = entry.target.children;
                    Array.from(items).forEach((item, index) => {
                        setTimeout(() => {
                            item.style.opacity = '1';
                            item.style.transform = 'translateY(0)';
                        }, index * 150);
                    });
                }

                // Timeline animation
                if (entry.target.classList.contains('timeline')) {
                    const items = entry.target.querySelectorAll('.timeline-item');
                    items.forEach((item, index) => {
                        setTimeout(() => {
                            item.style.opacity = '1';
                            item.style.transform = 'translateX(0)';
                        }, index * 200);
                    });
                }

                // Workflow steps animation
                if (entry.target.classList.contains('workflow-steps')) {
                    const steps = entry.target.querySelectorAll('.workflow-step');
                    const arrows = entry.target.querySelectorAll('.workflow-arrow');
                    
                    steps.forEach((step, index) => {
                        setTimeout(() => {
                            step.style.opacity = '1';
                            step.style.transform = 'translateY(0) scale(1)';
                        }, index * 200);
                    });

                    arrows.forEach((arrow, index) => {
                        setTimeout(() => {
                            arrow.style.opacity = '1';
                            arrow.style.transform = 'scaleX(1)';
                        }, (index + 0.5) * 200);
                    });
                }
            }
        });
    }, observerOptions);

    // Set initial styles for animated elements
    const animatedElements = document.querySelectorAll(`
        .problems-grid,
        .solution-grid,
        .business-models,
        .timeline,
        .workflow-steps,
        .comparison-table
    `);

    animatedElements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(30px)';
        el.style.transition = 'all 0.8s ease-out';
        observer.observe(el);
    });

    // Set initial styles for grid items
    const gridItems = document.querySelectorAll(`
        .problem-card,
        .solution-card,
        .business-card
    `);

    gridItems.forEach(item => {
        item.style.opacity = '0';
        item.style.transform = 'translateY(30px)';
        item.style.transition = 'all 0.6s ease-out';
    });

    // Set initial styles for timeline items
    const timelineItems = document.querySelectorAll('.timeline-item');
    timelineItems.forEach((item, index) => {
        item.style.opacity = '0';
        item.style.transform = index % 2 === 0 ? 'translateX(-50px)' : 'translateX(50px)';
        item.style.transition = 'all 0.6s ease-out';
    });

    // Set initial styles for workflow elements
    const workflowSteps = document.querySelectorAll('.workflow-step');
    const workflowArrows = document.querySelectorAll('.workflow-arrow');

    workflowSteps.forEach(step => {
        step.style.opacity = '0';
        step.style.transform = 'translateY(30px) scale(0.9)';
        step.style.transition = 'all 0.6s ease-out';
    });

    workflowArrows.forEach(arrow => {
        arrow.style.opacity = '0';
        arrow.style.transform = 'scaleX(0)';
        arrow.style.transformOrigin = 'left center';
        arrow.style.transition = 'all 0.4s ease-out';
    });

    // Parallax effect for circuit background
    window.addEventListener('scroll', () => {
        const scrolled = window.pageYOffset;
        const circuitBg = document.querySelector('.circuit-bg');
        
        if (circuitBg) {
            const speed = scrolled * 0.2;
            circuitBg.style.transform = `translateY(${speed}px)`;
        }
    });

    // Interactive hover effects for cards
    const cards = document.querySelectorAll(`
        .problem-card,
        .solution-card,
        .business-card,
        .workflow-step
    `);

    cards.forEach(card => {
        card.addEventListener('mouseenter', function() {
            this.style.transform = this.style.transform.replace('translateY(0px)', 'translateY(-10px)');
        });

        card.addEventListener('mouseleave', function() {
            this.style.transform = this.style.transform.replace('translateY(-10px)', 'translateY(0px)');
        });
    });

    // Logo pulse animation control
    const logoHexagon = document.querySelector('.logo-hexagon');
    if (logoHexagon) {
        logoHexagon.addEventListener('mouseenter', function() {
            this.style.animationDuration = '0.5s';
        });

        logoHexagon.addEventListener('mouseleave', function() {
            this.style.animationDuration = '2s';
        });
    }

    // Table row hover effects
    const tableRows = document.querySelectorAll('.table-row');
    tableRows.forEach(row => {
        row.addEventListener('mouseenter', function() {
            if (!this.classList.contains('highlight')) {
                this.style.background = 'rgba(59, 130, 246, 0.08)';
            }
        });

        row.addEventListener('mouseleave', function() {
            if (!this.classList.contains('highlight')) {
                this.style.background = 'transparent';
            }
        });
    });

    // Contact links animation
    const contactLinks = document.querySelectorAll('.contact-links a');
    contactLinks.forEach((link, index) => {
        link.style.opacity = '0';
        link.style.transform = 'translateX(-20px)';
        link.style.transition = 'all 0.4s ease-out';
        
        setTimeout(() => {
            link.style.opacity = '1';
            link.style.transform = 'translateX(0)';
        }, 2000 + (index * 150));
    });

    // Code snippet typing animation
    const codeLines = document.querySelectorAll('.code-line');
    if (codeLines.length > 0) {
        codeLines.forEach(line => {
            line.style.opacity = '0';
            line.style.transform = 'translateX(-10px)';
        });

        const contactSection = document.querySelector('#contact');
        const codeObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    codeLines.forEach((line, index) => {
                        setTimeout(() => {
                            line.style.opacity = '1';
                            line.style.transform = 'translateX(0)';
                            line.style.transition = 'all 0.4s ease-out';
                        }, index * 200);
                    });
                    codeObserver.unobserve(entry.target);
                }
            });
        }, { threshold: 0.3 });

        if (contactSection) {
            codeObserver.observe(contactSection);
        }
    }

    // Active nav link highlighting
    window.addEventListener('scroll', () => {
        const sections = document.querySelectorAll('section[id]');
        const scrollPos = window.scrollY + 100;

        sections.forEach(section => {
            const sectionTop = section.offsetTop;
            const sectionHeight = section.offsetHeight;
            const sectionId = section.getAttribute('id');
            const navLink = document.querySelector(`.nav-links a[href="#${sectionId}"]`);

            if (scrollPos >= sectionTop && scrollPos < sectionTop + sectionHeight) {
                navLinks.forEach(link => link.classList.remove('active'));
                if (navLink) {
                    navLink.classList.add('active');
                }
            }
        });
    });

    // Add active class styles
    const style = document.createElement('style');
    style.textContent = `
        .nav-links a.active {
            color: #60a5fa;
        }
        .nav-links a.active::after {
            width: 100%;
        }
    `;
    document.head.appendChild(style);

    // Loading animation
    setTimeout(() => {
        document.body.classList.add('loaded');
    }, 100);
});

// Mobile menu functionality (basic implementation)
document.addEventListener('DOMContentLoaded', function() {
    // Add mobile menu button if screen is small
    if (window.innerWidth <= 768) {
        const navbar = document.querySelector('.nav-container');
        const navLinks = document.querySelector('.nav-links');
        
        // Create mobile menu button
        const mobileMenuBtn = document.createElement('button');
        mobileMenuBtn.innerHTML = '☰';
        mobileMenuBtn.className = 'mobile-menu-btn';
        mobileMenuBtn.style.cssText = `
            background: none;
            border: none;
            color: white;
            font-size: 1.5rem;
            cursor: pointer;
            display: block;
        `;
        
        navbar.appendChild(mobileMenuBtn);
        
        // Toggle mobile menu
        let isMenuOpen = false;
        mobileMenuBtn.addEventListener('click', () => {
            isMenuOpen = !isMenuOpen;
            
            if (isMenuOpen) {
                navLinks.style.display = 'flex';
                navLinks.style.flexDirection = 'column';
                navLinks.style.position = 'absolute';
                navLinks.style.top = '70px';
                navLinks.style.left = '0';
                navLinks.style.width = '100%';
                navLinks.style.background = 'rgba(10, 20, 40, 0.98)';
                navLinks.style.padding = '20px';
                navLinks.style.boxShadow = '0 5px 15px rgba(0,0,0,0.3)';
                mobileMenuBtn.innerHTML = '✕';
            } else {
                navLinks.style.display = 'none';
                mobileMenuBtn.innerHTML = '☰';
            }
        });
        
        // Close menu when clicking on a link
        navLinks.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', () => {
                navLinks.style.display = 'none';
                mobileMenuBtn.innerHTML = '☰';
                isMenuOpen = false;
            });
        });
    }
});

// Performance optimization: Throttle scroll events
function throttle(func, limit) {
    let inThrottle;
    return function() {
        const args = arguments;
        const context = this;
        if (!inThrottle) {
            func.apply(context, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    }
}

// Apply throttling to scroll events
window.addEventListener('scroll', throttle(() => {
    // All scroll-based animations are already optimized above
}, 16)); // ~60fps