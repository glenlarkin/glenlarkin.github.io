// --- Smooth Scroll for Navigation ---
document.querySelectorAll('.nav-link').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();

        const targetId = this.getAttribute('href');
        const targetElement = document.querySelector(targetId);
        const headerOffset = document.querySelector('header').offsetHeight; // Get the height of the fixed header

        // Calculate the position to scroll to, accounting for the header's height
        const elementPosition = targetElement.getBoundingClientRect().top + window.scrollY;
        const offsetPosition = elementPosition - headerOffset - 20; // Added extra 20px for a little buffer

        window.scrollTo({
            top: offsetPosition,
            behavior: 'smooth'
        });
    });
});

// --- Typewriter Effect for Professional Title ---
const typewriterTextElement = document.getElementById('typewriter-text');
// Customize these phrases for your professional titles/taglines
const phrases = [
    "IT Supervisor",
    "Cybersecurity Enthusiast",
    "Systems Administrator",
    "Problem Solver",
    "Technical Expert"
]
let phraseIndex = 0;
let charIndex = 0;
let isDeleting = false;
const typingSpeed = 100; // milliseconds per character
const deletingSpeed = 50;
const pauseBetweenPhrases = 1500; // milliseconds

function typeWriter() {
    const currentPhrase = phrases[phraseIndex];
    if (isDeleting) {
        typewriterTextElement.textContent = currentPhrase.substring(0, charIndex - 1);
        charIndex--;
    } else {
        typewriterTextElement.textContent = currentPhrase.substring(0, charIndex + 1);
        charIndex++;
    }

    if (!isDeleting && charIndex === currentPhrase.length) {
        // Pause at end of phrase
        setTimeout(() => isDeleting = true, pauseBetweenPhrases);
    } else if (isDeleting && charIndex === 0) {
        isDeleting = false;
        phraseIndex = (phraseIndex + 1) % phrases.length; // Move to next phrase
    }

    const currentSpeed = isDeleting ? deletingSpeed : typingSpeed;
    setTimeout(typeWriter, currentSpeed);
}

// Start the typewriter effect when the DOM is fully loaded
document.addEventListener('DOMContentLoaded', typeWriter);

// --- Back to Top Button ---
const backToTopButton = document.getElementById('back-to-top');

window.addEventListener('scroll', () => {
    if (window.scrollY > 300) { // Show button after scrolling 300px
        backToTopButton.style.display = 'block';
    } else {
        backToTopButton.style.display = 'none';
    }
});

backToTopButton.addEventListener('click', () => {
    window.scrollTo({
        top: 0,
        behavior: 'smooth'
    });
});

// --- Scroll Reveal Animation ---
const scrollRevealSections = document.querySelectorAll('.scroll-reveal');

const observerOptions = {
    root: null, // viewport
    rootMargin: '0px',
    threshold: 0.1 // Trigger when 10% of the element is visible
};

const observer = new IntersectionObserver((entries, observer) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add('active');
            observer.unobserve(entry.target); // Stop observing once animated
        }
    });
}, observerOptions);

scrollRevealSections.forEach(section => {
    observer.observe(section);
});