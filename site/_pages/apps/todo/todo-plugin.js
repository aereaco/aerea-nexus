// Third-party Nexus-UX Plugin Example
const CustomPlugin = {
    name: 'test-plugin',
    attribute: 'test-plugin',
    handle: (el, expression, runtime) => {
        el.style.border = '4px solid #f0f'; // Fuchsia
        const badge = document.createElement('div');
        badge.className = 'badge badge-secondary absolute -top-4 -right-4 rotate-12 z-50 shadow-xl font-bold';
        badge.textContent = `Dynamic Plugin Loaded: ${expression}`;
        el.appendChild(badge);
        console.log(`[Plugin] Successfully applied data-test-plugin="${expression}" to ${el.tagName}`);
    }
};

// Decentralized Registration via the Public API
const ux = globalThis.UX || globalThis.Nexus;
if (ux) {
    ux.register('attribute', 'test-plugin', CustomPlugin);
    ux.register('attribute', 'test', CustomPlugin);
    document.querySelectorAll('[data-test-plugin]').forEach(el => {
        if (typeof ux.process === 'function') {
            ux.process(el, true);
        } else if (ux.coordinator) {
            ux.coordinator.processElement(el, true);
        }
    });
} else {
    console.error("[Plugin Error] Global UX instance not found!");
}
