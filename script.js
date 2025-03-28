// Reusable host expressions that can be used across multiple directives
const hostExpressions = [
    {value: "'none'", description: "Block all resources for this directive"},
    {value: "'self'", description: "Allow from same origin (scheme://host:port)"},
    {value: "*.example.com", description: "Allow from example.com and all subdomains"},
    {value: "cdn.example.com", description: "Allow from specific CDN domain"},
    {value: "example.com:8080", description: "Allow from specific port"},
    {value: "example.com:*", description: "Allow from any port on domain"},
    {value: "https://example.com/path", description: "Allow from specific path"},
    {value: "https://example.com/path/*", description: "Allow from path and subpaths"},
    {value: "https://example.com:443/path/*", description: "Allow from path and subpaths on port 443"},
    {value: "data:", description: "Allow data: URIs (base64 encoded resources)"},
    {value: "blob:", description: "Allow blob: URLs"},
    {value: "https:", description: "Allow from any HTTPS source (wildcard)"}
];

const directiveExplanations = {
    'default-src': {
        description: 'Fallback for other directives if not specified. Sets default policy for most resource types.',
        values: [
            ...hostExpressions,
            {value: "'unsafe-inline'", description: "Allow inline scripts/styles (security risk)"},
            {value: "'unsafe-eval'", description: "Allow eval(), Function(), setTimeout(string) etc."}
        ]
    },
    'script-src': {
        description: 'Controls sources for JavaScript execution. Critical for XSS protection.',
        values: [
            ...hostExpressions,
            {value: "'unsafe-inline'", description: "Allow inline scripts (dangerous for XSS)"},
            {value: "'unsafe-eval'", description: "Allow dynamic code evaluation (dangerous)"},
            {value: "'unsafe-hashes'", description: "Allow hashes to match inline event handlers (security risk)"},
            {value: "nonce-", description: "Allow scripts with matching nonce<br><code><script nonce='abc123'>...</script></code>"},
            {value: "sha256-", description: "Allow scripts matching hash<br><code><script integrity='sha256-abc123'>...</script></code>"}
        ]
    },
    'style-src': {
        description: 'Controls sources for CSS stylesheets. Helps prevent CSS injection attacks.',
        values: [
            ...hostExpressions,
            {value: "'unsafe-inline'", description: "Allow inline <style> elements and style attributes (security risk)"},
            {value: "'unsafe-hashes'", description: "Allow hashes to match inline styles (security risk)"},
            {value: "nonce-", description: "Allow styles with matching nonce<br><code><style nonce='def456'>...</style></code>"},
            {value: "sha256-", description: "Allow styles matching hash<br><code><link href='styles.css' integrity='sha256-def456'></code>"}
            
        ]
    },
    'img-src': {
        description: 'Valid sources for images',
        values: [
            ...hostExpressions,
            {value: "blob:", description: "Allow images from blob: URLs"}
        ]
    },
    'font-src': {
        description: 'Valid sources for fonts',
        values: [
            ...hostExpressions
        ]
    },
    'connect-src': {
        description: 'Valid targets for scripts to connect to (XHR, WebSockets, EventSource)',
        values: [
            ...hostExpressions,
            {value: "wss:", description: "Allow WebSocket connections"}
        ]
    },
    'media-src': {
        description: 'Valid sources for media (audio/video)',
        values: [
            ...hostExpressions,
        ]
    },
    'object-src': {
        description: 'Valid sources for plugins (object, embed, applet)',
        values: [
            ...hostExpressions
        ]
    },
    'prefetch-src': {
        description: 'Valid sources for prefetch or prerender',
        values: [
            ...hostExpressions
        ]
    },
    'child-src': {
        description: 'Valid sources for child frames (deprecated, prefer frame-src and worker-src)',
        values: [
            ...hostExpressions
        ]
    },
    'frame-src': {
        description: 'Valid sources for frames (iframe, embed, object)',
        values: [
            ...hostExpressions,
        ]
    },
    'frame-ancestors': {
        description: 'Specifies valid parents for embedding via iframe',
        values: [
            ...hostExpressions.filter(expr => 
                expr.value !== "data:" &&
                expr.value !== "blob:"
            )
        ]
    },
    'form-action': {
        description: 'Valid endpoints for form submissions',
        values: [
            ...hostExpressions
        ]
    },
    'upgrade-insecure-requests': {
        description: 'Upgrade HTTP to HTTPS requests'
    },
    'block-all-mixed-content': {
        description: 'Prevent loading mixed content (HTTP on HTTPS pages)'
    },
    'report-only': {
        description: 'Run in report-only mode without enforcing policies'
    },
    'report-uri': {
        description: 'Endpoint for CSP violation reports'
    },
    'report-to': {
        description: 'Reporting group for CSP violations'
    },
    'disown-opener': {
        description: 'Clean window.opener reference for external links'
    },
    'sandbox': {
        description: 'Enables sandbox for requested resources',
        values: [
            {value: "allow-forms", description: "Allow form submission"},
            {value: "allow-scripts", description: "Allow script execution"},
            {value: "allow-popups", description: "Allow popup windows"},
            {value: "allow-same-origin", description: "Allow same-origin access"},
            {value: "allow-top-navigation", description: "Allow navigation to top-level context"},
            {value: "allow-modals", description: "Allow modal dialogs"},
            {value: "allow-orientation-lock", description: "Allow screen orientation lock"},
            {value: "allow-pointer-lock", description: "Allow pointer lock API"},
            {value: "allow-presentation", description: "Allow presentation API"}
        ]
    },
    'base-uri': {
        description: 'Restricts which URLs can be used in document <base> elements. Critical for preventing base tag injection attacks.',
        values: [
            ...hostExpressions
        ]
    },
    'manifest-src': {
        description: 'Controls where web app manifests can be loaded from. Affects PWA installation.',
        values: [
            ...hostExpressions
        ]
    },
    'worker-src': {
        description: 'Valid sources for Worker, SharedWorker, ServiceWorker',
        values: [
            ...hostExpressions
        ]
    },
    'plugin-types': {
        description: 'Restrict MIME types for plugins (deprecated but still used with legacy plugins)',
        values: [
            {value: "application/pdf", description: "Allow PDF viewer plugins"},
            {value: "application/x-shockwave-flash", description: "Allow Adobe Flash content"},
            {value: "application/x-java-applet", description: "Allow Java applets"},
            {value: "application/x-silverlight", description: "Allow Microsoft Silverlight plugins"},
            {value: "application/x-mplayer2", description: "Allow Windows Media Player plugins"},
            {value: "text/html", description: "Allow HTML documents as plugins"}
        ]
    },
    'require-sri-for': {
        description: 'Require Subresource Integrity for scripts/styles',
        values: [
            {value: "script", description: "Require SRI for scripts"},
            {value: "style", description: "Require SRI for styles"},
            {value: "script style", description: "Require SRI for both"}
        ]
    },
    'trusted-types': {
        description: 'Restrict DOM XSS sinks to only accept non-spoofable, typed values',
        values: [
            {value: "'none'", description: "Block all Trusted Type policies"},
            {value: "'allow-duplicates'", description: "Allow duplicate policy names"},
            {value: "'*'", description: "Allow any policy name"},
            {value: "policyName", description: "Allow specific policy (e.g. 'default')"}
        ]
    },
    'navigate-to': {
        description: 'Restrict URLs the document can navigate to',
        values: [
            ...hostExpressions
        ]
    },
    'prefetch-src': {
        description: 'Valid sources for prefetch or prerender',
        values: [
            ...hostExpressions
        ]
    },
    'webrtc': {
        description: 'Specify WebRTC connection behavior',
        values: [
            {value: "'allow'", description: "Allow WebRTC connections"},
            {value: "'block'", description: "Block WebRTC connections"}
        ]
    }
};

// Initialize modal functionality
const modal = document.getElementById('directiveModal');
const closeBtn = document.querySelector('.close');

// Handle closing both modals
const directiveModal = document.getElementById('directiveModal');
const serverConfigModal = document.getElementById('serverConfigModal');
const closeButtons = document.querySelectorAll('.close');

closeButtons.forEach(btn => {
    btn.onclick = function() {
        if (this.closest('.modal')) {
            this.closest('.modal').style.display = 'none';
        }
    };
});

window.onclick = (event) => {
    if (event.target === directiveModal) {
        directiveModal.style.display = 'none';
    } else if (event.target === serverConfigModal) {
        serverConfigModal.style.display = 'none';
    }
};

function showDirectiveInfo(directiveName) {
    const info = directiveExplanations[directiveName];
    if (!info) return;

    document.getElementById('modalTitle').textContent = `${directiveName} Directive`;
    const body = document.getElementById('modalBody');
    body.innerHTML = `
        <p><strong>Description:</strong> ${info.description}</p>
        ${info.values ? `
        <p><strong>Common Values:</strong></p>
        <ul>
            ${info.values.map(v => `<li><code>${v.value}</code> - ${v.description}</li>`).join('')}
        </ul>
        ` : ''}
        <p>For more details, see <a href="https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy/${directiveName}" target="_blank">MDN documentation</a></p>
    `;
    modal.style.display = 'block';
}

document.addEventListener('DOMContentLoaded', () => {
    const directives = document.querySelectorAll('.directive');
    directives.forEach(initDirective);
    updateCSPPreview();
});

function initDirective(directiveElement) {
    const directiveName = directiveElement.dataset.directive;
    const sourceControls = directiveElement.querySelector('.source-controls');
    
    if (sourceControls) {
        addSourceRow(sourceControls);
        
        const addBtn = document.createElement('button');
        addBtn.className = 'add-source';
        addBtn.textContent = '+ Add Source';
        addBtn.onclick = () => addSourceRow(sourceControls);
        sourceControls.appendChild(addBtn);
    }

    // Handle all checkboxes (including sandbox options)
    const checkboxes = directiveElement.querySelectorAll('input[type="checkbox"]');
    checkboxes.forEach(checkbox => {
        checkbox.addEventListener('change', updateCSPPreview);
    });

    // Add click handler for details button
    const detailsBtn = directiveElement.querySelector('.details-btn');
    if (detailsBtn) {
        detailsBtn.onclick = () => showDirectiveInfo(directiveName);
    }
}

function addSourceRow(container) {
    const sourceRow = document.createElement('div');
    sourceRow.className = 'source-row';
    
    const input = document.createElement('input');
    input.type = 'text';
    input.placeholder = 'Enter source (e.g. \'self\' https://example.com)';
    input.addEventListener('input', updateCSPPreview);
    
    const removeBtn = document.createElement('button');
    removeBtn.className = 'remove-source';
    removeBtn.textContent = '×';
    removeBtn.onclick = () => {
        sourceRow.remove();
        updateCSPPreview();
    };
    
    sourceRow.appendChild(input);
    sourceRow.appendChild(removeBtn);
    container.insertBefore(sourceRow, container.lastElementChild);
}

function updateCSPPreview() {
    const directives = [];
    let reportOnly = false;
    
    document.querySelectorAll('.directive').forEach(directive => {
        const name = directive.dataset.directive;
        const sourceControls = directive.querySelector('.source-controls');
        const toggle = directive.querySelector('input[type="checkbox"]');
        
        // Handle special report-only case
        if (name === 'report-only') {
            reportOnly = toggle?.checked || false;
            return;
        }
        
        if (name === 'sandbox') {
            const enabledOptions = Array.from(directive.querySelectorAll('input[data-sandbox]:checked'))
                .map(input => input.dataset.sandbox);
            if (enabledOptions.length > 0) {
                directives.push(`${name} ${enabledOptions.join(' ')}`);
            }
        } else if (sourceControls) {
            const sources = Array.from(sourceControls.querySelectorAll('input'))
                .map(input => input.value.trim())
                .filter(value => value.length > 0);
            
            if (sources.length > 0) {
                directives.push(`${name} ${sources.join(' ')}`);
            }
        } else if (toggle && toggle.checked) {
            directives.push(name);
        }
    });
    
    const headerName = reportOnly 
        ? 'Content-Security-Policy-Report-Only' 
        : 'Content-Security-Policy';
        
    const cspString = `${headerName}: ${directives.join('; ')}`;
    document.getElementById('cspPreview').textContent = cspString;
}

function copyCSP() {
    const cspText = document.getElementById('cspPreview').textContent;
    navigator.clipboard.writeText(cspText)
        .then(() => {
            const btn = document.querySelectorAll('.copy-btn')[0];
            btn.textContent = 'Copied!';
            setTimeout(() => btn.textContent = 'Copy CSP Header', 2000);
        })
        .catch(err => {
            console.error('Failed to copy:', err);
            alert('Failed to copy CSP header to clipboard');
        });
}

function showServerConfig(type) {
    const cspHeader = document.getElementById('cspPreview').textContent;
    const isReportOnly = cspHeader.includes('Report-Only');
    const cspText = cspHeader.replace(/Content-Security-Policy(-Report-Only)?:\s*/, '');
    const title = document.getElementById('serverConfigTitle');
    const code = document.getElementById('serverConfigCode');
    const modal = document.getElementById('serverConfigModal');

    let config = '';
    switch(type) {
        case 'apache':
            title.textContent = 'Apache Configuration';
            config = isReportOnly 
                ? `Header set Content-Security-Policy-Report-Only "${cspText}"`
                : `Header set Content-Security-Policy "${cspText}"`;
            break;
        case 'nginx':
            title.textContent = 'Nginx Configuration'; 
            config = isReportOnly
                ? `add_header Content-Security-Policy-Report-Only "${cspText}";`
                : `add_header Content-Security-Policy "${cspText}";`;
            break;
        case 'php':
            title.textContent = 'PHP Configuration';
            config = isReportOnly
                ? `header("Content-Security-Policy-Report-Only: ${cspText}");`
                : `header("Content-Security-Policy: ${cspText}");`;
            break;
    }

    code.textContent = config;
    modal.style.display = 'block';
}

function copyServerConfig() {
    const configCode = document.getElementById('serverConfigCode').textContent;
    navigator.clipboard.writeText(configCode)
        .then(() => {
            const btns = document.querySelectorAll('.copy-btn');
            btns[btns.length - 1].textContent = 'Copied!';
            setTimeout(() => {
                btns[btns.length - 1].textContent = 'Copy Config';
            }, 2000);
        })
        .catch(err => {
            console.error('Failed to copy:', err);
            alert('Failed to copy server configuration');
        });
}
