
(function () {
    'use strict';

    /* ---------- Nav: scroll state ---------- */
    var nav = document.getElementById('nav');
    var onScroll = function () {
        nav.classList.toggle('scrolled', window.scrollY > 12);
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();

    /* ---------- Nav: mobile toggle ---------- */
    var toggle = document.getElementById('navToggle');
    var links = document.getElementById('navLinks');
    toggle.addEventListener('click', function () {
        var open = links.classList.toggle('open');
        toggle.setAttribute('aria-expanded', String(open));
    });
    links.addEventListener('click', function (e) {
        if (e.target.tagName === 'A') {
            links.classList.remove('open');
            toggle.setAttribute('aria-expanded', 'false');
        }
    });

    /* ---------- Terminal: staggered line reveal ---------- */
    var term = document.getElementById('terminal');
    if (term) {
        var lines = term.querySelectorAll('.ln');
        lines.forEach(function (ln, i) {
            ln.style.animationDelay = (i * 90) + 'ms';
        });
    }

    /* ---------- Flow diagram: cycling highlight ---------- */
    var flowNodes = Array.prototype.slice.call(document.querySelectorAll('[data-flow]'));
    if (flowNodes.length && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
        var idx = 0;
        setInterval(function () {
            flowNodes.forEach(function (n) { n.classList.remove('hot'); });
            flowNodes[idx % flowNodes.length].classList.add('hot');
            idx++;
        }, 900);
    }

    /* ---------- Scroll reveal ---------- */
    var revealEls = document.querySelectorAll('.rv');
    if ('IntersectionObserver' in window) {
        var io = new IntersectionObserver(function (entries) {
            entries.forEach(function (entry) {
                if (entry.isIntersecting) {
                    entry.target.classList.add('in');
                    io.unobserve(entry.target);
                }
            });
        }, { threshold: 0.12, rootMargin: '0px 0px -8% 0px' });

        revealEls.forEach(function (el, i) {
            el.style.transitionDelay = ((i % 4) * 70) + 'ms';
            io.observe(el);
        });
    } else {
        revealEls.forEach(function (el) { el.classList.add('in'); });
    }

    /* ---------- Copy to clipboard ---------- */
    document.querySelectorAll('.cp').forEach(function (btn) {
        btn.addEventListener('click', function () {
            var target = document.querySelector(btn.getAttribute('data-copy'));
            if (!target) return;
            var text = target.innerText;
            var done = function () {
                var old = btn.textContent;
                btn.textContent = 'COPIADO ✓';
                setTimeout(function () { btn.textContent = old; }, 1600);
            };
            if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(text).then(done).catch(function () { });
            } else {
                var ta = document.createElement('textarea');
                ta.value = text;
                ta.style.position = 'fixed';
                ta.style.opacity = '0';
                document.body.appendChild(ta);
                ta.select();
                try { document.execCommand('copy'); done(); } catch (e) { }
                document.body.removeChild(ta);
            }
        });
    });
})();
