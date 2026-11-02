(() => {
  'use strict';
  const data = JSON.parse(document.getElementById('reader-data').textContent);
  const volumes = data.volumes;
  const byId = new Map(volumes.map(volume => [volume.id, volume]));
  const main = document.getElementById('main');
  const searchDialog = document.getElementById('search-dialog');
  const searchInput = document.getElementById('global-search');
  const memory = new Map();
  const searchCache = new Map();
  let activeVolume = null;
  let activeRoute = 'overview';
  let category = 'All topics';
  let libraryQuery = '';
  let focusMode = false;
  let noteTimer;
  let scrollTimer;
  let toastTimer;
  let searchTimer;
  let observer;
  let storageWarningShown = false;

  const escape = value => String(value ?? '').replace(/[&<>"']/g, character => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[character]));
  const icon = name => `<svg class="icon" aria-hidden="true"><use href="#i-${escape(name)}"></use></svg>`;
  function notify(message) {
    clearTimeout(toastTimer);
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.classList.add('visible');
    toastTimer = setTimeout(() => toast.classList.remove('visible'), 3200);
  }
  function read(key, fallback = null) {
    if (memory.has(key)) return memory.get(key);
    try { return localStorage.getItem(key) ?? fallback; } catch { return fallback; }
  }
  function write(key, value) {
    try {
      localStorage.setItem(key, String(value));
      memory.delete(key);
      return true;
    } catch {
      memory.set(key, String(value));
      if (!storageWarningShown) {
        storageWarningShown = true;
        notify('Browser storage is unavailable. Back up your progress before closing.');
        document.querySelector('.profile div > span').textContent = 'Temporary session · export to keep';
      }
      return false;
    }
  }
  function savedIds() {
    try {
      const value = JSON.parse(read('cf_saved', '[]'));
      return new Set(Array.isArray(value) ? value.filter(id => byId.has(id)) : []);
    } catch { return new Set(); }
  }
  function isDone(id) {
    return read(`sl_bible_${id}`, read(`sl_hacker_bible_${id}`, '0')) === '1';
  }
  function completed() { return volumes.filter(volume => isDone(volume.id)).length; }
  function lastVolume() { return byId.get(read('cf_last_read')) || volumes.find(volume => !isDone(volume.id)) || volumes[0]; }
  function hasVisited(id) { return read(`cf_visited_${id}`) === '1'; }
  function currentTheme() { return read('cf_theme', 'dark') === 'light' ? 'light' : 'dark'; }
  function applyTheme() {
    const theme = currentTheme();
    document.documentElement.dataset.theme = theme;
    const toggle = document.getElementById('theme-toggle');
    toggle.innerHTML = icon(theme === 'dark' ? 'sun' : 'moon');
    toggle.setAttribute('aria-label', `Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`);
    document.querySelector('meta[name="theme-color"]').content = theme === 'dark' ? '#101413' : '#f5f7f2';
  }
  function updateShell() {
    const count = completed();
    const percentage = Math.round(count / volumes.length * 100);
    document.getElementById('journey-percent').innerHTML = `${percentage}<span>%</span>`;
    document.getElementById('journey-count').textContent = `${count} of ${volumes.length} completed`;
    document.getElementById('journey-fill').style.width = `${percentage}%`;
    document.getElementById('saved-count').textContent = savedIds().size;
    document.querySelectorAll('[data-nav]').forEach(link => {
      const selected = link.dataset.nav === activeRoute || (activeVolume?.id === 'vol-17' && link.dataset.nav === 'labs');
      link.classList.toggle('active', selected);
      if (selected) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
    });
    document.querySelectorAll('[data-complete]').forEach(button => {
      const done = isDone(button.dataset.complete);
      button.innerHTML = `${icon(done ? 'check' : 'book')} ${done ? 'Completed' : 'Mark complete'}`;
      button.setAttribute('aria-pressed', String(done));
    });
  }
  function toggleSaved(id) {
    const saved = savedIds();
    const added = !saved.has(id);
    if (added) saved.add(id); else saved.delete(id);
    write('cf_saved', JSON.stringify([...saved]));
    document.querySelectorAll(`[data-save="${id}"]`).forEach(button => {
      button.setAttribute('aria-pressed', String(added));
      button.setAttribute('aria-label', `${added ? 'Unsave' : 'Save'} ${byId.get(id).title}`);
      if (button.classList.contains('reader-save')) button.innerHTML = `${icon('bookmark')} ${added ? 'Saved' : 'Save'}`;
    });
    updateShell();
    if (activeRoute === 'saved') renderLibrary('saved');
    if (activeRoute === 'overview') {
      const count = document.getElementById('overview-saved');
      if (count) count.textContent = saved.size;
    }
    notify(added ? 'Chapter saved for later.' : 'Chapter removed from saved.');
  }
  function courseCard(volume) {
    const done = isDone(volume.id);
    const saved = savedIds().has(volume.id);
    return `<article class="course-card">
      <div class="card-top"><span class="course-icon ${volume.color}">${icon(volume.icon)}</span><span class="card-number">${String(volume.number).padStart(2, '0')} / 21</span><button class="card-bookmark" data-save="${volume.id}" aria-label="${saved ? 'Unsave' : 'Save'} ${escape(volume.title)}" aria-pressed="${saved}">${icon('bookmark')}</button></div>
      <div class="card-kicker">${escape(volume.category)}</div><h3><a href="#${volume.id}">${escape(volume.title)}</a></h3><p>${escape(volume.description)}</p>
      <div class="card-bottom"><span class="card-meta">${icon('book')}${volume.toc.filter(entry => entry.level === 1).length} chapter headings</span>${done ? `<span class="card-status">${icon('check')}Completed</span>` : hasVisited(volume.id) ? '<span class="card-status">Continue reading</span>' : icon('arrow')}</div>
    </article>`;
  }
  function heroArt() {
    return `<div class="hero-art" aria-hidden="true"><svg viewBox="0 0 370 285" fill="none">
      <circle class="art-ring" cx="190" cy="137" r="105"/><circle class="art-ring" cx="190" cy="137" r="76" stroke-dasharray="2 7"/>
      <path class="art-line" d="M95 62 190 137 292 70M190 137l22 102M95 62l117 177M292 70l-80 169"/>
      <path class="art-shield" d="m190 88 39 15v33c0 29-39 49-39 49s-39-20-39-49v-33Z"/>
      <path class="art-code" d="m178 120-12 12 12 12m24-24 12 12-12 12m-9-30-7 36"/>
      <rect class="art-panel" x="37" y="37" width="118" height="47" rx="9"/><circle class="art-accent" cx="54" cy="60" r="3"/><text class="art-text" x="66" y="58">Understand</text><text class="art-muted" x="66" y="71">THE FOUNDATIONS</text>
      <rect class="art-panel" x="244" y="53" width="108" height="47" rx="9"/><circle class="art-accent" cx="260" cy="77" r="3"/><text class="art-text" x="271" y="75">Explore</text><text class="art-muted" x="271" y="88">THE UNKNOWN</text>
      <rect class="art-panel" x="149" y="215" width="126" height="47" rx="9"/><circle class="art-accent" cx="166" cy="239" r="3"/><text class="art-text" x="178" y="237">Build &amp; defend</text><text class="art-muted" x="178" y="250">WITH CONFIDENCE</text>
      <circle class="art-accent" cx="90" cy="167" r="2"/><circle class="art-accent" cx="258" cy="166" r="2"/><circle class="art-accent" cx="192" cy="31" r="2"/>
      <text class="art-muted" x="15" y="217">KNOWLEDGE</text><path class="art-line" d="M15 225h70"/><text class="art-muted" x="295" y="213">PRACTICE</text>
    </svg></div>`;
  }
  function renderOverview() {
    const next = lastVolume();
    const returning = hasVisited(next.id);
    const date = new Intl.DateTimeFormat('en-GB', {day:'numeric', month:'short', year:'numeric'}).format(new Date());
    main.innerHTML = `<section class="page-intro"><div><p class="eyebrow">YOUR LEARNING SPACE</p><h1>A little better, every day.</h1><p>Your path from curiosity to cybersecurity confidence.</p></div><span class="date-label">${icon('clock')}${date}</span></section>
      <section class="hero" aria-labelledby="hero-title"><div class="hero-copy"><p class="eyebrow"><i></i> YOUR NEXT CHAPTER STARTS HERE</p><h2 id="hero-title">Build the skills.<br><em>Earn the confidence.</em></h2><p>One clear path. Real concepts. Deliberate practice.<br>Make your next step a meaningful one.</p><div class="hero-actions"><a href="#${next.id}" class="button button-primary">${returning ? 'Continue learning' : 'Start your journey'}${icon('arrow')}</a><a class="text-link" href="#curriculum">Explore curriculum ${icon('chevron')}</a></div></div>${heroArt()}</section>
      <section class="stats-row" aria-label="Your curriculum at a glance"><div class="stat">${icon('book')}<div><strong>12</strong><span>Core learning volumes</span></div></div><div class="stat">${icon('layers')}<div><strong>9</strong><span>Reference collections</span></div></div><div class="stat">${icon('check')}<div><strong>${completed()}<small> / 21</small></strong><span>Volumes completed</span></div></div><div class="stat">${icon('bookmark')}<div><strong id="overview-saved">${savedIds().size}</strong><span>Saved for later</span></div></div></section>
      <section aria-labelledby="foundation-heading"><div class="section-heading"><div><h2 id="foundation-heading">${returning ? 'Keep your momentum' : 'Start with a strong foundation'}</h2><p>${returning ? `Pick up ${escape(next.title)} or revisit the essentials.` : 'Understand the systems before you test their boundaries.'}</p></div><a class="text-link" href="#curriculum">View all volumes ${icon('arrow')}</a></div><div class="card-grid">${(returning ? [next, ...volumes.filter(v => v.id !== next.id).slice(0,2)] : volumes.slice(0,3)).map(courseCard).join('')}</div></section>
      <div class="bottom-grid"><section class="practice-banner"><div class="practice-visual">${icon('flask')}</div><div><p class="eyebrow">FROM KNOWING TO DOING</p><h3>Make the knowledge stick.</h3><p>40 hands-on labs to turn your reading into practical understanding.</p><a class="text-link" href="#vol-17">Explore the lab manual ${icon('arrow')}</a></div></section><section class="study-note">${icon('compass')}<div><h3>Learn at your own pace.</h3><p>A degree, a busy week, a fresh start. Your progress stays with you. Pick one concept and make it yours.</p><small>CONSISTENCY OVER INTENSITY</small></div></section></div>`;
  }
  function matchesQuery(volume, query) {
    const term = query.trim().toLowerCase();
    return !term || `${volume.part} ${volume.title} ${volume.description} ${volume.subtitle}`.toLowerCase().includes(term);
  }
  function renderLibrary(mode) {
    const saved = mode === 'saved';
    const references = mode === 'references';
    const title = saved ? 'Your next reads, kept close.' : references ? 'A reference for every question.' : 'Your path. At your pace.';
    const subtitle = saved ? 'A personal shelf of the chapters you want to come back to.' : references ? 'Nine collections to keep beside you as you learn and practise.' : 'Twelve core volumes. Nine reference collections. A whole world to understand.';
    main.innerHTML = `<section class="page-intro"><div><p class="eyebrow">${saved ? 'SAVED CHAPTERS' : references ? 'THE REFERENCE LIBRARY' : 'EXPLORE THE CURRICULUM'}</p><h1>${title}</h1><p>${subtitle}</p></div></section><div class="library-toolbar">${!saved && !references ? `<div class="filter-tabs" role="group" aria-label="Filter by topic">${['All topics','Foundations','Application security','Systems & defence','Reference'].map(label => `<button data-filter="${escape(label)}" class="${label === category ? 'active' : ''}" aria-pressed="${label === category}">${escape(label)}</button>`).join('')}</div>` : ''}<label class="library-search">${icon('search')}<span class="sr-only">Filter volumes by title or topic</span><input id="library-query" type="search" placeholder="Find a volume..." value="${escape(libraryQuery)}"></label></div><p class="result-count" id="result-count" aria-live="polite"></p><div id="library-results"></div>`;
    updateLibraryResults(mode);
  }
  function updateLibraryResults(mode = activeRoute) {
    const saved = savedIds();
    const selected = volumes.filter(v => (mode !== 'saved' || saved.has(v.id)) && (mode !== 'references' || v.category === 'Reference') && (mode !== 'curriculum' || category === 'All topics' || v.category === category) && matchesQuery(v, libraryQuery));
    document.getElementById('result-count').textContent = `${selected.length} ${selected.length === 1 ? 'volume' : 'volumes'}${libraryQuery.trim() ? ` matching “${libraryQuery.trim()}”` : ' to explore'}`;
    document.getElementById('library-results').innerHTML = selected.length ? `<div class="card-grid">${selected.map(courseCard).join('')}</div>` : `<div class="empty-state">${icon(mode === 'saved' ? 'bookmark' : 'search')}<h2>${mode === 'saved' && !saved.size ? 'Make room for your next discovery.' : 'No matching volumes yet.'}</h2><p>${mode === 'saved' && !saved.size ? 'Use the bookmark on any volume to keep it on your personal shelf.' : 'Try another topic or clear your filters. You can also search inside every chapter with Ctrl K.'}</p><a class="button button-secondary" href="#curriculum">Explore the curriculum ${icon('arrow')}</a></div>`;
  }
  function enhanceArticle(article) {
    article.querySelectorAll('pre').forEach(pre => {
      const code = pre.querySelector('code');
      if (!code) return;
      const language = [...code.classList].find(name => name.startsWith('language-'))?.slice(9) || 'text';
      const block = document.createElement('div');
      block.className = 'code-block';
      const heading = document.createElement('div');
      heading.className = 'code-heading';
      heading.innerHTML = `<span>${escape(language.toUpperCase())}</span><button class="copy-button" data-copy aria-label="Copy ${escape(language)} example">${icon('copy')}Copy</button>`;
      pre.replaceWith(block);
      block.append(heading, pre);
      pre.tabIndex = 0;
      pre.setAttribute('aria-label', `${language} example, scroll horizontally if needed`);
    });
    article.querySelectorAll('table').forEach(table => {
      const wrap = document.createElement('div');
      wrap.className = 'table-wrap';
      wrap.tabIndex = 0;
      wrap.setAttribute('role', 'region');
      wrap.setAttribute('aria-label', 'Reference table, scroll horizontally if needed');
      table.replaceWith(wrap);
      wrap.append(table);
    });
    article.querySelectorAll('a').forEach(link => {
      const href = link.getAttribute('href') || '';
      if (/^(javascript|data|vbscript):/i.test(href.trim())) link.removeAttribute('href');
      else if (/^https?:\/\//i.test(href)) { link.target = '_blank'; link.rel = 'noopener noreferrer'; }
      else if (href.startsWith('#')) {
        const target = href.slice(1);
        const matching = activeVolume.toc.find(entry => entry.id === target || entry.id.endsWith(`-${target}`));
        if (matching) link.href = `#${activeVolume.id}/${matching.id}`;
      }
    });
  }
  function renderReader(volume, targetHeading) {
    activeVolume = volume;
    write('cf_last_read', volume.id);
    write(`cf_visited_${volume.id}`, '1');
    const saved = savedIds().has(volume.id);
    const next = volumes[volume.number];
    main.innerHTML = `<div class="reader-toolbar"><a class="text-link" href="#curriculum">${icon('arrow')}Back to curriculum</a><div class="reader-actions"><button class="font-button" data-font="-1" aria-label="Decrease reading text size">A−</button><button class="font-button" data-font="1" aria-label="Increase reading text size">A+</button><button class="icon-button" id="focus-toggle" aria-pressed="${focusMode}" aria-label="${focusMode ? 'Leave' : 'Enter'} focus mode">${icon('focus')}</button><button class="button button-secondary reader-save" data-save="${volume.id}" aria-pressed="${saved}" aria-label="${saved ? 'Unsave' : 'Save'} ${escape(volume.title)}">${icon('bookmark')}${saved ? 'Saved' : 'Save'}</button><button class="button button-primary" data-complete="${volume.id}" aria-pressed="${isDone(volume.id)}"></button></div><div class="reading-progress" aria-hidden="true"><span id="reading-fill"></span></div></div>
      <header class="reader-header"><p class="eyebrow">${escape(volume.part)} <span> / </span> ${escape(volume.category)}</p><h1>${escape(volume.title)}</h1><p>${escape(volume.description)}</p><div class="reader-meta"><span>${icon('book')}${volume.toc.filter(item => item.level === 1).length} chapter headings</span><span>${icon('clock')}About ${volume.readMinutes} min to read · take it in sessions</span><span>${icon('shield')}Learn. Practise with permission.</span></div></header>
      <div class="reader-grid"><div><article class="article" id="chapter-content" aria-label="${escape(volume.title)}"></article><section class="reader-end"><p class="eyebrow">PAUSE. REFLECT. MAKE IT YOURS.</p><h3>What can you explain now?</h3><p>Put one idea into your own words, then try it in an authorized practice environment. Mark this volume complete when you are ready.</p><div class="reader-end-actions"><button class="button button-primary" data-complete="${volume.id}" aria-pressed="${isDone(volume.id)}"></button>${next ? `<a class="text-link" href="#${next.id}">Next: ${escape(next.title)} ${icon('arrow')}</a>` : '<a class="text-link" href="#overview">Back to your overview →</a>'}</div></section></div>
      <aside class="reader-aside" aria-label="Chapter tools"><h2 class="toc-title">IN THIS VOLUME</h2><nav class="toc" aria-label="On this page">${volume.toc.map(entry => `<a href="#${volume.id}/${entry.id}" data-heading="${entry.id}" class="${entry.level > 1 ? 'toc-child' : ''}">${escape(entry.title)}</a>`).join('')}</nav><details class="note-panel" open><summary>${icon('note')}Your chapter notes</summary><label class="sr-only" for="chapter-note">Personal notes for ${escape(volume.title)}</label><textarea id="chapter-note" placeholder="One idea. One question. One thing to try." spellcheck="true"></textarea><small id="note-status">Personal notes · saved on this device</small></details></aside></div>`;
    const article = document.getElementById('chapter-content');
    article.append(document.getElementById(`content-${volume.id}`).content.cloneNode(true));
    enhanceArticle(article);
    document.getElementById('chapter-note').value = read(`cf_note_${volume.id}`, '');
    document.documentElement.style.setProperty('--reader-size', `${Math.max(14, Math.min(22, Number(read('cf_font_size', '17')) || 17))}px`);
    if ('IntersectionObserver' in window) {
      observer = new IntersectionObserver(entries => {
        const visible = entries.filter(entry => entry.isIntersecting);
        if (!visible.length) return;
        const target = visible[0].target.id;
        document.querySelectorAll('.toc a').forEach(link => link.classList.toggle('current', link.dataset.heading === target));
      }, {rootMargin:'-150px 0px -65% 0px'});
      article.querySelectorAll('h1[id], h2[id]').forEach(heading => observer.observe(heading));
    }
    requestAnimationFrame(() => {
      if (activeVolume?.id !== volume.id) return;
      if (targetHeading && document.getElementById(targetHeading)) document.getElementById(targetHeading).scrollIntoView({behavior:'instant',block:'start'});
      else window.scrollTo({top:Math.max(0, Number(read(`cf_scroll_${volume.id}`, '0')) || 0),behavior:'instant'});
      updateReadingProgress();
    });
  }
  function persistNote() {
    clearTimeout(noteTimer);
    const field = document.getElementById('chapter-note');
    if (!activeVolume || !field) return;
    const saved = write(`cf_note_${activeVolume.id}`, field.value);
    const status = document.getElementById('note-status');
    if (status) status.textContent = saved ? 'Saved on this device' : 'Saved for this session · export to keep';
  }
  function updateReadingProgress() {
    const article = document.getElementById('chapter-content');
    if (!activeVolume || !article) return;
    const start = article.getBoundingClientRect().top + window.scrollY;
    const distance = Math.max(1, article.offsetHeight - window.innerHeight + 150);
    const percentage = Math.max(0, Math.min(100, (window.scrollY - start + 150) / distance * 100));
    document.getElementById('reading-fill').style.width = `${percentage}%`;
  }
  function persistScroll() {
    clearTimeout(scrollTimer);
    if (activeVolume) write(`cf_scroll_${activeVolume.id}`, String(Math.round(window.scrollY)));
  }
  function setMenu(open) {
    const sidebar = document.getElementById('sidebar');
    sidebar.classList.toggle('open', open);
    document.getElementById('nav-backdrop').hidden = !open;
    document.getElementById('open-menu').setAttribute('aria-expanded', String(open));
    if (open) document.getElementById('close-menu').focus();
  }
  function route() {
    let hash;
    try { hash = decodeURIComponent(location.hash.slice(1)); } catch { hash = 'overview'; }
    const [id, heading] = hash.split('/');
    if (activeVolume && id === activeVolume.id) {
      if (heading && document.getElementById(heading)) document.getElementById(heading).scrollIntoView({behavior:'instant',block:'start'});
      return;
    }
    persistNote(); persistScroll();
    if (observer) observer.disconnect();
    activeVolume = null;
    setMenu(false);
    if (byId.has(id)) {
      activeRoute = byId.get(id).category === 'Reference' ? 'references' : 'curriculum';
      document.getElementById('current-page').textContent = byId.get(id).title;
      renderReader(byId.get(id), heading);
      document.title = `${byId.get(id).title} — CyberForge`;
    } else {
      focusMode = false;
      document.body.classList.remove('focus-mode');
      activeRoute = ['curriculum','references','saved'].includes(id) ? id : 'overview';
      document.getElementById('current-page').textContent = ({overview:'Overview',curriculum:'Curriculum',references:'Reference library',saved:'Saved chapters'})[activeRoute];
      document.title = `${document.getElementById('current-page').textContent} — CyberForge`;
      if (activeRoute === 'overview') renderOverview(); else renderLibrary(activeRoute);
      window.scrollTo({top:0,behavior:'instant'});
      if (id && !['overview','curriculum','references','saved'].includes(id)) notify('That chapter could not be found. Explore your curriculum below.');
    }
    updateShell();
    main.focus({preventScroll:true});
  }
  function getSearchText(volume) {
    if (!searchCache.has(volume.id)) {
      const text = document.getElementById(`content-${volume.id}`).content.textContent.replace(/\s+/g, ' ').trim();
      searchCache.set(volume.id, {text,lower:text.toLowerCase()});
    }
    return searchCache.get(volume.id);
  }
  function highlighted(text, query) {
    const index = text.toLowerCase().indexOf(query.toLowerCase());
    if (index < 0) return escape(text);
    return `${escape(text.slice(0,index))}<mark>${escape(text.slice(index,index+query.length))}</mark>${escape(text.slice(index+query.length))}`;
  }
  function renderSearch() {
    const query = searchInput.value.trim();
    const term = query.toLowerCase();
    const resultArea = document.getElementById('search-results');
    if (!term) {
      resultArea.innerHTML = '<p class="search-empty">A concept, a command, a question. Where will your curiosity take you?</p>' + volumes.slice(0,4).map(volume => `<a class="search-result" href="#${volume.id}" data-search-result><small>${escape(volume.part)}</small><strong>${escape(volume.title)}</strong><p>${escape(volume.description)}</p></a>`).join('');
      return;
    }
    const results = [];
    for (const volume of volumes) {
      const heading = volume.toc.find(entry => entry.title.toLowerCase().includes(term));
      const titleMatch = `${volume.title} ${volume.subtitle} ${volume.part}`.toLowerCase().includes(term);
      const content = getSearchText(volume);
      const position = content.lower.indexOf(term);
      if (!titleMatch && !heading && position < 0) continue;
      const snippet = position >= 0 ? `${position > 75 ? '…' : ''}${content.text.slice(Math.max(0,position-75),position+170)}…` : volume.description;
      results.push({volume,heading,snippet,rank:titleMatch ? 0 : heading ? 1 : 2});
    }
    results.sort((a,b) => a.rank-b.rank || a.volume.number-b.volume.number);
    resultArea.innerHTML = results.length ? `<p class="result-count" style="padding:0 14px">Found in ${results.length} ${results.length === 1 ? 'volume' : 'volumes'}</p>` + results.map(({volume,heading,snippet}) => `<a class="search-result" href="#${volume.id}${heading ? `/${heading.id}` : ''}" data-search-result><small>${escape(volume.part)} · ${escape(volume.category)}</small><strong>${highlighted(heading?.title || volume.title,query)}</strong><p>${highlighted(snippet,query)}</p></a>`).join('') : '<p class="search-empty">No matches. Try a broader concept, such as “Linux”, “authentication”, or “logging”.</p>';
  }
  function openSearch() {
    if (!searchDialog.open) searchDialog.showModal();
    renderSearch();
    searchInput.focus();
  }
  async function copyCode(button) {
    const text = button.closest('.code-block').querySelector('code').textContent;
    try {
      if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(text);
      button.innerHTML = `${icon('check')}Copied`;
      setTimeout(() => { if (button.isConnected) button.innerHTML = `${icon('copy')}Copy`; }, 1800);
    } catch {
      const range = document.createRange();
      range.selectNodeContents(button.closest('.code-block').querySelector('code'));
      const selection = window.getSelection();
      selection.removeAllRanges(); selection.addRange(range);
      notify('Code selected. Press Ctrl+C or Command+C to copy.');
    }
  }
  function exportProgress() {
    persistNote(); persistScroll();
    const backup = {format:'cyberforge-reader',version:1,exportedAt:new Date().toISOString(),theme:currentTheme(),fontSize:read('cf_font_size','17'),lastRead:read('cf_last_read'),saved:[...savedIds()],volumes:volumes.map(volume => ({id:volume.id,title:volume.title,completed:isDone(volume.id),visited:hasVisited(volume.id),note:read(`cf_note_${volume.id}`,''),scroll:Number(read(`cf_scroll_${volume.id}`,'0')) || 0}))};
    const url = URL.createObjectURL(new Blob([JSON.stringify(backup,null,2)],{type:'application/json'}));
    const link = document.createElement('a');
    link.href = url; link.download = `cyberforge-progress-${new Date().toISOString().slice(0,10)}.json`;
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    notify('Progress and notes exported to your downloads.');
  }

  document.addEventListener('click', event => {
    const save = event.target.closest('[data-save]');
    if (save) { toggleSaved(save.dataset.save); return; }
    const complete = event.target.closest('[data-complete]');
    if (complete) {
      const id = complete.dataset.complete;
      const done = !isDone(id);
      write(`sl_bible_${id}`, done ? '1' : '0');
      write(`sl_hacker_bible_${id}`, done ? '1' : '0');
      updateShell();
      notify(done ? 'Volume completed. That is one more step forward.' : 'Volume marked as in progress.');
      return;
    }
    const filter = event.target.closest('[data-filter]');
    if (filter) {
      category = filter.dataset.filter;
      document.querySelectorAll('[data-filter]').forEach(button => { const selected = button === filter; button.classList.toggle('active',selected); button.setAttribute('aria-pressed',String(selected)); });
      updateLibraryResults(); return;
    }
    const font = event.target.closest('[data-font]');
    if (font) {
      const size = Math.max(14,Math.min(22,(Number(read('cf_font_size','17')) || 17)+Number(font.dataset.font)));
      write('cf_font_size',size);
      document.documentElement.style.setProperty('--reader-size',`${size}px`);
      notify(`Reading text: ${size}px`); return;
    }
    const copy = event.target.closest('[data-copy]');
    if (copy) { copyCode(copy); return; }
    if (event.target.closest('[data-search-result]')) searchDialog.close();
    const focus = event.target.closest('#focus-toggle');
    if (focus) {
      focusMode = !focusMode;
      document.body.classList.toggle('focus-mode',focusMode);
      focus.setAttribute('aria-pressed',String(focusMode));
      focus.setAttribute('aria-label',`${focusMode ? 'Leave' : 'Enter'} focus mode`);
    }
  });
  document.addEventListener('input', event => {
    if (event.target.id === 'library-query') { libraryQuery = event.target.value; updateLibraryResults(); }
    if (event.target.id === 'chapter-note') {
      document.getElementById('note-status').textContent = 'Saving…';
      clearTimeout(noteTimer); noteTimer = setTimeout(persistNote,350);
    }
  });
  searchInput.addEventListener('input',() => {clearTimeout(searchTimer);searchTimer=setTimeout(renderSearch,130);});
  document.getElementById('open-search').addEventListener('click',openSearch);
  document.getElementById('close-search').addEventListener('click',() => searchDialog.close());
  searchDialog.addEventListener('click',event => { if (event.target === searchDialog) { const rect=searchDialog.getBoundingClientRect(); if(event.clientX<rect.left || event.clientX>rect.right || event.clientY<rect.top || event.clientY>rect.bottom) searchDialog.close(); } });
  document.getElementById('theme-toggle').addEventListener('click',() => {write('cf_theme',currentTheme()==='dark'?'light':'dark');applyTheme();});
  document.getElementById('export-progress').addEventListener('click',exportProgress);
  document.getElementById('open-menu').addEventListener('click',() => setMenu(true));
  document.getElementById('close-menu').addEventListener('click',() => {setMenu(false);document.getElementById('open-menu').focus();});
  document.getElementById('nav-backdrop').addEventListener('click',() => setMenu(false));
  document.addEventListener('keydown',event => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {event.preventDefault();openSearch();}
    if (event.key === 'Escape') {setMenu(false);if(searchDialog.open)searchDialog.close();}
    if (document.getElementById('sidebar').classList.contains('open') && event.key === 'Tab') {
      const controls = [...document.getElementById('sidebar').querySelectorAll('a,button')].filter(element => element.getClientRects().length);
      const first=controls[0],last=controls[controls.length-1];
      if(event.shiftKey && document.activeElement===first){event.preventDefault();last.focus();}
      else if(!event.shiftKey && document.activeElement===last){event.preventDefault();first.focus();}
    }
  });
  window.addEventListener('hashchange',route);
  window.addEventListener('scroll',() => {updateReadingProgress();clearTimeout(scrollTimer);scrollTimer=setTimeout(persistScroll,200);},{passive:true});
  window.addEventListener('pagehide',() => {persistNote();persistScroll();});
  window.addEventListener('storage',() => {applyTheme();updateShell();if(!activeVolume){if(activeRoute==='overview')renderOverview();else updateLibraryResults();}});
  window.addEventListener('resize',() => {if(window.innerWidth>1000)setMenu(false);});
  applyTheme(); route();
})();
