# CyberForge Academy

## English master curriculum, learning content, and website specification

**Edition:** 1.0 · **Prepared:** 2 November 2026 · **Audience:** a university student in Sri Lanka starting from zero · **Language:** English

**Document status:** Content preparation before website implementation. This document is the proposed source of truth for the learning website. It contains the curriculum, compact teaching lessons, practical assignments, assessment answers, projects, reference material, and product requirements. The website has not been implemented or published.

**Format note:** This is a Markdown (`.md`) document. An `.md5` file normally contains a checksum rather than readable course content.

> Build the knowledge to understand systems, find weaknesses with permission, explain their impact, repair them, and help other people stay secure.

The ambition is to become a respected ethical security professional in Sri Lanka with skills that also stand up internationally. Reputation comes from useful research, reliable engineering, careful reporting, and trusted work over time. Finishing a website, collecting badges, or obtaining a certificate cannot guarantee a national ranking, a job, or expertise in every security field.

This edition is a complete first curriculum and content specification, not an exhaustive textbook on every vulnerability. Its 144 compact lessons teach the core ideas; the 48 practical briefs turn them into evidence; the advanced subjects identify where sustained specialist study is required. External lab platforms remain necessary for some realistic environments. Their courses are linked, not copied or silently represented as content hosted here.

## Contents

1. [Learning promise and starting point](#learning-promise-and-starting-point)
2. [Study system and degree-friendly schedule](#study-system-and-degree-friendly-schedule)
3. [Roadmap and prerequisites](#roadmap-and-prerequisites)
4. [Lab environments and working rules](#lab-environments-and-working-rules)
5. [Stage A — Foundations](#stage-a--foundations)
6. [Stage B — Programming and systems](#stage-b--programming-and-systems)
7. [Stage C — Web and application security](#stage-c--web-and-application-security)
8. [Stage D — Professional penetration testing](#stage-d--professional-penetration-testing)
9. [Stage E — Defence, investigation, and response](#stage-e--defence-investigation-and-response)
10. [Stage F — Cloud, software delivery, mobile, and AI](#stage-f--cloud-software-delivery-mobile-and-ai)
11. [Stage G — Advanced security and research](#stage-g--advanced-security-and-research)
12. [Stage H — Portfolio and professional growth](#stage-h--portfolio-and-professional-growth)
13. [First 30 days](#first-30-days)
14. [Practical workbooks and synthetic evidence](#practical-workbooks-and-synthetic-evidence)
15. [Projects, assessments, and graduation](#projects-assessments-and-graduation)
16. [Reference library and tool guide](#reference-library-and-tool-guide)
17. [Glossary and revision cards](#glossary-and-revision-cards)
18. [Sri Lankan professional pathway](#sri-lankan-professional-pathway)
19. [Website experience and page content](#website-experience-and-page-content)
20. [Content model and implementation requirements](#content-model-and-implementation-requirements)
21. [Release acceptance checklist](#release-acceptance-checklist)

## Learning promise and starting point

### What the learner should eventually be able to do

- Explain how an operating system, network, browser, application, identity service, and database cooperate.
- Write small programs, read unfamiliar code, debug failures, and understand how mistakes create security weaknesses.
- Set up an isolated practice environment and work within a written testing scope.
- Investigate web, API, host, identity, and cloud security controls using repeatable methods.
- Separate a scanner's suspicion from a verified vulnerability and a verified vulnerability from a proven business impact.
- Analyse logs and network captures, reconstruct incidents, and propose proportionate containment and recovery.
- Write a clear technical report and explain the same finding to a manager or developer.
- Implement and retest a fix, including normal user behaviour and relevant negative cases.
- Develop depth in one specialization while maintaining a useful understanding of adjacent disciplines.
- Build a portfolio with reproducible, permitted, original work and communicate uncertainty honestly.

### Assumptions

The learner has basic computer access but no prior security knowledge. The default plan uses approximately eight hours per week alongside a degree. Most reading and foundational practice should be possible without paid subscriptions. Hardware, internet access, electricity, some hosted labs, cloud usage, and optional examinations may still cost money.

Start with the operating system already available. Kali Linux is a collection of tools, not a prerequisite or a measure of skill. A normal Linux environment, Windows, or macOS plus a browser can support early study. Choose tools only when a lesson requires them.

### Starting diagnostic

Answer these without looking anything up. This is a placement exercise, not a test of intelligence.

| Prompt | Evidence of understanding | If unfamiliar |
| --- | --- | --- |
| Explain a file, directory, process, and user account. | Distinguishes stored data from running activity and identity. | Begin M02–M03. |
| Describe what happens when you visit a website. | Mentions name resolution, connection, request, response, and rendering. | Complete M04–M05. |
| Explain authentication and authorization. | Proving identity differs from permission to act. | Focus on M01 and M12. |
| Read a short loop that counts log entries. | Can follow variables, conditions, and iteration. | Complete M07–M09. |
| Describe a database query and a transaction. | Separates retrieval from an atomic group of changes. | Complete M10. |
| Decide whether a discovered public website may be tested. | Requires explicit authorization or a clearly applicable testing policy. | Complete M01 before any active testing. |
| Explain what evidence would support a vulnerability report. | Includes context, reproduction, observed result, impact, and limitations. | Study M06 and M24. |
| Describe how you would restore a broken lab. | Has a clean baseline, saved work, and a tested recovery method. | Complete M02. |

Familiarity permits a challenge assessment; it does not automatically mark a module complete. Everyone completes M01 and the environment isolation check.

## Study system and degree-friendly schedule

### The weekly learning loop

1. **Recall:** spend ten minutes explaining the previous topic without notes.
2. **Learn:** read one lesson and draw a model of the system it describes.
3. **Predict:** write what you expect to happen before running an experiment.
4. **Practise:** perform the exercise and record the actual result.
5. **Explain:** describe the root cause, useful evidence, and a competing explanation.
6. **Repair:** identify or apply a fix, then check normal and adverse cases.
7. **Review:** revisit weak concepts after roughly one, three, seven, and twenty-one days.

These review intervals are a starting routine, not a scientifically exact schedule for every learner. Adjust them when recall is consistently too easy or too difficult.

### Suggested eight-hour week

| Day | Session | Time |
| --- | --- | --- |
| Monday | Concepts and a diagram | 60 minutes |
| Tuesday | Programming or command-line practice | 60 minutes |
| Wednesday | Quiz, recall, and correction | 45 minutes |
| Thursday | Guided practical work | 75 minutes |
| Friday | Degree work or rest | No required session |
| Saturday | Longer lab and evidence collection | 150 minutes |
| Sunday | Report, revision, and planning | 90 minutes |
| **Total** | | **480 minutes** |

During examinations, use maintenance mode: two thirty-minute revision sessions and one sixty-minute practical or writing session per week. Freeze optional challenges and preserve sleep and degree deadlines. A missed day never deletes earned progress.

### Workload and honest time estimates

| Stage | Modules | Planned learning and practice hours |
| --- | --- | --- |
| A | M01–M06 | 70 |
| B | M07–M12 | 100 |
| C | M13–M18 | 130 |
| D | M19–M24 | 110 |
| E | M25–M30 | 110 |
| F | M31–M36 | 110 |
| G | M37–M42 | 120 |
| H | M43–M48 | 110 |
| **Total** | **48 modules** | **860 hours** |

The module budgets include their lessons, practical work, reflection, and module questions. The eight stage projects consolidate that work; they should reuse it instead of silently adding another full curriculum. Extensive repetition, optional courses, exam preparation, and independent research can add substantial time.

At eight hours per week, 860 hours is approximately 108 active study weeks. Allowing for examinations and breaks, plan around 2–3 years for this broad programme. At five hours per week, allow roughly 3–4 years. At twelve hours per week, the active-study minimum is around 72 weeks, with additional calendar time for breaks and remediation. These are planning estimates, not promises of professional mastery.

### How the degree supports the programme

| Degree subject | Security connection | Reusable portfolio output |
| --- | --- | --- |
| Programming and software engineering | Validation, state, error handling, code review | Small application with a documented security fix |
| Computer networks | Protocol behaviour, routing, segmentation, monitoring | Annotated network diagram and packet investigation |
| Operating systems | Processes, privileges, memory, isolation | Host hardening and permission analysis |
| Databases | Queries, transactions, access control, backups | Parameterized data access and authorization tests |
| Mathematics and statistics | Probability, base rates, measurement, cryptographic reasoning | Detection evaluation with false-positive analysis |
| Distributed systems | Races, retries, consistency, identity boundaries | Idempotent transaction design and concurrency tests |
| Research methods | Hypotheses, evidence, reproducibility, limitations | Small independently reproducible security study |
| Professional practice | Ethics, communication, law, teamwork | Scoped report, disclosure draft, and presentation |

## Roadmap and prerequisites

### Stages and gates

| Stage | Theme | Entry requirement | Exit evidence |
| --- | --- | --- | --- |
| A | Foundations | None | Isolated lab plan, system diagram, first evidence notebook |
| B | Programming and systems | A practical gate | A useful script, code explanation, identity and database model |
| C | Web and application security | B; especially HTTP, SQL, identity | Reproducible application findings and fixes |
| D | Professional penetration testing | C; host basics from B | Scoped assessment and retest report |
| E | Defence and investigation | A–B; C–D recommended | Incident timeline, detection rationale, response decisions |
| F | Modern platforms | B–C; E logging concepts | Platform threat model and verified control improvements |
| G | Advanced security and research | C–F relevant modules | Bounded research with clear limitations and reproducible evidence |
| H | Portfolio and professional growth | All required earlier gates | Two capstones, portfolio, and defensible specialization plan |

The default route is sequential. Learners may preview any lesson. A prerequisite affects readiness labels and suggested order; it should not hide reading material. M25 can begin after M06 and M11 for a learner exploring a defensive role, and M31 can begin after M12 and M15 for cloud interest.

### Module anatomy

Every module below contains three short lessons, a practical brief, a completion standard, two questions with answer explanations, and reference IDs. Lesson IDs use `M01-L1` through `M48-L3`. Practical IDs use `LAB-01` through `LAB-48`. Question IDs use `M01-Q1` and `M01-Q2`, continuing consistently through M48.

Each practical brief is an assignment specification. Some are fully executable with the synthetic workbooks in this document; others require the learner to select and prepare the stated lab or follow the linked provider's setup. They are not claimed to be prebuilt, running labs inside a website that does not yet exist.

## Lab environments and working rules

### Four modes of practice

| Mode | Use | What it requires |
| --- | --- | --- |
| PAPER | Diagrams, code review, scope decisions, synthetic log analysis | This document and a text editor |
| BROWSER | Provider-operated educational challenges | A supported browser, an account if required, and that provider's rules |
| LOCAL | Personally controlled files, applications, or isolated machines | Suitable hardware, a reset procedure, and explicit network isolation |
| CLOUD | A disposable account/project owned or authorized for training | Provider rules, narrow permissions, cost controls, and verified cleanup |

All data in the built-in exercises is synthetic. `example.test` and its subdomains are documentation examples; they are not a hosted lab. `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24` are documentation address ranges, not addresses to scan. `127.0.0.1` means the current machine; `0.0.0.0` is not an equivalent safe listening address.

### Hardware paths

- **Browser-first:** suitable when the computer cannot run virtual machines. Use provider labs, reading, diagrams, local text processing, and synthetic datasets. Do not promise that a particular provider's full catalogue is free.
- **Light local practice:** an approximately 8 GB RAM machine can often support modest scripting and one small Linux guest, depending on host workload and allocation. Close unnecessary applications and measure resource use.
- **Multi-machine practice:** 16 GB RAM or more and sufficient SSD space make small Linux/Windows environments more practical. Enterprise identity labs may need significantly more. Licensing and evaluation periods must be checked with the vendor.

These are rough planning guides. The chosen guest images and host operating system determine actual requirements. Do not install several large security distributions before learning the basics.

### Environment setup procedure

1. Back up important personal and degree work. Keep recovery material separate from the lab.
2. Obtain software from the maintainer's official distribution channel. Verify signatures or published checksums where available; prefer a modern cryptographic checksum for integrity verification.
3. Create a dedicated lab workspace and use unique dummy accounts. Never reuse banking, university, or personal passwords.
4. For vulnerable guests, prefer a virtual **internal network** that cannot reach the host or wider network. Use **host-only networking** only when host-to-guest access is required and understand that it exposes the host to the guest. Neither option should be bridged to university or public networks.
5. Treat NAT as a way to provide outbound connectivity, not as full containment. If updates require temporary access, shut down vulnerable services first, update, remove that access, and recheck isolation.
6. Disable shared folders, clipboard synchronization, and unnecessary guest integration for untrusted samples. A container is not a strong boundary for running unknown malware.
7. Take a clean snapshot where supported and test a restore. A snapshot helps reset a lab; it is not a replacement for backups of important work.
8. Record the actual allowed addresses, hostnames, accounts, tool versions, and time window in the scope sheet. Confirm them before generating traffic.
9. Keep vulnerable applications local or within the isolated network. Do not expose them through router forwarding, public tunnels, or a public cloud endpoint.
10. After the exercise, stop services, restore or remove disposable resources, and verify that nothing remains reachable or billable unexpectedly.

### Permission and evidence

Permission must come from someone authorized to grant it. Owning an account on a service does not mean owning the service. A university email address, a visible login page, or a friendly conversation is not a testing scope. A bounty programme's published policy may authorize specific activity under specified conditions; read those conditions before acting.

Record the minimum evidence required. Prefer dummy records and redact session tokens, passwords, personal information, and unrelated data. Stop and contact the designated owner when an exercise reaches an unexpected system, reveals real sensitive information, or causes instability. Report limits as limits rather than trying to obtain more access merely to make a screenshot more dramatic.

For every practical, record: objective, permission/scope, environment/version, hypothesis, method, expected result, observed result, evidence, interpretation, fix, retest, and cleanup. The templates and sample evidence appear later in this document.

## Stage A — Foundations

**Budget:** 70 hours. **Stage outcome:** understand the systems being tested and work safely enough to practise independently.

### M01 — Ethical practice, scope, and security principles

**Budget:** 8 hours · **Prerequisites:** none · **Practical:** LAB-01 · **Mode:** PAPER

**M01-L1 — What security protects.** Confidentiality concerns who can read information; integrity concerns whether information and actions are trustworthy; availability concerns whether a service can be used when needed. A leaked student record is a confidentiality failure. An unauthorized grade change is an integrity failure. A broken registration system can be an availability failure without any attacker. Security work begins by identifying whose interests the system serves and which failures matter.

**M01-L2 — Identity is not permission.** Authentication checks an identity claim. Authorization decides whether that identity may perform an action on a resource. An authenticated student should not automatically be allowed to edit another student's profile. Ethical hacking examines these boundaries under authorization. A testing scope states permitted systems, methods, accounts, dates, data handling, contacts, and stop conditions. Good intentions do not replace that agreement.

**M01-L3 — Think in controls and evidence.** A threat is a possible source of harm, a vulnerability is a weakness, and risk concerns the likelihood and consequences of harm in context. Controls can prevent, detect, or help recover from a failure. A tool output is an observation, not automatically a confirmed finding. The professional task is to connect observations to an explainable cause and a proportionate improvement.

**LAB-01 — Write your first rules of engagement.** Use the scope template in the workbooks. Invent a local student-notes application with two dummy users. Specify allowed functions and a test window; exclude real university systems and real student data. Classify five proposed activities: reading the app's own logs, changing a dummy profile, inspecting another service on the laptop, testing a live university portal, and deleting the lab's disposable test record. Explain which are authorized and why.

**Completion:** a scope another person can interpret consistently; a diagram linking one asset, threat, weakness, control, and evidence source.

**M01-Q1:** Does a public login page permit penetration testing? **Answer:** No. Reachability does not establish authorization. A valid owner-granted scope or applicable programme policy is needed.

**M01-Q2:** A backup exists, but nobody has restored it. Is recovery proven? **Answer:** No. Backup creation is evidence of a process; a successful restore and integrity check provide evidence of recoverability.

**References:** R07, R20, R21, R22.

### M02 — Computers, operating systems, and an isolated lab

**Budget:** 12 hours · **Prerequisites:** M01 · **Practical:** LAB-02 · **Mode:** PAPER or LOCAL

**M02-L1 — What runs a programme.** A CPU executes instructions, RAM holds working state, and storage retains files. The operating system schedules processes and controls access to memory, devices, and files. A process is a running instance of a programme; a service is a process or group of processes providing a function, often in the background. An ordinary user and an administrator should have different capabilities.

**M02-L2 — Boundaries and virtualization.** A virtual machine has a guest operating system under a hypervisor. A container normally shares a host kernel and uses operating-system isolation mechanisms. These technologies provide useful boundaries, but their strength depends on configuration and implementation. A bridged guest participates in a surrounding network; an internal virtual network can isolate guests from it. Draw the network before trusting a label in a setup wizard.

**M02-L3 — Reversibility is an engineering skill.** Keep a known-good baseline, make one change, observe its effect, and restore if needed. Save your notes outside a disposable guest. Verify that a restore returns files, accounts, and services to the intended state. Record time zones and clock differences because later log comparisons depend on them.

**LAB-02 — Prove your lab boundary.** Choose the browser-first plan or create one small Linux guest. Document permitted communication paths, the update procedure, and how you will prevent a vulnerable service becoming public. Create a harmless text file, take a supported snapshot or file backup, change it, and demonstrate restoration. If using paper mode, produce the exact checklist and test evidence you would need before considering the environment ready.

**Completion:** a network diagram, resource budget, and verified restore record; paper mode is labelled planned rather than executed.

**M02-Q1:** Is a NAT-connected vulnerable guest fully isolated? **Answer:** No. NAT commonly allows outbound traffic and may allow other configured paths. Inspect actual connectivity and forwarding.

**M02-Q2:** Why keep evidence outside a resettable guest? **Answer:** A restore may erase the work needed to explain or reproduce the exercise.

**References:** R25, R26.

### M03 — Linux and the command line

**Budget:** 14 hours · **Prerequisites:** M02 · **Practical:** LAB-03 · **Mode:** LOCAL or BROWSER

**M03-L1 — Files and navigation.** A shell interprets commands. An absolute path starts from the filesystem root; a relative path depends on the current directory. Learn to inspect your location before modifying anything. Files contain bytes; extensions are naming conventions, not proof of their contents. Hidden filenames are not secure storage. Standard input, standard output, and standard error let small tools cooperate.

**M03-L2 — Permissions and ownership.** Traditional Linux permissions distinguish an owner, a group, and others. Read, write, and execute have different meanings for files and directories. Directory execute permission permits traversal; directory write permission can permit changes to its entries. A secure file can still be exposed through an unsafe parent directory or a privileged service. Least privilege means granting the capabilities actually needed.

**M03-L3 — Processes and services.** A process has an identity, environment, open files, and resource usage. A listening service accepts communication on a socket. Learn to inspect processes, service state, logs, disk space, and listening sockets before troubleshooting by restarting everything. Package updates and trusted software sources matter more than memorizing long command strings.

**LAB-03 — Build a personal evidence workspace.** In your lab account, make folders for notes, evidence, and reports. Use the Linux workbook to inspect a small text file, change only that file's permissions, and record the difference. Inspect your own processes and local listening sockets. Complete introductory Bandit levels if using the provider option; record the principle learned, never publish current challenge passwords.

**Completion:** explain five commands in your own words, demonstrate a permission change on a disposable file, and locate the evidence without a tutorial.

**M03-Q1:** Does making a script executable make its code safe? **Answer:** No. Execute permission allows an attempt to run it; it says nothing about trustworthiness or behaviour.

**M03-Q2:** Why does a relative path sometimes address the wrong file? **Answer:** Its meaning changes with the working directory.

**References:** R03, R10.

### M04 — Networking from the first packet

**Budget:** 16 hours · **Prerequisites:** M02 · **Practical:** LAB-04 · **Mode:** PAPER or LOCAL

**M04-L1 — Addresses and routes.** An IP address identifies an interface within a network context; a port helps identify a transport endpoint. A subnet describes an address range, and a route decides where traffic goes next. A default gateway handles destinations without a more specific route. Private addresses are not automatically safe, and a public address is not permission to probe. Learn binary notation well enough to explain a subnet boundary rather than memorize a calculator result.

**M04-L2 — Protocol roles.** Ethernet and Wi-Fi move local frames. ARP helps IPv4 hosts discover local link-layer destinations; IPv6 uses different neighbour mechanisms. IP handles addressing and forwarding. TCP provides an ordered byte stream with reliability mechanisms; UDP provides datagrams without TCP's delivery guarantees. Applications decide how to use them. A TCP connection is not the same thing as a logged-in web session.

**M04-L3 — Names and encryption.** DNS resolves names to records; it does not itself prove an application's identity. TLS can provide confidentiality, integrity, and server authentication when certificates and names are validated correctly. DNS failures, routing failures, closed ports, TLS errors, and application errors are different layers of a failed request. Diagnose them in order and record evidence at the relevant layer.

**LAB-04 — Draw and explain a request path.** Draw your browser, local router, DNS resolver, and an example server. Label address, port, route, name lookup, and TLS. Calculate the range of a documentation `/24` subnet on paper. If collecting a capture, use only your own lab-generated traffic on the correct interface; otherwise inspect the synthetic request timeline in the workbook. Explain one likely failure at each layer.

**Completion:** a labelled diagram, a correct subnet explanation, and a five-step troubleshooting path.

**M04-Q1:** Does a closed port prove the host is offline? **Answer:** No. A host or intermediary may respond while that particular service is absent or blocked.

**M04-Q2:** Does HTTPS prove a website is honest? **Answer:** No. It helps secure the connection and authenticate a hostname; a malicious operator can also use HTTPS.

**References:** R11, R12.

### M05 — How websites and APIs work

**Budget:** 12 hours · **Prerequisites:** M04 · **Practical:** LAB-05 · **Mode:** PAPER or LOCAL

**M05-L1 — Requests and responses.** HTTP messages contain a method, target, headers, and sometimes a body. Responses contain a status, headers, and often content. GET is intended for retrieval and should not be designed to change important application state. A status code is only one clue: a response body, side effect, and backend log may tell a different story. APIs expose operations and structured data rather than necessarily returning complete pages.

**M05-L2 — State and identity.** HTTP does not inherently remember a user between requests. Applications add state with mechanisms such as server-side sessions and cookies or tokens. A cookie may carry a session identifier, not the entire identity record. The server must validate identity and permission for every relevant operation. Hidden form fields, disabled buttons, and frontend routes are under client influence.

**M05-L3 — The browser's boundaries.** An origin includes scheme, hostname, and port. Browser security policies limit some interactions across origins but do not replace server authorization. HTML describes structure, CSS presentation, and JavaScript behaviour. A browser's developer tools expose the network activity and storage needed to understand an application. Learn what a normal request looks like before trying to diagnose an abnormal one.

**LAB-05 — Read a synthetic conversation.** Use the HTTP workbook. Identify the requested object, session carrier, response type, and identity checks the server needs. Use developer tools only on your own application or an authorized learning page to compare a page request and a data request. Redact tokens from screenshots. Describe where the browser stops and server responsibility begins.

**Completion:** annotate a request and response and explain why a hidden button is not an access-control rule.

**M05-Q1:** Are a JSON token and encrypted data the same thing? **Answer:** No. JSON is a representation format; tokens may be signed, encrypted, opaque, or insecure depending on their design.

**M05-Q2:** Why must a server check permission after a user logs in? **Answer:** Identity alone does not specify which objects or actions that user is allowed to access.

**References:** R01, R11.

### M06 — Reasoning, evidence, threat models, and learning habits

**Budget:** 8 hours · **Prerequisites:** M01–M05 · **Practical:** LAB-06 · **Mode:** PAPER

**M06-L1 — Form a falsifiable hypothesis.** A useful hypothesis predicts an observable result. “The app is insecure” is vague. “User A can read User B's dummy note because ownership is not checked” can be tested with two accounts and one known object. Write the expected secure behaviour first. Include a control test so a broken login or stale cache is not mistaken for a vulnerability.

**M06-L2 — Model the system.** A basic threat model names assets, actors, components, data flows, trust boundaries, assumptions, and possible failures. A boundary is a change in trust, identity, privilege, or ownership. Ask what enters each component, what decisions it makes, and which evidence would show a mistake. A small accurate diagram is more useful than a large unexplained list of threats.

**M06-L3 — Explain without overstating.** Separate observed facts, inferences, and unknowns. State when a test was not performed. Preserve enough context for another learner to reproduce your result, while minimizing sensitive data. Keep a mistake log: what you misunderstood, why, and which experiment corrected it. Active recall and original explanations expose gaps that watching another tutorial can conceal.

**LAB-06 — Produce a one-page investigation.** Use the fictional two-user notes app. Draw a data-flow diagram, identify three trust boundaries, write one authorization hypothesis, and plan a control test. Record an invented observation as explicitly synthetic. Explain what it would prove and what it would not prove. End with a fix and a negative test.

**Completion:** a peer could distinguish your observations from your assumptions and repeat the planned experiment.

**M06-Q1:** A scanner reports a critical issue. What should you do next? **Answer:** Check scope, product/configuration applicability, evidence, and a safe validation method before assigning a confirmed finding.

**M06-Q2:** Why keep a failed experiment? **Answer:** It records limits, eliminates some hypotheses, and can prevent repeated mistakes if the context is preserved.

**References:** R02, R06, R07.

## Stage B — Programming and systems

**Budget:** 100 hours. **Stage outcome:** understand and modify small programmes, reason about data and identity, and read operating-system evidence.

### M07 — Python for useful security automation

**Budget:** 24 hours · **Prerequisites:** M03, M06 · **Practical:** LAB-07 · **Mode:** LOCAL

**M07-L1 — Programmes transform data.** Learn variables, strings, numbers, lists, dictionaries, conditions, loops, and functions by solving small problems. Read a line of a log, split its fields, validate them, and count a meaningful event. A function should have a clear input, result, and failure behaviour. Understand a programme well enough to predict its output before running it.

**M07-L2 — Treat input as uncertain.** Files can be missing, timestamps malformed, JSON incomplete, and a row unexpectedly large. Handle expected errors explicitly and keep useful diagnostics. Avoid broad exception handling that silently labels every failed operation successful. Keep secrets out of source code and logs. Read local synthetic files before attempting automation involving a network or credentials.

**M07-L3 — Automation needs boundaries.** A useful utility is predictable, bounded, and explainable. It should not recursively inspect unrelated folders, contact arbitrary systems, or consume unlimited resources by default. Learn unit tests using a small known dataset, including an empty file and malformed record. Prefer standard libraries until a dependency clearly improves the task. Record the runtime and dependency versions needed to reproduce results.

**LAB-07 — Write a synthetic authentication-log summarizer.** Use Workbook C's data and expected results. Count failed logins by account and source, identify successful logins, and print a short summary. Add handling for a blank line and an invalid JSON record. Explain why the result is a triage lead rather than proof that any account was compromised.

**Completion:** readable code, exact counts matching the answer key, useful error handling, and a short explanation of its limitations.

**M07-Q1:** Why is copying an unknown script into a terminal a poor learning method? **Answer:** Its effects and assumptions are unverified, and running it does not demonstrate understanding. Read, isolate, and test a small understood part first.

**M07-Q2:** What should a parser do with an invalid record? **Answer:** Follow a documented policy, such as count and report it while continuing; it must not silently invent a valid event.

**References:** R09, R17.

### M08 — Bash, PowerShell, Git, and reproducible work

**Budget:** 12 hours · **Prerequisites:** M03, M07 · **Practical:** LAB-08 · **Mode:** LOCAL

**M08-L1 — Shells connect tools.** Bash commonly connects text streams; PowerShell pipelines often carry structured objects. Quoting determines whether characters are interpreted as syntax or treated as data. Spaces, wildcards, substitutions, and untrusted filenames can change a command's meaning. Start with read-only inspection and explicit paths. Understand exit codes before combining operations into scripts.

**M08-L2 — Version control records intent.** Git records snapshots and their relationships. A branch is a movable reference, not a separate backup service. A useful commit groups one understandable change and explains why it exists. Review differences before committing. Ignore generated output and local configuration when appropriate, but remember that adding a secret to an ignore list does not remove it from existing history.

**M08-L3 — Reproduction beats a lucky run.** Document how to prepare inputs, run the task, and interpret the result. Separate configuration from logic and make destructive actions explicit. Keep real credentials out of example files. If a credential leaks, revoke or rotate it through its owner; merely deleting the visible line is insufficient. Do not publish lab solutions when a platform's rules prohibit them.

**LAB-08 — Version a small investigation.** Create a local repository for LAB-07. Add a short readme, synthetic input, expected output, and an explanation of dependencies. Make an intentional code improvement, inspect the difference, and commit it. Write a Bash or PowerShell command that counts a harmless local dataset and explain its quoting. No remote publication is required.

**Completion:** another learner can reproduce the result from the written instructions; no secrets or unrelated personal files are included.

**M08-Q1:** Does deleting a secret from the current file revoke it? **Answer:** No. Copies and history may retain it; the issuing system must invalidate or rotate it.

**M08-Q2:** Why inspect a command's exit status? **Answer:** Printed text alone can be misleading; subsequent steps must know whether the operation succeeded under its documented contract.

**References:** R10, R13, R14.

### M09 — Programming fundamentals, C, and memory

**Budget:** 18 hours · **Prerequisites:** M07–M08 · **Practical:** LAB-09 · **Mode:** PAPER or LOCAL

**M09-L1 — Data structures and algorithms.** Arrays, maps, sets, and queues solve different problems. An algorithm's time and memory use matter when an input grows. A nested comparison of every record with every other record can become impractical faster than a dictionary lookup. Resource exhaustion can arise from ordinary expensive logic, not just obvious malicious code. Bound input sizes and measure representative cases.

**M09-L2 — Memory has structure and lifetime.** A pointer refers to a memory location; an array has a finite capacity. Stack and heap allocations have different management patterns. Reading beyond a boundary or using an object after its lifetime can produce crashes or corrupt state. C exposes responsibilities that higher-level runtimes often manage for the programmer. Learn the root cause using small self-authored programmes before studying exploit development.

**M09-L3 — Mitigations reduce classes of failure.** Bounds checking, compiler diagnostics, sanitizers, safer APIs, and memory-safe languages can prevent or reveal mistakes. ASLR, non-executable memory, and stack protections can make some exploitation harder but do not repair incorrect ownership or bounds. A crash is evidence of a failure; it does not by itself establish code execution or exploitability.

**LAB-09 — Review a bounded parser.** Write or inspect a tiny programme that accepts a length and a string. Test empty, ordinary, too-long, and nonnumeric inputs. If using C, compile only your own code with available warnings and a supported sanitizer, then correct any reported bounds or lifetime mistake. Paper mode uses a state table showing accepted and rejected input and the intended memory limits.

**Completion:** explain the boundary condition, demonstrate or reason through the correction, and distinguish crash evidence from impact claims.

**M09-Q1:** Does a sanitizer finding prove a remotely exploitable vulnerability? **Answer:** No. Exposure, attacker control, build settings, and practical consequences need separate analysis.

**M09-Q2:** Can a memory-safe language still have authorization bugs? **Answer:** Yes. Memory safety does not establish correct business rules or identity checks.

**References:** R17, R18.

### M10 — Databases, SQL, and transaction safety

**Budget:** 14 hours · **Prerequisites:** M07, M09 · **Practical:** LAB-10 · **Mode:** PAPER or LOCAL

**M10-L1 — Model relationships.** A relational database stores records in tables with keys, constraints, and relationships. A primary key identifies a record; a foreign key expresses a relationship to another table. Queries retrieve or modify rows. Schema design can prevent invalid states, but the database does not automatically know whether a particular web user is allowed to read a record.

**M10-L2 — Separate code from values.** Constructing a query by concatenating untrusted text can let that text alter query structure. Parameterized queries keep values separate from the SQL statement. Parameters generally do not replace arbitrary identifiers such as a table name or sort direction; those require a controlled design or allowlist. An ORM helps with common patterns but unsafe raw queries can reintroduce injection.

**M10-L3 — Changes need consistent rules.** Transactions group related changes. Isolation and locking determine how concurrent work interacts. A balance check followed by an unprotected update can fail when two requests run together. Database constraints and appropriately atomic operations can preserve invariants. Backups must have access controls and tested restore procedures because they often contain the same sensitive data as production.

**LAB-10 — Secure a fictional notes table.** Define users and notes with ownership. Use Workbook D to compare an unsafe concatenated query, a parameterized lookup, and a parameterized lookup that also enforces ownership. Write expected outcomes for own note, another user's note, missing note, and malformed input. Design a transaction that must never reduce an inventory count below zero.

**Completion:** explain why injection prevention and authorization are distinct; provide a correct negative test and concurrency invariant.

**M10-Q1:** Does parameterization automatically enforce object ownership? **Answer:** No. It protects query structure; permission still needs a condition or other reliable authorization check.

**M10-Q2:** Why test two requests that overlap in time? **Answer:** Sequential tests may miss a race where both requests act on the same old state.

**References:** R06, R15.

### M11 — Windows, enterprise identity, and Active Directory

**Budget:** 18 hours · **Prerequisites:** M02, M04, M08 · **Practical:** LAB-11 · **Mode:** PAPER or LOCAL

**M11-L1 — Windows security objects.** Processes run with access tokens describing identities and privileges. Security identifiers identify principals; access-control lists express permissions on objects. Services, scheduled tasks, registry configuration, and file permissions influence what runs and with whose rights. The graphical interface is one view of these decisions, not the whole security model.

**M11-L2 — Centralized identity.** Active Directory Domain Services provides directory and domain capabilities. Users, computers, groups, policies, and trusts create relationships that can be useful or overpermissive. Kerberos uses tickets to support authentication; LDAP supports directory access. These roles are related but not interchangeable. Domain administration and local administration are different scopes of authority.

**M11-L3 — Identity creates paths.** A low-privilege account may indirectly control a sensitive resource through a writable group, delegated permission, or service configuration. Model these relationships as a graph and ask whether each edge is necessary. Distinguish on-premises AD DS from Microsoft Entra ID; similar identity vocabulary does not make them the same service or management plane.

**LAB-11 — Analyse a fictional domain.** On paper, create student, helpdesk, service, and administrator identities. Draw group membership and permissions. Deliberately grant helpdesk excessive control over a service configuration, then identify the resulting trust problem and a narrower permission. If a licensed isolated Windows lab is available, inspect the corresponding permissions and audit settings without harvesting credentials.

**Completion:** an identity graph, one unnecessary permission path, a proposed correction, and the evidence needed to verify it.

**M11-Q1:** Is membership in an ordinary domain group equivalent to domain administration? **Answer:** No. Effective permission depends on the group's rights and relationships.

**M11-Q2:** Why do service identities deserve attention? **Answer:** They can hold broad or persistent privileges and may be managed less carefully than interactive users.

**References:** R13, R16.

### M12 — Cryptography, passwords, and identity protocols

**Budget:** 14 hours · **Prerequisites:** M05, M09–M11 · **Practical:** LAB-12 · **Mode:** PAPER or LOCAL

**M12-L1 — Different primitives solve different problems.** Encoding changes representation and is normally reversible without a secret. Encryption protects confidentiality using a key. A cryptographic hash produces a digest; it is not encryption. A MAC authenticates data using a shared secret, while a digital signature uses an asymmetric key pair. A hash alone cannot prove who created a file. MD5 is unsuitable for collision-resistant security uses; modern designs should select current, reviewed primitives and libraries.

**M12-L2 — Passwords need specialized storage.** Password verification should use a suitable adaptive password-hashing scheme, such as Argon2id where supported and appropriately configured, with a unique salt. Salts prevent identical passwords from producing identical stored results under the same parameters; they are not secrets. A pepper is a separate secret with its own management burden. A fast general-purpose hash alone is a poor password-storage design. Recovery and MFA reset paths need as much care as normal login.

**M12-L3 — Identity is a protocol, not just a token.** OAuth is principally an authorization framework; OpenID Connect adds an identity layer. Validate intended issuer, audience, signature or other required protection, lifetime, and protocol state using maintained libraries. Key storage, rotation, revocation, and recovery can matter more than choosing a fashionable algorithm. A signed token is readable unless separately encrypted and does not automatically authorize every action.

**LAB-12 — Design an identity lifecycle.** For a fictional study app, diagram registration, login, session renewal, password reset, MFA enrollment, logout, and account removal. Mark where identity and authorization are checked. Compare encoding, hashing, and encryption on harmless example text conceptually or with trusted local tools. Review a proposed password-storage design and explain what must change.

**Completion:** a threat-aware identity diagram and a clear explanation of salts, session invalidation, and key responsibility.

**M12-Q1:** Does Base64 protect a password? **Answer:** No. It is encoding and can be decoded without a secret.

**M12-Q2:** Is a correctly signed token valid for every API? **Answer:** No. The recipient must also validate its intended context and enforce the requested permission.

**References:** R06, R19, R28.

## Stage C — Web and application security

**Budget:** 130 hours. **Stage outcome:** understand vulnerability causes, validate them in educational environments, and connect every finding to a repair and retest.

### M13 — Application mapping and an intercepting proxy

**Budget:** 16 hours · **Prerequisites:** Stage B · **Practical:** LAB-13 · **Mode:** BROWSER or LOCAL

**M13-L1 — Map behaviour before testing.** List entry points, user roles, sensitive objects, state changes, integrations, and background jobs. Follow a normal user journey and preserve its sequence. A route list alone misses business operations such as invitation acceptance, export generation, and account recovery. Mark which component makes each authorization decision and where data crosses a trust boundary.

**M13-L2 — Observe requests accurately.** An intercepting proxy lets you inspect and, within a lab, modify requests and responses. Use a dedicated browser profile and scope filters. Trust a testing certificate only within that disposable profile when required; remove it afterward. Browser developer tools may be sufficient for early exercises. Do not route unrelated personal sessions through a testing proxy.

**M13-L3 — Build a coverage map.** For each operation, record input locations, expected permissions, response behaviour, and relevant test categories. Change one variable at a time and keep a baseline. Automated discovery can miss authenticated functionality and can trigger unintended state changes. Manual understanding supplies context that tools cannot infer from URLs alone.

**LAB-13 — Map an intentionally vulnerable app.** Use a provider's beginner application or a local educational app. Walk through registration, login, profile viewing, and a dummy content operation. Record ten distinct requests or all available requests if the app is smaller. Build a matrix of role, operation, object, and expected result. Identify two untested assumptions without claiming they are vulnerabilities.

**Completion:** a clean request map with tokens redacted, a defined test scope, and a baseline request that can be reproduced.

**M13-Q1:** Why keep a baseline request? **Answer:** It shows normal behaviour and helps attribute a changed result to the specific experimental change.

**M13-Q2:** Does a proxy's target filter create legal authorization? **Answer:** No. It helps constrain a tool; permission comes from the testing agreement or provider policy.

**References:** R01, R02, R04.

### M14 — Authentication, sessions, and account recovery

**Budget:** 20 hours · **Prerequisites:** M12–M13 · **Practical:** LAB-14 · **Mode:** BROWSER or LOCAL

**M14-L1 — Authentication is a lifecycle.** Examine enrollment, login, failure handling, password changes, recovery, MFA setup, and account removal together. An excellent login form can be undermined by a weak reset process. Responses can reveal whether an account exists; the impact depends on context. Rate controls must consider abuse and availability, including whether an attacker could lock out legitimate users.

**M14-L2 — Sessions represent continuing trust.** Session identifiers should be unpredictable and protected in transit and storage. Cookie attributes such as Secure, HttpOnly, and SameSite address different risks. They do not replace server-side validation. Rotate session state when authentication or privilege changes require it, and design explicit expiry and revocation behaviour. Logout should have a documented effect on sessions and tokens.

**M14-L3 — Test state changes.** Compare behaviour before login, after login, after password change, after logout, and after expiry. Check whether sensitive operations require appropriate recent authentication. Treat OAuth/OIDC redirects and linked identities as security boundaries. Use maintained protocol libraries and explicit redirect rules rather than building a protocol from an example token.

**LAB-14 — Audit a dummy account lifecycle.** In an assigned authentication lab, create only the supplied dummy accounts. Document cookie attributes and session behaviour across login and logout. Review the password-reset flow and state your expected token lifetime and single-use rules. Complete one provider exercise on authentication, then describe its root cause and a regression test; avoid automated guessing against unrelated accounts.

**Completion:** a lifecycle matrix and a finding or verified-control report with reproduction and limitations.

**M14-Q1:** Does HttpOnly prevent every consequence of XSS? **Answer:** No. It restricts script access to a cookie, but injected script may still perform actions within the page's authority.

**M14-Q2:** Why can an account-recovery feature be security-critical? **Answer:** It can replace credentials or establish access without the ordinary login path.

**References:** R01, R06, R19.

### M15 — Authorization, APIs, and tenant isolation

**Budget:** 24 hours · **Prerequisites:** M10, M13–M14 · **Practical:** LAB-15 · **Mode:** PAPER, BROWSER, or LOCAL

**M15-L1 — Authorize the action and the object.** Function-level authorization asks whether a user may perform an operation; object-level authorization asks whether it may be performed on this specific resource. A valid account with a valid object identifier can still be unauthorized. Check ownership, tenant, role, resource state, and delegated permission on the server. An unpredictable identifier can reduce guessability but does not supply authorization.

**M15-L2 — APIs have more than URL parameters.** Inputs can appear in JSON bodies, nested objects, batch requests, GraphQL operations, headers, and uploaded metadata. Mass assignment occurs when an app accepts fields that should not be client-controlled. Limit returned properties as well as writable ones. Pagination, quotas, expensive queries, and file exports can expose excessive data or resource use even when authentication is correct.

**M15-L3 — Isolation must survive every path.** Multi-tenant applications need consistent boundaries in queries, caches, storage, search, exports, queues, and background tasks. A correctly protected page does not prove its download endpoint is protected. For WebSocket connections, check the identity and permissions relevant to messages and long-lived state, not only the initial connection.

**LAB-15 — Use a two-user authorization matrix.** Follow Workbook D with dummy users A and B and separate records. Test or reason through read, update, delete, and export using authorized identities and objects. Add a tenant dimension on paper. Include an allowed control case and a denied cross-user case. Propose centralized checks and regression tests covering alternate endpoints.

**Completion:** a matrix with both successful and denied cases, minimum evidence of any flaw, and a fix that checks resource ownership.

**M15-Q1:** Does changing sequential IDs to UUIDs fix broken object authorization? **Answer:** No. Less predictable IDs do not enforce permission when an identifier becomes known.

**M15-Q2:** Why test an export after testing its screen? **Answer:** Export generation and retrieval may use different code or permissions and expose a separate failure.

**References:** R01, R05, R06.

### M16 — Injection and unsafe interpretation

**Budget:** 24 hours · **Prerequisites:** M07, M09–M10, M13 · **Practical:** LAB-16 · **Mode:** BROWSER or LOCAL

**M16-L1 — The interpreter boundary.** Injection occurs when data is interpreted as instructions or syntax in an unintended context. SQL, shell commands, templates, directory queries, and document stores have different grammars, so a universal “sanitize” function is unreliable. Trace data from its source to the interpreter. Determine which part of the final structure the input can influence before choosing a test.

**M16-L2 — Fix the construction.** Parameterize database values; avoid invoking a shell when a structured library API can perform the operation; use explicit argument handling and allowlists where appropriate. A prepared database query does not secure a separate shell call. Template engines should receive data through their intended interfaces, not arbitrary templates assembled from user text. Error suppression may hide symptoms without repairing the boundary.

**M16-L3 — Demonstrate the smallest useful effect.** In a training app, a controlled change in a dummy query result can prove an input affected query structure. It is unnecessary to retrieve entire databases to explain the cause. Compare an ordinary baseline, a deliberate controlled variation, and the fixed behaviour. Describe possible impact separately from what you actually demonstrated.

**LAB-16 — Diagnose and repair an injection lab.** Complete one provider SQL injection exercise and review Workbook D's parameterized repair. Then inspect a fictional programme that builds a shell command from a filename; redesign it using an appropriate direct file or process API. Record the relevant grammar, trust boundary, minimal observation, and negative tests. Keep any active reproduction inside the assigned lab.

**Completion:** explain two distinct injection contexts and why their fixes differ; produce a validated query repair.

**M16-Q1:** Does hiding a database error remove SQL injection? **Answer:** No. The query may still be influenced even when its error is not displayed.

**M16-Q2:** Why are allowlists useful for a selectable sort direction? **Answer:** A small permitted set can constrain syntax that ordinary value parameters do not represent.

**References:** R01, R06, R15.

### M17 — Browser security: XSS, CSRF, CORS, and content handling

**Budget:** 22 hours · **Prerequisites:** M05, M12, M14–M16 · **Practical:** LAB-17 · **Mode:** BROWSER or LOCAL

**M17-L1 — Cross-site scripting.** XSS occurs when untrusted data becomes executable content in a browser context. Reflected, stored, and DOM-based paths differ in where data travels and becomes dangerous. Context-aware output handling matters: HTML text, attributes, URLs, and JavaScript are not interchangeable contexts. Prefer safe rendering APIs and template escaping; sanitize allowed rich HTML with a maintained library. CSP is defence in depth, not a substitute for repairing unsafe rendering.

**M17-L2 — Cross-site request forgery.** CSRF takes advantage of a browser automatically attaching credentials to a request the user did not intend. Protect state-changing actions with an appropriate token design and origin validation, alongside suitable cookie settings. SameSite behaviour depends on request context and browser semantics. XSS can defeat some CSRF protections by operating within the trusted origin, so controls must be evaluated together.

**M17-L3 — CORS and related boundaries.** CORS tells browsers when a response may be exposed to a different origin. It is not server-side authentication, and it does not stop every request from being sent. A permissive policy is meaningful only in context, such as sensitive responses and credential handling. Also understand clickjacking protections and the distinction between an origin and a registrable site when reasoning about browser policies.

**LAB-17 — Trace a browser trust boundary.** Use assigned XSS and CSRF learning exercises. For XSS, use only the lab's harmless demonstration and record source, transformation, sink, and rendering context. For CSRF, explain which credentials the browser attaches and which check should reject an unwanted action. Evaluate a fictional CORS policy and specify allowed origins and credential expectations.

**Completion:** three distinct diagrams for XSS, CSRF, and CORS; a repair and a test that actually exercise the relevant boundary.

**M17-Q1:** Does CORS authenticate an API client? **Answer:** No. It controls browser response sharing under specified conditions; the API still needs its own identity and permission checks.

**M17-Q2:** Is generic HTML escaping always safe inside JavaScript source? **Answer:** No. Escaping must match the output context, and avoiding inline code construction is usually safer.

**References:** R01, R06, R11.

### M18 — Server-side boundaries and business logic

**Budget:** 24 hours · **Prerequisites:** M13–M17 · **Practical:** LAB-18 · **Mode:** PAPER, BROWSER, or LOCAL

**M18-L1 — Files, parsers, and outbound requests.** Path traversal crosses an intended filesystem boundary. Upload problems can arise from file interpretation, storage location, permissions, or unsafe processing. SSRF lets untrusted input influence a server's outbound requests. XML external entity processing and unsafe deserialization can expose additional interpreter or resource boundaries. Model each feature's intended data flow and remove unnecessary capabilities instead of relying only on filename suffixes or a blocklist.

**M18-L2 — Components can disagree.** Proxies, caches, and application servers may interpret request boundaries, paths, headers, or cache keys differently. Request smuggling and cache-related flaws arise from such disagreements. Study them in purpose-built provider labs because malformed traffic on shared infrastructure can affect other users. Fixes require consistent parsing, patching, architecture review, and verification at every relevant component.

**M18-L3 — Valid requests can create invalid outcomes.** A discount applied twice, a refund exceeding a purchase, or an invitation accepted after revocation can be a logic flaw without unusual characters. Define invariants and state transitions. Concurrency adds races: two individually valid requests can violate a shared constraint. Atomic changes, idempotency, and server-controlled state can enforce business rules more reliably than UI sequencing.

**LAB-18 — Model three boundary failures.** Choose one assigned SSRF or path exercise and document its intended boundary and fix. On paper, design a safe upload flow with content checks, separate storage, and controlled retrieval. Use Workbook E to reason about a double redemption race. If studying request smuggling, use only a dedicated educational instance and explain the parser disagreement rather than treating a payload as a universal trick.

**Completion:** one lab finding and two design reviews, each with an explicit invariant, evidence requirement, and regression test.

**M18-Q1:** Is validating only the first URL enough for a server that follows redirects? **Answer:** No. Subsequent destinations may cross the intended boundary; validate effective destinations and enforce appropriate egress restrictions.

**M18-Q2:** Why can a workflow fail even if every input has the correct type? **Answer:** Valid individual values do not guarantee valid relationships, ordering, authorization, or concurrent state transitions.

**References:** R01, R02, R06.

## Stage D — Professional penetration testing

**Budget:** 110 hours. **Stage outcome:** carry out a scoped assessment with defensible evidence, useful recommendations, and a verified cleanup.

### M19 — Engagement planning, reconnaissance, and network enumeration

**Budget:** 16 hours · **Prerequisites:** Stages A–C · **Practical:** LAB-19 · **Mode:** PAPER or LOCAL

**M19-L1 — Begin with the business question.** Determine what the owner wants to learn: whether a boundary is effective, whether a new application meets requirements, or whether a specific threat can be detected. Define scope, exclusions, time windows, permitted source addresses, escalation contacts, rate limits, and evidence handling. Third-party hosting and integrations may need separate permission. A penetration test is a bounded investigation, not permission to pursue every connected system.

**M19-L2 — Discovery has different levels of interaction.** Passive research can use owner-provided inventories, documentation, and public technical information. Active enumeration sends traffic and may affect a service. In a lab, start with a narrow known target and the smallest question: is the expected service reachable, and what evidence describes it? Avoid treating guessed banners or exposed metadata as verified software versions.

**M19-L3 — Enumerate to understand.** For each allowed host and service, record its purpose, identity boundary, protocol, exposure, authentication requirements, and evidence source. DNS, web, SSH, SMB, database, and remote-management services have different normal behaviours and risks. A port number suggests a convention, not proof of the running application. Reconcile tool observations with owner documentation and the actual configuration when available.

**LAB-19 — Inventory a small approved lab.** Use only the explicitly listed machines in your isolated environment. Compare a service inventory obtained from local configuration with a narrowly scoped network observation using an appropriate tool. If using paper mode, use the service table in Workbook F. For every mismatch, write at least two possible explanations before declaring a finding.

**Completion:** a scope, service inventory, method record, and one evidence-backed configuration observation.

**M19-Q1:** Is every hostname discovered during a test automatically in scope? **Answer:** No. Discovery and authorization are separate; confirm ownership and scope before further interaction.

**M19-Q2:** Why compare a network view with host configuration? **Answer:** Firewalls, proxies, stale inventories, and misleading banners can make either view incomplete.

**References:** R02, R12, R24.

### M20 — Vulnerability validation, prioritization, and uncertainty

**Budget:** 18 hours · **Prerequisites:** M06, M19 · **Practical:** LAB-20 · **Mode:** PAPER or LOCAL

**M20-L1 — A vulnerability record is not a diagnosis.** CVE identifies a published vulnerability record; it is not a guarantee that a particular system is affected. Product versions, backported patches, enabled features, reachable code paths, and configuration all matter. Read the vendor's advisory and compare the affected conditions with the lab. Do not execute an unknown public proof of concept merely because a scanner links to it.

**M20-L2 — Validate proportionately.** Prefer configuration inspection, a safe controlled request, or a vendor-supported check when those answer the question. Write the expected observation for both vulnerable and fixed states. A negative result may mean the condition is absent, the method is unsuitable, or the observation is incomplete. Keep confidence and verification status separate from severity.

**M20-L3 — Prioritize in context.** CVSS describes technical severity using a defined version and vector. Business risk also depends on exposure, asset value, existing controls, exploitation evidence, and recovery options. EPSS estimates a particular exploitation probability and is not a severity score. A known-exploited vulnerability catalogue is another prioritization signal, not a complete inventory of all dangerous issues.

**LAB-20 — Triage three fictional findings.** Use Workbook F. Compare an unsupported version guess, a verified overly broad permission, and an externally exposed critical service with uncertain patch status. State what is known, what additional evidence is needed, and which owner should act first. If calculating CVSS, include the version, vector, and reasoning rather than only a number.

**Completion:** three triage records with confidence, technical impact, contextual priority, safe validation method, and a next action.

**M20-Q1:** Can a lower CVSS issue deserve earlier remediation? **Answer:** Yes. Actual exposure, business impact, and current exploitation can make it more urgent in context.

**M20-Q2:** What does a scanner's version match prove? **Answer:** Usually only that observed information matched a rule; applicability and actual impact still require verification.

**References:** R23, R24, R29.

### M21 — Linux host assessment and privilege boundaries

**Budget:** 20 hours · **Prerequisites:** M03, M09, M19–M20 · **Practical:** LAB-21 · **Mode:** LOCAL or BROWSER

**M21-L1 — Privilege follows trust.** A privileged process may trust a file, directory, executable, environment, or scheduled job that a less privileged identity can influence. This creates a path across a privilege boundary. Inspect ownership, permissions, service accounts, scheduled tasks, administrative delegation, capabilities, and privileged executables. Explain why a particular combination matters instead of collecting a list of unusual settings.

**M21-L2 — Assess the chain of control.** A writable configuration file is significant when a more privileged process actually uses it in a security-relevant way. A weak directory can matter even when an individual file looks protected. Trace who can change each input and which identity consumes it. Review unnecessary services and secrets storage as well as escalation opportunities. Kernel vulnerability claims require precise build and patch evidence.

**M21-L3 — Repair and observe.** Remove unnecessary privilege, correct ownership, use explicit execution paths, separate service identities, and protect configuration integrity. Validate that the service still works after hardening. Record relevant file, process, and audit events so a defender could recognize a similar problem. Temporary lab changes should have a documented reset path.

**LAB-21 — Audit a deliberately misconfigured service.** Use an educational Linux machine or a personally authored harmless service in an isolated guest. Identify one intended permission boundary and one controlled misconfiguration. Prove the influence with a harmless dummy output in the lab, then correct the permission and repeat the test. Include a normal service-function check after the repair.

**Completion:** an explained privilege relationship, minimal lab evidence, a working fix, a regression test, and restored lab state.

**M21-Q1:** Does every world-writable file imply administrative compromise? **Answer:** No. Impact depends on what trusts or consumes it and with which privileges.

**M21-Q2:** Why test normal functionality after reducing permissions? **Answer:** A security change that breaks required work may be bypassed or rolled back; the intended service must remain usable.

**References:** R03, R06, R10.

### M22 — Windows and Active Directory assessment

**Budget:** 22 hours · **Prerequisites:** M11–M12, M19–M20 · **Practical:** LAB-22 · **Mode:** PAPER or LOCAL

**M22-L1 — Evaluate effective permissions.** Review users, groups, services, scheduled tasks, local administrators, directory delegation, and administrative separation. The important question is which actions an identity can cause, including through other objects. Group nesting, inherited permissions, and management tools can create unexpected rights. Begin with read-only inspection and a clear identity graph.

**M22-L2 — Understand authentication weaknesses.** Weak credential handling, overly privileged service accounts, insecure legacy protocols, and unconstrained delegation can undermine identity security. Learn the mechanisms and their defensive consequences in a dedicated domain lab. Distinguish authentication material from authorization and understand that access to a directory is not automatically permission to retrieve secrets or exercise every discovered relationship.

**M22-L3 — Reduce the opportunity for escalation.** Separate administrative accounts, minimize standing privilege, protect service identities, manage local administrator credentials, review delegation, and monitor sensitive changes. Hardening choices depend on the environment and supported features. Confirm the actual policy effect on the intended hosts rather than assuming a policy exists because it was created in a management console.

**LAB-22 — Remove one excessive permission path.** Extend LAB-11's fictional identity graph or use a licensed isolated domain. Identify a low-privilege path to a sensitive configuration, describe its prerequisites, and inspect or simulate it using dummy objects. Remove the unnecessary edge and verify required helpdesk work still succeeds. Produce an audit event or specify the expected telemetry.

**Completion:** before-and-after permission graphs, a bounded validation, and a defensive control with evidence of its effect.

**M22-Q1:** Why is a graph helpful for directory security? **Answer:** Several individually ordinary permissions can combine into a significant chain of control.

**M22-Q2:** Does creating a policy prove every device applies it? **Answer:** No. Scope, inheritance, connectivity, conflicts, and refresh state affect actual application.

**References:** R13, R16, R08.

### M23 — Wireless, human factors, and physical security

**Budget:** 14 hours · **Prerequisites:** M01, M04, M12 · **Practical:** LAB-23 · **Mode:** PAPER or LOCAL

**M23-L1 — Wireless is a shared medium.** Distinguish network names, radio identifiers, association, authentication, and encryption. Security depends on configuration, client behaviour, credential management, and segmentation, not just a familiar network name. Review current supported protections and remove unnecessary legacy features. Wireless signals can reach beyond a room, so even a home exercise needs a carefully limited design.

**M23-L2 — Human behaviour is part of a system.** Urgency, authority, familiarity, and unexpected requests can influence decisions. Good awareness training teaches verification through independent channels and makes reporting easy. Measure whether the process helps users, rather than humiliating people for mistakes. A training exercise requires agreement on participants, content, data collection, support, and debriefing.

**M23-L3 — Physical access changes assumptions.** Lost devices, unattended unlocked screens, removable media, and poorly controlled rooms can undermine technical controls. Device encryption, secure boot, screen locking, asset management, and recovery procedures work together. A policy that is impossible to follow under real working conditions needs redesign, not simply stronger wording.

**LAB-23 — Conduct a configuration and awareness review.** Inspect the configuration of your own access point without disrupting traffic or testing other networks. Document guest isolation, administrative access, updates, and supported authentication settings. Create a clearly labelled fictional suspicious message on paper, identify its cues, and write a verification/reporting response. Do not send it to anyone as part of this exercise.

**Completion:** a configuration checklist, a labelled awareness sample, a respectful response procedure, and a physical-device checklist.

**M23-Q1:** Does a familiar Wi-Fi name prove the access point's identity? **Answer:** No. Names can be duplicated; authentication and configuration provide stronger evidence.

**M23-Q2:** What is a useful awareness success metric? **Answer:** Improved recognition, verification, and reporting with minimal harm, assessed under a consented training plan.

**References:** R07, R20, R30.

### M24 — Reporting, remediation, retesting, and cleanup

**Budget:** 20 hours · **Prerequisites:** M19–M23 · **Practical:** LAB-24 · **Mode:** PAPER or LOCAL

**M24-L1 — A finding must be useful.** State the affected asset, expected behaviour, observed behaviour, reproduction, evidence, root cause, impact, confidence, and recommended repair. Keep executive and technical explanations consistent. Avoid making an impact claim that depends on actions you did not perform without clearly labelling the inference. “Potential” should describe a specific unverified consequence, not conceal missing analysis.

**M24-L2 — A recommendation needs an owner and a test.** Prefer repairing the root cause to filtering one observed input. Describe the desired control, implementation considerations, and a verification method. Assign an owner and priority through the engagement's process. Document compensating controls and residual risk when a complete repair is not immediately possible. A retest should include the original case, adjacent cases, and normal use.

**M24-L3 — Close the engagement properly.** Remove temporary accounts, files, configuration changes, test tokens, and any agreed simulation mechanisms. Confirm the owner's systems are in the expected state. Protect and retain evidence only for the agreed period. State coverage gaps, unavailable systems, incomplete tests, and follow-up needs. A concise, reproducible report is more valuable than a large export of unreviewed tool output.

**LAB-24 — Deliver a small assessment.** Use the report template and two earlier lab findings. Write a one-page executive summary, technical details, and a remediation table. Retest one correction and give it a clear status: fixed, partially fixed, not fixed, or unable to verify. Add a cleanup checklist and a five-minute spoken explanation aimed at a developer.

**Completion:** a report another person can reproduce, a tested fix, explicit limits, and evidence of cleanup.

**M24-Q1:** Is “install a firewall” an adequate universal recommendation? **Answer:** No. A useful recommendation addresses the specific cause and defines how to verify the control.

**M24-Q2:** Should an unavailable retest be marked fixed? **Answer:** No. Use an explicit unable-to-verify status and describe the missing evidence.

**References:** R02, R06, R23.

## Stage E — Defence, investigation, and response

**Budget:** 110 hours. **Stage outcome:** turn observations into a defensible investigation and improve prevention, visibility, and recovery.

### M25 — Logs, SIEM concepts, and detection engineering

**Budget:** 18 hours · **Prerequisites:** M06–M07, M11 · **Practical:** LAB-25 · **Mode:** PAPER or LOCAL

**M25-L1 — Logs are measurements.** Authentication, process, application, DNS, proxy, and cloud audit logs describe different parts of a system. A missing event can mean nothing happened, logging was disabled, collection failed, retention expired, or your query missed it. Record source, timestamp, time zone, event meaning, and collection limits. Normalize fields carefully without erasing original values needed for an investigation.

**M25-L2 — A SIEM supports questions.** Centralized search and correlation help connect events, but a dashboard does not create trustworthy evidence by itself. Begin with a question, identify needed fields, and write a query whose assumptions are explicit. Correlate by stable identifiers when possible; usernames, addresses, and display names may be reused or shared. Protect logs from unnecessary personal-data exposure and unauthorized modification.

**M25-L3 — Evaluate detections.** A rule needs a hypothesis, required telemetry, logic, expected benign cases, severity rationale, and response guidance. Measure precision and recall against labelled test data, recognizing that synthetic test performance may not represent production. A low false-positive rate can still create overwhelming alerts when benign activity is common. Changes to applications and log schemas require regression checks.

**LAB-25 — Build a small authentication detection.** Use Workbook C. Identify a burst of failed logins followed by a success and a nearby sensitive action. Write a rule in plain language or a local query, list the exact required fields, and test it against the labelled sample. Add a benign explanation such as user error or a shared address and identify evidence that would distinguish it.

**Completion:** a rule specification, sample matches and nonmatches, a limitation statement, and an analyst response checklist.

**M25-Q1:** Is an alert equivalent to an incident? **Answer:** No. An alert is a signal requiring validation and context; an incident is a determined event needing response under the organization's criteria.

**M25-Q2:** Why preserve raw timestamps? **Answer:** Normalization can hide clock or time-zone mistakes that affect event ordering.

**References:** R08, R13, R33.

### M26 — Network defence and packet investigation

**Budget:** 18 hours · **Prerequisites:** M04, M19, M25 · **Practical:** LAB-26 · **Mode:** PAPER or LOCAL

**M26-L1 — Segment according to trust.** Segmentation limits which systems can communicate. A useful rule identifies source, destination, service, purpose, and owner. Default-deny designs still need managed exceptions, monitoring, and testing. Egress controls can limit unwanted outbound activity, while ingress controls regulate entry. Network location alone should not establish trust in an identity or device.

**M26-L2 — Read packet evidence carefully.** A capture is a view from one interface during one period. Missing packets, encryption, offloading, asymmetric routing, or an incorrect capture point can change interpretation. Distinguish capture filters from display filters. Follow a connection, inspect protocol fields, and compare timing against application logs. TLS often hides content while leaving some metadata visible.

**M26-L3 — Detection complements prevention.** IDS observes and alerts; an IPS may also block in a traffic path. Both depend on visibility and tuning. A signature match needs context, and the absence of a match does not prove safety. Document what a rule can see, what encrypted or unobserved traffic it cannot see, and how an analyst should investigate without overclaiming.

**LAB-26 — Explain a permitted connection.** Capture a short request between your own lab components or use a provider-supplied training capture. Identify the endpoints, protocol sequence, timing, and whether application content is visible. Design a small segmentation table that permits required functions and rejects an unnecessary path. Verify through lab observation or a labelled paper simulation.

**Completion:** an annotated flow, a visibility statement, and a tested or explicitly simulated network-control table.

**M26-Q1:** Can an empty capture prove no network activity occurred? **Answer:** No. It may reflect the wrong interface, filter, capture time, or collection failure.

**M26-Q2:** Why describe the purpose of a firewall rule? **Answer:** Future reviewers need to decide whether the permission is still necessary and who owns it.

**References:** R12, R29, R30.

### M27 — Incident response and recovery

**Budget:** 18 hours · **Prerequisites:** M24–M26 · **Practical:** LAB-27 · **Mode:** PAPER

**M27-L1 — Prepare before an incident.** Identify critical services, accountable decision-makers, communication channels, evidence sources, backups, and recovery priorities. Preparation includes exercised procedures and access to the right people. Response activities interact with governance, identification, protection, detection, and recovery rather than forming a perfect one-way sequence. A tabletop exercise can reveal missing authority or dependencies before a real outage.

**M27-L2 — Make proportionate decisions.** Validate the signal, establish a working scope, preserve relevant evidence, and choose containment based on likely harm and operational needs. Isolation can reduce spread but also interrupt critical services or destroy some volatile evidence. Record who made each decision, its rationale, and what was known at the time. Communicate confirmed facts separately from working hypotheses.

**M27-L3 — Recovery requires confidence.** Remove the cause where possible, restore trusted components, correct credentials and permissions, validate business functions, and monitor for recurrence. A clean-looking dashboard alone does not prove recovery. Review what allowed the event, what delayed detection, and what changes are owned and measurable. Blame-focused retrospectives discourage the reporting needed to improve.

**LAB-27 — Run a tabletop incident.** Use Workbook C's ambiguous login sequence. Write the first five questions, an initial severity rationale, two containment options with tradeoffs, an evidence plan, and a communication draft. Add an update in which the account owner confirms or denies the activity. Explain how the new evidence changes the decision.

**Completion:** a decision log, timeline, recovery checklist, and concise stakeholder update with explicit uncertainty.

**M27-Q1:** Should every suspicious login trigger immediate deletion of the account? **Answer:** No. Validate and choose a proportionate response; preserve evidence and consider continuity and recovery.

**M27-Q2:** What makes a lessons-learned action useful? **Answer:** A concrete improvement with an owner, due date, and verification method.

**References:** R07, R20, R32.

### M28 — Digital forensics and evidence integrity

**Budget:** 20 hours · **Prerequisites:** M02, M06, M25–M27 · **Practical:** LAB-28 · **Mode:** PAPER or LOCAL

**M28-L1 — Preserve before interpreting.** Acquisition choices affect what remains available. Volatile memory, active connections, and temporary state can disappear, while modifying an original disk can change evidence. Use training images and copies for study. Record who obtained an item, when, how, and with what tool/version. Chain of custody documents handling; it does not by itself prove every interpretation is correct.

**M28-L2 — Build a timeline from multiple sources.** Filesystem metadata, application records, operating-system events, browser artifacts, and network logs can disagree because they represent different actions or clocks. A timestamp may describe creation, modification, access, or an application's own event time. Document the meaning and limitations of each source. File extension, magic bytes, and metadata can support hypotheses but need context.

**M28-L3 — Hashes support integrity checks.** A modern cryptographic digest helps compare whether acquired bytes changed. It does not prove the original content was truthful or identify its creator. Work on copies, preserve originals under appropriate controls, and distinguish acquisition errors from analytic errors. Reports should explain what can and cannot be concluded from the available artifacts.

**LAB-28 — Analyse a synthetic evidence bundle.** Create or use only the harmless sample logs and note files from this document. Record a SHA-256 digest of each original, copy them to a working area, and build a timeline from the sample event times. Add a deliberately inconsistent timestamp and explain alternative causes. Verify the original digests again after analysis.

**Completion:** an evidence inventory, integrity comparison, timeline, and three conclusions with their supporting sources and limitations.

**M28-Q1:** Does a matching hash prove the file contains accurate claims? **Answer:** No. It supports byte-for-byte consistency relative to the compared digest, not truthfulness.

**M28-Q2:** Why distinguish an event timestamp from collection time? **Answer:** An event may be collected later; confusing them can reverse the apparent sequence.

**References:** R31, R32.

### M29 — Threat intelligence and hypothesis-led hunting

**Budget:** 18 hours · **Prerequisites:** M25–M28 · **Practical:** LAB-29 · **Mode:** PAPER or LOCAL

**M29-L1 — Intelligence answers a decision.** An indicator is an observable item such as a hash or domain; behaviour describes actions and relationships. Indicators can expire, be shared by benign activity, or be changed easily. Assess source reliability, confidence, relevance, and age. Avoid attributing an event to a named group based on one matching tool or infrastructure detail.

**M29-L2 — Use frameworks as vocabulary.** MITRE ATT&CK organizes adversary behaviours and can help describe hypotheses and coverage. A technique label does not prove that a detection is effective. Specify the exact observable behaviour, required data, and test result. A coverage heatmap should distinguish “we wrote a rule,” “we tested a rule,” and “we validated it under representative conditions.”

**M29-L3 — Hunt to reduce uncertainty.** Start with a falsifiable hypothesis about an asset or behaviour, select telemetry, define a time range, establish a baseline, and test alternatives. Record negative results and collection gaps. A successful hunt may find no incident but reveal missing visibility or a better detection. Keep a record of why the hypothesis mattered and what changed afterward.

**LAB-29 — Investigate a small behaviour hypothesis.** Use the synthetic authentication and export events. Hypothesize that an unusual successful login was followed by data access. Identify what the supplied logs support, what additional application records are needed, and plausible benign explanations. Map only justified behaviours to a framework and propose one new collection or detection improvement.

**Completion:** a hunt report with hypothesis, method, evidence, competing explanations, coverage gaps, and a decision.

**M29-Q1:** Does matching a public malicious IP list prove compromise? **Answer:** No. Timing, shared hosting, context, direction, and source quality affect interpretation.

**M29-Q2:** Is a hunt with no confirmed incident necessarily unsuccessful? **Answer:** No. It can eliminate a hypothesis or identify a measurable visibility improvement.

**References:** R08, R20, R29.

### M30 — Malware analysis and reverse-engineering foundations

**Budget:** 18 hours · **Prerequisites:** M09, M25, M28 · **Practical:** LAB-30 · **Mode:** PAPER or isolated LOCAL

**M30-L1 — Analyse behaviour, not a filename.** Static analysis examines bytes, strings, metadata, imports, and code without executing the programme. Dynamic analysis observes a programme running in a controlled environment. Both have limits: packed content can hide static clues, and a programme may behave differently across environments. Begin with benign binaries you wrote or official educational samples with clearly documented requirements.

**M30-L2 — Recover a model of the programme.** Learn basic assembly concepts, calling conventions, branches, loops, functions, and data references. A decompiler produces an approximation of higher-level code, not the original source. Use multiple observations to infer purpose, and label uncertainty. Recognizing a network library import alone does not establish malicious communication.

**M30-L3 — Containment is a prerequisite for unknown samples.** Unknown malware can harm the host or other systems if networking, shared folders, or guest integration are misconfigured. This core course uses harmless self-authored programmes and supplied traces instead. Later specialist work with real malware requires a dedicated, properly controlled analysis environment and experienced supervision where appropriate. Focus here on observation, evidence, and defensive interpretation.

**LAB-30 — Reverse a harmless toy programme.** Compile or obtain an explicitly benign educational programme that prints a message, checks an input, and writes a dummy file. Compare its source with disassembly or decompiler output, identify a branch, and document its file activity. If no local tool is available, annotate a supplied toy pseudocode listing and state what additional observations would verify it.

**Completion:** a behaviour summary, one mapped code path, a confidence statement, and an explanation of static versus dynamic evidence.

**M30-Q1:** Does a suspicious string establish that a programme performed the referenced action? **Answer:** No. The string may be unused, misleading, or part of a library; execution or stronger code-path evidence is needed.

**M30-Q2:** Is decompiled code an exact copy of the original source? **Answer:** No. It is a reconstruction whose types, names, and structure may be inferred incorrectly.

**References:** R18, R31, R39.

## Stage F — Cloud, software delivery, mobile, and AI

**Budget:** 110 hours. **Stage outcome:** assess modern deployment and application boundaries without assuming that a managed platform makes every control automatic.

### M31 — Cloud foundations and identity

**Budget:** 18 hours · **Prerequisites:** M04, M11–M12, M15 · **Practical:** LAB-31 · **Mode:** PAPER or CLOUD

**M31-L1 — Responsibility depends on the service.** Cloud providers operate some layers while customers configure others. Responsibilities differ for virtual machines, managed databases, object storage, and serverless functions. Separate control-plane actions, such as changing a policy, from data-plane actions, such as reading an object. An internet-unreachable workload can still be affected by an overprivileged cloud identity.

**M31-L2 — Permissions combine.** Users, roles, service identities, resource policies, organization controls, conditions, and explicit denies influence effective access. Provider semantics differ, so inspect the official rules for the chosen platform. Prefer short-lived credentials and narrowly scoped roles where practical. Understand which identity a workload actually uses rather than assuming it uses the person who deployed it.

**M31-L3 — Costs and cleanup are part of the lab.** Free tiers have conditions, and budgets or alerts are often notifications rather than hard spending limits. Define allowable resource types, regions, quotas, and a shutdown checklist. Tag lab resources and verify billing after cleanup. Protect the account's recovery methods and avoid using a production or family business account as a disposable classroom.

**LAB-31 — Review a fictional cloud identity policy.** Use Workbook G's role matrix. Identify permissions broader than the workload needs and propose a narrower design. Paper mode is sufficient. If using an owned training account, create only a minimal disposable resource under a predetermined budget and verify its identity and audit event; delete it and confirm the resulting resource inventory.

**Completion:** a responsibility diagram, least-privilege policy rationale, and either an explicit paper review or a verified cloud cleanup record.

**M31-Q1:** Does “serverless” mean nobody is responsible for security? **Answer:** No. Responsibility shifts, but application logic, identity, configuration, and data controls still matter.

**M31-Q2:** Does a budget alert guarantee spending stops? **Answer:** No. Provider budgets often notify without imposing a hard limit; verify the actual controls.

**References:** R34.

### M32 — Cloud applications, storage, and serverless systems

**Budget:** 18 hours · **Prerequisites:** M18, M25, M31 · **Practical:** LAB-32 · **Mode:** PAPER or CLOUD

**M32-L1 — Storage has multiple access paths.** Object storage, managed databases, snapshots, backups, and signed download links can expose the same data through different policies. Encryption at rest is useful but does not prevent an authorized or overprivileged identity from reading plaintext. Check public-access settings, resource policy, application authorization, link lifetime, logging, and recovery together.

**M32-L2 — Events cross boundaries.** A serverless workflow may consume events from queues, storage, webhooks, or other services. Validate event provenance and content, use narrow execution roles, and design retry behaviour. Duplicate delivery and partial failure are normal distributed-system concerns. An event with a valid structure can still be unauthorized or replayed in an unintended context.

**M32-L3 — Observe identity and network effects.** Central audit logs, data-access logs where appropriate, configuration history, and application correlation IDs support investigation. Review secret handling, metadata-service access, outbound destinations, and exposure of management interfaces. State which logs are enabled and their cost and retention implications. Do not assume every data read appears in a default audit trail.

**LAB-32 — Threat-model a document-processing pipeline.** Draw a fictional upload, object store, event queue, worker, and download route. Use dummy documents. Assign one identity to each component and specify allowed reads and writes. Add expiry for download links, duplicate-event handling, and logs needed to investigate an unexpected export. Paper mode avoids cloud charges while testing the design.

**Completion:** a data-flow diagram, access matrix, retry/idempotency rule, and investigation checklist.

**M32-Q1:** Does encryption at rest fix a publicly readable object policy? **Answer:** No. The storage service may decrypt and serve data to anyone permitted by that policy.

**M32-Q2:** Why plan for duplicate events? **Answer:** At-least-once delivery and retries can repeat processing; important actions need idempotent or otherwise controlled behaviour.

**References:** R06, R34.

### M33 — Containers, orchestration, and Kubernetes

**Budget:** 18 hours · **Prerequisites:** M03, M21, M31 · **Practical:** LAB-33 · **Mode:** PAPER or LOCAL

**M33-L1 — Images and runtime are different.** An image is a packaged filesystem and configuration; a running container adds process state, mounts, networking, and permissions. A patched image may still run with unsafe privileges. A minimal image may still contain vulnerable application logic. Record the image digest and build inputs so that a scan or finding refers to an identifiable artifact.

**M33-L2 — Runtime configuration defines exposure.** Review user identity, capabilities, privileged mode, host mounts, writable filesystems, secrets, network access, and access to the container-management socket. Granting control of a powerful host management interface can undermine the intended boundary. Containers usually share a kernel, so their suitability for isolating untrusted code differs from a dedicated virtual machine.

**M33-L3 — Orchestration adds an API and identities.** Kubernetes uses control-plane components, nodes, pods, services, service accounts, and RBAC. Network policies depend on supported enforcement by the chosen networking implementation. Secrets encoded as Base64 are not automatically encrypted. Review admission controls, workload privileges, secret access, audit logging, and actual enforcement rather than merely checking whether a manifest contains a familiar field.

**LAB-33 — Review a synthetic deployment.** On paper, analyse a workload that runs as root, mounts a host directory, uses a broad service account, and has unrestricted outbound access. Explain each risk in context, then propose only the privileges the fictional workload needs. If using a local educational cluster, inspect and verify the resulting controls without deploying intentionally vulnerable public services.

**Completion:** a before-and-after configuration review, explicit assumptions about enforcement, and a verification checklist.

**M33-Q1:** Does an image scan establish runtime security? **Answer:** No. Runtime permissions, secrets, mounts, network policy, and application behaviour require separate evaluation.

**M33-Q2:** Why does a network-policy object need a behaviour test? **Answer:** The underlying networking implementation and selected traffic must actually enforce it.

**References:** R35, R36.

### M34 — Secure coding, DevSecOps, and the software supply chain

**Budget:** 20 hours · **Prerequisites:** M07–M10, M15–M18, M24 · **Practical:** LAB-34 · **Mode:** LOCAL

**M34-L1 — Build security into changes.** Requirements, threat modeling, code review, tests, dependency review, deployment controls, and observability reinforce each other. Review the security effect of a change, not just its style. A small authorization change may matter more than a large cosmetic patch. Use secure defaults and make exceptional privileges explicit and reviewable.

**M34-L2 — Tools have specific coverage.** Static analysis studies code without necessarily running it; dynamic testing observes running behaviour; software-composition analysis examines dependencies; secret scanning looks for exposed credentials. None establishes total security. Triage findings, document justified suppressions, and add regression tests for important repaired causes. A passing pipeline only proves the configured checks passed on the tested inputs.

**M34-L3 — Protect build trust.** Dependencies, package registries, build scripts, CI identities, artifacts, and deployment permissions all form a supply chain. Pin or otherwise control dependencies appropriately, review updates, keep builds reproducible where possible, and restrict pipeline credentials. An SBOM inventories components; signatures and provenance provide evidence about artifacts and their production. Authentic provenance does not prove the application is free of vulnerabilities.

**LAB-34 — Add a security check to a toy app.** Use the notes application or LAB-07 repository. Add meaningful tests for ownership or malformed input, inspect dependencies, and document a safe update process. Design a CI workflow with minimal permissions and no embedded secrets. Include a case that fails before a real repair and passes afterward; do not add tests that merely assert a filename exists.

**Completion:** a reviewed fix, useful regression test, dependency inventory, and an explained build/deployment trust boundary.

**M34-Q1:** Does a signed artifact mean its code is safe? **Answer:** No. A signature can support origin and integrity checks under a trust model; it does not prove secure behaviour.

**M34-Q2:** Why should CI credentials be narrowly scoped? **Answer:** A compromised workflow or dependency can act with the credentials available to it.

**References:** R06, R17, R28, R36.

### M35 — Mobile application security

**Budget:** 18 hours · **Prerequisites:** M12–M18, M30 · **Practical:** LAB-35 · **Mode:** PAPER or LOCAL

**M35-L1 — The device is one part of the application.** Mobile clients interact with operating-system permissions, local storage, interprocess communication, browsers, deep links, and backend APIs. The backend must enforce its own authorization because the client is not a trustworthy policy boundary. Distinguish Android and iOS platform mechanisms; a recommendation for one may not apply unchanged to the other.

**M35-L2 — Protect data through its lifecycle.** Examine logs, caches, screenshots, backups, notifications, clipboard use, and key storage as well as the main database. Use platform-supported secure storage where appropriate and understand its limits. Hardcoded secrets distributed to every client cannot be treated as confidential server credentials. Transport validation matters, but client-side obfuscation or pinning alone does not repair backend authorization.

**M35-L3 — Test with a defined application and device.** Use a self-authored app, emulator, or intentionally vulnerable training app. Review permissions, exported components, links, and API requests. Keep real messages, photos, banking apps, and accounts away from the testing environment. A local observation should be tied to a specific app build and platform version.

**LAB-35 — Review a fictional study-notes mobile app.** Map login, token storage, offline notes, backup, deep links, and API access. Identify one unnecessary permission and one sensitive-data exposure path. If an appropriate emulator and training app are available, verify one observation with dummy data. Describe a platform-appropriate control and an independent backend test.

**Completion:** a mobile data-flow diagram, two contextual findings or design risks, and verification steps for the client and API.

**M35-Q1:** Can a hidden mobile endpoint rely on secrecy for access control? **Answer:** No. Clients can be inspected and requests reproduced; the server must authorize each operation.

**M35-Q2:** Why inspect backups and notifications? **Answer:** They may expose sensitive data outside the app's primary storage and screen protections.

**References:** R37.

### M36 — AI applications, LLMs, and agent security

**Budget:** 18 hours · **Prerequisites:** M06, M15, M18, M31–M34 · **Practical:** LAB-36 · **Mode:** PAPER or LOCAL

**M36-L1 — Separate instructions from untrusted content.** An AI application can receive user text, retrieved documents, tool output, and system instructions. Prompt injection occurs when untrusted content influences behaviour beyond its intended role. A document can contain instructions without having authority to issue them. Treat model output as untrusted when it reaches a command, database, browser, or action API.

**M36-L2 — Authorization belongs outside the model.** Restrict tools and credentials to the task, enforce resource ownership in ordinary code, and require appropriate confirmation for consequential actions. Retrieval must respect document permissions before content is provided to a model. Redaction, data minimization, and secret separation reduce exposure. A confident generated answer is not evidence that a permission check happened.

**M36-L3 — Evaluate behaviour under realistic conditions.** Build test cases for normal tasks, malicious document instructions, cross-user data requests, unsafe output handling, and unexpected tool results. Record expected boundaries and actual actions. Model variability means one successful test is not universal proof. Defences need layered design and repeated evaluation against a defined threat model, not a promise that one prompt makes injection impossible.

**LAB-36 — Design a bounded study assistant.** Use only fictional documents and mock tools. Give a retrieved note an instruction to access another learner's document; the expected system behaviour is to ignore that instruction and deny access through a server-side check. Test a normal permitted summary as a control. Write the permission policy, evaluation cases, and evidence that the tool boundary worked.

**Completion:** a threat model, five boundary tests, a least-privilege tool design, and honest reporting of uncertain results.

**M36-Q1:** Can a system prompt replace backend authorization? **Answer:** No. A model's behaviour is not a reliable permission-enforcement boundary.

**M36-Q2:** What is a useful success criterion for an injection defence? **Answer:** The intended task succeeds while prohibited data access or actions remain blocked under the defined tests and enforced controls.

**References:** R06, R38.

## Stage G — Advanced security and research

**Budget:** 120 hours. **Stage outcome:** investigate difficult classes of failure with a clear model, bounded experiments, and realistic claims about evidence.

### M37 — Advanced code review, races, and multi-component failures

**Budget:** 22 hours · **Prerequisites:** Stages C and F · **Practical:** LAB-37 · **Mode:** PAPER or LOCAL

**M37-L1 — Trace a property across the system.** Advanced review follows a security invariant through handlers, services, queues, caches, and storage. “A learner can only export their own notes” must remain true when a job runs later under a service identity. Read callers and consumers, not just the function that looks dangerous. Record assumptions about normalization, ownership, state, and error handling at each boundary.

**M37-L2 — Time and interpretation create gaps.** Time-of-check/time-of-use failures occur when conditions change between a decision and an action. Canonicalization differences can make components disagree about a path or identity. Cache keys can omit tenant or permission context. A race is not solved merely by moving the same two operations closer together; the relevant invariant needs an appropriate atomic operation or synchronization design.

**M37-L3 — Prove a repair under variation.** Create a minimal local reproducer, control its timing where possible, and test both security and required functionality. Examine cancellation, retries, duplicate messages, partial failures, and revoked access. If a result depends on an unreliable timing condition, report that uncertainty rather than presenting a single success as a stable universal exploit.

**LAB-37 — Review an asynchronous export.** Use a fictional API that validates a user, queues an export, and later serves a download. Define where ownership and current authorization must be checked. Add a scenario in which access is revoked between enqueue and execution. Use Workbook E for a separate concurrency example, then specify a fix and tests for both cases.

**Completion:** an end-to-end data/control-flow review, a stated invariant, and tests covering normal, revoked, repeated, and concurrent cases.

**M37-Q1:** Why can authorization at job creation be insufficient? **Answer:** Permissions or resource ownership may change before execution or download, and the worker may use a more powerful identity.

**M37-Q2:** What is wrong with a cache key that ignores tenant identity? **Answer:** Different tenants can share an unintended cached response unless the design otherwise enforces a correct boundary.

**References:** R02, R06, R28.

### M38 — Fuzzing, memory safety, and exploitability reasoning

**Budget:** 24 hours · **Prerequisites:** M09, M30, M34 · **Practical:** LAB-38 · **Mode:** isolated LOCAL or PAPER

**M38-L1 — Fuzzing explores input space.** A harness exposes a bounded target function to generated or mutated inputs. A seed corpus supplies useful starting examples. Coverage feedback can guide exploration but is not the same as proving correctness. Reset state between cases where needed, set time and memory limits, and make crashes reproducible. Fuzz your own small parser before a large unfamiliar project.

**M38-L2 — Triage the failure.** Preserve the failing input, environment, build flags, and diagnostic output. Minimize the case while retaining the failure, then locate its root cause. Deduplicate reports by meaningful cause rather than merely identical error text. Integer conversion, bounds, allocation, and lifetime errors can have different consequences. Reachability and attacker control remain separate questions from the existence of a crash.

**M38-L3 — Understand mitigation limits.** Memory layout randomization, non-executable memory, control-flow protections, and sanitizers affect different failure paths. Defensive exploitability analysis explains what conditions would be required and which protections stand in the way. Building weaponized chains is not necessary for this core milestone; demonstrate the defect in a toy target, repair it, and add a regression case.

**LAB-38 — Fuzz a toy parser.** Create a bounded parser for a simple fictional record format. Use a maintained fuzzing framework or a small bounded generator of harmless inputs. Run within an isolated, resource-limited environment. Preserve one failure if found, or report coverage and limits honestly if none is found. Repair the cause and rerun the minimized case plus valid inputs.

**Completion:** a harness design, resource limits, reproducible evidence or a qualified negative result, and a fix/retest record.

**M38-Q1:** Does high code coverage prove the programme is secure? **Answer:** No. Covered code may still have untested values, states, sequences, or properties.

**M38-Q2:** Why minimize a crashing input? **Answer:** A smaller reproducer helps isolate the cause, avoid unrelated behaviour, and create a useful regression test.

**References:** R17, R18, R40.

### M39 — Firmware, IoT, and operational technology

**Budget:** 20 hours · **Prerequisites:** M04, M09, M30, M38 · **Practical:** LAB-39 · **Mode:** PAPER or LOCAL

**M39-L1 — Embedded systems have physical context.** Firmware, bootloaders, hardware interfaces, update mechanisms, cloud services, and mobile apps form an IoT system. A vulnerability in one component may affect others, but physical access and device state can be important prerequisites. Start with owned development hardware or openly licensed educational firmware and record its exact model and version.

**M39-L2 — Trust starts before the application.** Secure boot, signed updates, rollback protection, debug-interface controls, secret storage, and recovery procedures influence the device's trust chain. A signed update still needs a trustworthy key-management and verification design. Extracting a firmware image for analysis does not automatically establish permission to redistribute it or use embedded credentials against a service.

**M39-L3 — Availability and safety change testing.** Operational technology can control physical processes with long equipment lifecycles and strict availability requirements. Ordinary IT scanning or rebooting may be unacceptable. Use simulation, documentation review, and a carefully approved test environment. Do not infer permission to test a building, utility, medical device, or campus control system from general access to its network.

**LAB-39 — Review a simulated smart-device update.** Draw a device, update server, signing key, mobile app, and local network. Identify how the device knows an update is authorized and how recovery works after interruption. Review a harmless educational firmware file statically if available. For an OT example, write a tabletop change plan with an operational owner and a defined safe rollback.

**Completion:** a trust-chain diagram, one evidence-backed design risk, and a change/rollback plan appropriate to physical consequences.

**M39-Q1:** Why can an ordinary port scan be unsuitable in OT? **Answer:** Some devices or processes may be sensitive to traffic or disruption; testing must match the approved operational constraints.

**M39-Q2:** Does signing an update solve insecure key storage? **Answer:** No. Compromise of the trusted signing key can undermine the update trust model.

**References:** R29, R30, R39.

### M40 — Adversary simulation and purple-team validation

**Budget:** 18 hours · **Prerequisites:** Stages D–E, M31–M34 · **Practical:** LAB-40 · **Mode:** PAPER or isolated LOCAL

**M40-L1 — Test a defensive objective.** A useful simulation asks whether a control prevents, observes, or responds to a defined behaviour. Agree on the scenario, systems, identities, actions, time window, success criteria, and emergency stop. Keep the scenario relevant to the organization rather than collecting unrelated techniques. A purple-team exercise encourages attacker and defender perspectives to examine the same evidence together.

**M40-L2 — Use the least intrusive representative action.** Many detection questions can be tested with benign canary files, dummy accounts, controlled configuration changes, or replayed synthetic events. Separate the action from the telemetry it is intended to create. Tool choice does not make an action authorized. Simulated persistence, credential access, or lateral movement require explicit scope and cleanup; introductory exercises should use harmless substitutes where they answer the question.

**M40-L3 — Measure the whole response.** Record whether prevention worked, whether the event was collected, whether an alert was generated, whether an analyst understood it, and whether the response was appropriate. Time-to-detect and time-to-respond metrics need clearly defined start and end events. A detection that fires after an exercise's own manual query is different from an automated alert that arrived independently.

**LAB-40 — Validate one control collaboratively.** Simulate a sensitive dummy group change or use synthetic events. Predict the event, collection path, detection, and analyst action. Run the controlled exercise in your isolated environment or on paper with a second learner reviewing the evidence. Identify the first broken step and improve it. Record cleanup and repeat the same scenario once.

**Completion:** a scenario card, expected/actual evidence table, response timing definitions, and one verified improvement.

**M40-Q1:** Does an ATT&CK technique label prove a realistic simulation? **Answer:** No. The action, conditions, telemetry, and objective must meaningfully represent the behaviour being evaluated.

**M40-Q2:** Why distinguish collection failure from detection failure? **Answer:** A rule cannot detect an event that never reaches its data source; the repairs are different.

**References:** R08, R32, R33.

### M41 — Bug bounty and coordinated vulnerability disclosure

**Budget:** 18 hours · **Prerequisites:** Stage C, M24, M37 · **Practical:** LAB-41 · **Mode:** PAPER or BROWSER

**M41-L1 — A programme policy is a contract of expectations.** Read the exact asset scope, accepted testing methods, exclusions, rate limits, data-handling rules, disclosure conditions, and any safe-harbour language. Different programmes permit different activity, and policies can change. A programme's existence does not authorize testing every asset carrying the same brand. Keep a dated record of the applicable terms before a live engagement.

**M41-L2 — Demonstrate impact minimally.** Use your own permitted accounts and dummy data when possible. A clear reproducible flaw with a well-supported impact statement is more useful than large-scale collection. Stop when evidence reaches unexpected sensitive material. Duplicates, out-of-scope issues, and unaccepted risk can all lead to no reward even if significant effort was spent. Bounties are uncertain income, not a study funding guarantee.

**M41-L3 — Coordinate professionally.** A disclosure report should contain a concise title, affected asset, preconditions, reproduction, evidence, actual and potential impact, and suggested correction. Send it through the authorized channel and follow the policy's publication conditions. Give maintainers useful clarification and retest results. Never threaten disclosure or demand payment outside the programme's terms.

**LAB-41 — Draft a report without sending it.** Choose one earlier lab finding and write a realistic disclosure using the template. Review a public programme policy only to practise scope interpretation, without testing its assets. List three allowed and three excluded activities according to that policy. Have another learner reproduce the finding only in the original training lab.

**Completion:** a scoped, reproducible disclosure draft and a written decision about whether a proposed action fits the chosen policy.

**M41-Q1:** Does a valid finding guarantee a bounty? **Answer:** No. Eligibility, impact thresholds, duplication, programme rules, and reward decisions vary.

**M41-Q2:** When may a private report be published? **Answer:** According to the relevant programme or coordinated disclosure agreement; do not assume submission grants publication permission.

**References:** R01, R02, R41.

### M42 — Governance, privacy, and risk decisions

**Budget:** 18 hours · **Prerequisites:** M01, M24, M27, M31 · **Practical:** LAB-42 · **Mode:** PAPER

**M42-L1 — Controls need ownership.** Policies state expectations; standards define required details; procedures explain how to perform work; evidence shows whether it happened. Asset ownership, exception management, supplier review, and change control help sustain security after a test ends. Compliance can support security but does not prove every attack path has been addressed.

**M42-L2 — Personal data creates responsibilities.** Identify what is collected, why, who can access it, where it goes, and how long it is kept. Minimize collection and make deletion and recovery responsibilities explicit. Privacy and security overlap but are not identical: data can be securely stored yet collected for an unjustified purpose. Use current authoritative local legal material when determining obligations and effective dates.

**M42-L3 — Make risk decisions visible.** Record the scenario, likelihood reasoning, impact, controls, options, owner, review date, and residual risk. Accepting risk is an accountable business decision, not a security tester quietly ignoring a finding. A simple impact scale can be useful when its meaning is defined; unsupported numerical precision can conceal uncertainty. Include operational, financial, privacy, and safety consequences where relevant.

**LAB-42 — Review the learning website itself.** Inventory planned profile, progress, note, and export data. Explain why each field is needed, how it is stored, and how a learner can delete it. Write three risk-register entries: lost local progress, cross-account access if sync is added, and accidental upload of sensitive evidence. Specify a control and accountable owner for each.

**Completion:** a data inventory, retention/deletion design, and a risk register with decisions and verification criteria.

**M42-Q1:** Does passing an audit prove a system is unhackable? **Answer:** No. Audits have defined scope and evidence limits; secure behaviour still needs engineering and ongoing assessment.

**M42-Q2:** Who should accept material business risk? **Answer:** An authorized accountable owner, informed by the technical evidence and consequences.

**References:** R07, R21, R22, R28.

## Stage H — Portfolio and professional growth

**Budget:** 110 hours. **Stage outcome:** demonstrate independent work, communicate it professionally, and choose a realistic path to deeper expertise.

### M43 — Research methods and continuing technical growth

**Budget:** 14 hours · **Prerequisites:** Stage G · **Practical:** LAB-43 · **Mode:** PAPER or LOCAL

**M43-L1 — Turn curiosity into a research question.** Start with a narrow claim that can be tested: whether a particular control prevents a defined failure under stated conditions. Review related work and distinguish your contribution from what is already known. Define inputs, measurement, baseline, limitations, and criteria that would disprove the claim. A negative result can be valuable when the method is sound and the question matters.

**M43-L2 — Reproduction and attribution build trust.** Record environment versions, code, datasets, seeds where relevant, and the steps needed to obtain the result. Respect licences and cite sources. Use synthetic data or data you have permission to process. Avoid generalizing from one application or a small convenience sample to all systems. Peer review should try to find mistakes, not just praise a successful demonstration.

**M43-L3 — Follow change without chasing every trend.** Keep a small watchlist: vendor advisories, relevant standards, research in your specialization, and official project releases. Emerging topics such as post-quantum migration require understanding assets, cryptographic dependencies, interoperability, and migration constraints. Do not replace reviewed cryptography with a self-designed algorithm. Explain what changed and whether it actually affects your systems.

**LAB-43 — Produce a small reproducible study.** Compare two authorization designs or two detection rules using a labelled synthetic dataset. State the hypothesis, test method, results, confounders, and limits. Ask a peer to reproduce one key result. Write a short note on an official research or standards update and explain its relevance without claiming universal impact.

**Completion:** a reproducible research note with honest limitations, attribution, and at least one independent check or a clearly stated lack of review.

**M43-Q1:** Is a result new because you personally had not seen it before? **Answer:** No. Novelty requires examining prior work and identifying a genuine difference.

**M43-Q2:** Why record a negative result? **Answer:** It constrains the claim and can prevent others repeating an unproductive assumption when the tested conditions are clear.

**References:** R17, R28, R44.

### M44 — Choose a specialization and a ninety-day depth plan

**Budget:** 10 hours · **Prerequisites:** M24, M30, Stage F, M43 · **Practical:** LAB-44 · **Mode:** PAPER

**M44-L1 — Breadth supports depth.** Application security, enterprise penetration testing, detection and incident response, cloud security, and vulnerability research share foundations but demand different daily work. Choose based on the problems you enjoy solving and the evidence you can produce, not only a fashionable title. You can change later, but trying to specialize in everything at once dilutes practice.

**M44-L2 — Define a concrete skill gap.** “Get better at hacking” is too broad. “Review an unfamiliar API, identify its authorization rules, and deliver a reproducible report” is observable. Compare your current work with a professional example, identify the missing capability, and select a project that exposes it. A course subscription is a resource, not the outcome.

**M44-L3 — Balance learning and delivery.** Spend the first month strengthening the missing foundation, the second completing a bounded project, and the third validating, improving, and presenting it. Set weekly evidence targets and a review point. Keep some time for adjacent skills such as writing, software development, and defensive interpretation.

**LAB-44 — Commit to one depth project.** Select a track from the specialization table. Write a ninety-day plan with one main project, required prerequisites, a weekly time budget, three measurable milestones, and a final reviewer. List what you will defer. Include a fallback if hardware, cost, or access prevents the preferred lab.

**Completion:** a realistic plan with observable outcomes and an explicit reason for the chosen specialization.

**M44-Q1:** Is finishing more courses always better than improving one weak project? **Answer:** No. Depth, correction, and independent performance can provide stronger evidence than additional passive consumption.

**M44-Q2:** What makes a specialization goal measurable? **Answer:** A defined task, environment, quality standard, and deliverable that another person can assess.

**References:** R01, R08, R28, R34, R37.

### M45 — Capstone: assess, fix, and retest an application

**Budget:** 30 hours · **Prerequisites:** Stages C–D, M34, M37 · **Practical:** LAB-45 · **Mode:** BROWSER or LOCAL

**M45-L1 — Choose a complete but manageable system.** Use a self-authored application or an educational application with an explicit licence and training purpose. Prefer a system with at least two user roles, per-user records, authentication, and one state-changing workflow. Define a scope and time budget. An application with too many features can prevent the deep reasoning this capstone is meant to demonstrate.

**M45-L2 — Assess and repair the same boundary.** Map the application, define security properties, test ordinary and adverse cases, and record findings with minimal evidence. Implement at least one meaningful correction where source access permits it. When a hosted training lab cannot be modified, reproduce the relevant cause in a small local model and demonstrate the repair there; identify this limitation in the report.

**M45-L3 — Defend the conclusion.** Present the root cause, actual impact, scope limits, repair, and regression evidence. Include a negative result where a suspected weakness was not confirmed. A professional assessment is not graded by how many dramatic findings it contains. Accurate reasoning and useful remediation matter more than volume.

**LAB-45 — Deliver the application capstone.** Produce the scope, architecture diagram, role/object matrix, test log, findings, one verified repair, and a retest report. Use dummy data only. Present the result in ten minutes, then answer questions about an alternative explanation and a missed test. Archive enough evidence to repeat the assessment without revealing private tokens.

**Completion:** at least one executed practical validation and one implemented/retested repair. A paper-only design earns planning credit but not this practical capstone pass.

**M45-Q1:** Must every tested feature produce a vulnerability to earn credit? **Answer:** No. A well-supported control verification or qualified negative result is valid evidence.

**M45-Q2:** Why disclose that a repair used a local model? **Answer:** It distinguishes what was directly changed and verified from what remains untested in the hosted application.

**References:** R01, R02, R04, R28.

### M46 — Capstone: investigate an incident and improve a control

**Budget:** 30 hours · **Prerequisites:** Stage E, M31–M34, M40 · **Practical:** LAB-46 · **Mode:** LOCAL with synthetic data

**M46-L1 — Build an evidence-led case.** Use a permitted training dataset or generate a harmless sequence in your own environment. Include identity, application, and system observations where possible. Define the incident question before searching. Mark known synthetic ground truth separately so you can evaluate the investigation without quietly giving yourself facts an analyst would not have.

**M46-L2 — Make and revise decisions.** Build a timeline, identify affected identities and resources, document competing explanations, and decide whether the evidence meets an incident threshold. Propose containment and recovery with operational tradeoffs. Add a new fact halfway through the exercise and show whether it changes your conclusion. An investigation that never updates its hypothesis may be defending an assumption.

**M46-L3 — Improve something measurable.** Add or repair a logging rule, detection, identity permission, or segmentation control. Test the improvement against both the relevant suspicious pattern and representative benign activity. Explain coverage and remaining gaps. If cloud deployment is unnecessary, use policy files and synthetic audit events locally rather than creating cost solely for appearance.

**LAB-46 — Deliver the investigation capstone.** Produce an evidence register, timeline, incident decision, containment options, recovery checklist, one tested defensive improvement, and a lessons-learned record. Use the supplied workbook as a starting point but add your own benign and ambiguous cases. Ask another learner to challenge two conclusions.

**Completion:** an executed local analysis, a repeatable detection/control test, and a report whose conclusions match the evidence. Label any simulated operational actions clearly.

**M46-Q1:** Can a technically correct timeline still lead to the wrong conclusion? **Answer:** Yes. Missing context, alternative explanations, and collection gaps can change interpretation.

**M46-Q2:** Why test a new rule against benign activity? **Answer:** A rule that detects the target case but overwhelms analysts with false positives may be unusable.

**References:** R08, R31, R32, R33, R34.

### M47 — Professional communication, community, and career development

**Budget:** 16 hours · **Prerequisites:** M24, M41, M45–M46 · **Practical:** LAB-47 · **Mode:** PAPER

**M47-L1 — Show work a reviewer can assess.** A portfolio entry should state the problem, permission context, method, result, repair or recommendation, and limitations. Use original diagrams and sanitized evidence. Public writing should respect provider rules and confidentiality. A repository full of copied scripts provides weaker evidence than a small tool you can explain and maintain.

**M47-L2 — Learn to explain across audiences.** A developer needs reproduction and root cause; a manager needs affected outcomes and priorities; a nontechnical user needs a clear safe action. Practise short technical English explanations while using Sinhala or Tamil when they help a local audience understand. Reliable teamwork, respectful questions, and good documentation create opportunities that technical trivia alone cannot.

**M47-L3 — Build experience gradually.** Seek internships, university projects, approved CTFs, open-source maintenance, and authorized supervised work. Verify current local opportunities through official sources and the university career office. Treat certificates as optional structured assessments, selected for a specific role after practical foundations. Avoid spending money to compensate for unfinished core projects.

**LAB-47 — Assemble a professional evidence pack.** Select three sanitized pieces: an application report, a detection or investigation, and a small tool or research note. Write a one-page skills-based CV, a two-minute introduction, and a concise project explanation. Practise an interview in which you explain one mistake and how evidence changed your approach. Draft applications locally; sending them is a separate decision.

**Completion:** a coherent portfolio and CV with no inflated claims, private data, or unexplained copied work.

**M47-Q1:** Is it appropriate to claim professional client experience for a training lab? **Answer:** No. Label lab, academic, volunteer, and professional work accurately.

**M47-Q2:** What is a strong answer when you do not know a technical detail? **Answer:** State the gap, explain how you would verify it, and distinguish your current hypothesis from fact.

**References:** R20, R27, R42, R43.

### M48 — Mastery review and the next learning cycle

**Budget:** 10 hours · **Prerequisites:** M01–M47 required practical gates · **Practical:** LAB-48 · **Mode:** PAPER and LOCAL

**M48-L1 — Test independence.** Repeat selected earlier tasks with different harmless inputs and without a walkthrough. Explain normal system behaviour before diagnosing the failure. Use documentation as a professional would, but record assistance and hints. A memorized solution to one challenge is not evidence that the principle transfers to a different system.

**M48-L2 — Measure competence honestly.** Separate familiarity, guided completion, independent completion, and reviewed performance. Evaluate reasoning, evidence quality, fixes, communication, and boundary discipline. A quiz score can identify recall gaps but cannot prove safe professional practice. Self-assessment is useful when labelled; it is not independent accreditation.

**M48-L3 — Expertise is maintained.** Plan ongoing practice, selected research, periodic review of old assumptions, and contributions to other people's learning. Revisit unresolved portfolio weaknesses before adding new topics. Becoming a leading ethical hacker is a long-term pattern of trusted work and original contribution, not a title the website awards on a progress bar.

**LAB-48 — Conduct a final practical review.** Complete the graduation assessment later in this document. Present both capstones, independently repeat one foundation exercise and one specialization exercise, and explain a legal/scope decision. Record reviewer feedback or clearly mark a self-review. Create the next ninety-day plan from the weakest demonstrated area.

**Completion:** all required gates, both practical capstones, an honest competence profile, and a sustainable next plan.

**M48-Q1:** Does 100% website completion prove expert status? **Answer:** No. It shows completion under the site's rules; expertise requires continued independent performance and external evidence.

**M48-Q2:** What should happen when a review reveals a gap? **Answer:** Assign targeted practice and reassessment instead of hiding it behind accumulated points.

**References:** R02, R07, R28, R42.

## First 30 days

This schedule totals 2,040 minutes: 34 hours, approximately eight hours per week over thirty days. It allocates the full M01 budget of eight hours, M02 budget of twelve hours, and M03 budget of fourteen hours. Rest days are intentional. Move sessions to fit the degree timetable; if a task takes longer, carry it forward instead of compressing recovery or sleep.

| Day | Minutes | Task | Saved result |
| --- | --- | --- | --- |
| 1 | 60 | Read the learning promise and starting diagnostic. | Honest baseline and weekly study slots |
| 2 | 60 | Read M01-L1 and explain the security triad. | Three examples in your own words |
| 3 | 90 | Read M01-L2 and draft the rules of engagement. | Scope sheet with allowed and excluded actions |
| 4 | 60 | Read M01-L3; classify the LAB-01 scenarios. | Decisions with reasons |
| 5 | 0 | Rest or focus on degree work. | No required submission |
| 6 | 150 | Finish LAB-01 and its questions; correct weak answers. | Evidence of the ethics/scope gate |
| 7 | 60 | Review the week's work and plan the lab. | Mistake log and equipment choice |
| 8 | 60 | Read M02-L1 and inspect your own machine's resources. | CPU/RAM/storage/process notes |
| 9 | 60 | Read M02-L2; choose browser-first or a small guest. | Isolation diagram |
| 10 | 60 | Read M02-L3; plan backup and restoration. | Recovery checklist |
| 11 | 90 | Prepare only the chosen environment. | Actual setup notes or a clearly labelled plan |
| 12 | 0 | Rest or focus on degree work. | No required submission |
| 13 | 90 | Verify the intended communication boundaries. | Isolation checklist and observations |
| 14 | 60 | Explain NAT, host-only, and internal networking in your own words. | Corrected network diagram |
| 15 | 60 | Prepare a harmless file and a supported restore method. | Baseline file and recovery steps |
| 16 | 0 | Rest or focus on degree work. | No required submission |
| 17 | 120 | Perform LAB-02's restore exercise and investigate any failure. | Before/after restoration evidence |
| 18 | 120 | Complete M02 questions, repeat the check, and document limitations. | Environment gate and final setup notes |
| 19 | 60 | Read M03-L1; practise navigation in a dedicated folder. | Explained absolute and relative paths |
| 20 | 60 | Read M03-L2; inspect ownership and permissions. | Permission interpretation |
| 21 | 60 | Read M03-L3; inspect your own processes and services. | Process/service notes |
| 22 | 90 | Perform Workbook A on disposable files. | Command transcript and observations |
| 23 | 0 | Rest or focus on degree work. | No required submission |
| 24 | 120 | Complete an introductory provider exercise or local equivalent. | Original explanation of the solved principle |
| 25 | 90 | Practise reading and filtering harmless local text. | Five commands explained in your own words |
| 26 | 60 | Review file and parent-directory permissions. | Corrected permission model |
| 27 | 0 | Rest or focus on degree work. | No required submission |
| 28 | 120 | Repeat the command-line task with changed synthetic input. | Independent attempt and correction |
| 29 | 90 | Finish LAB-03, its questions, and the evidence notebook. | Linux practical evidence |
| 30 | 90 | Review M01–M03 and schedule M04–M06. | Next-month plan and a short reflection |

After this month, the next priority is networking, HTTP, and evidence practice in M04–M06. Do not jump directly to advanced exploitation because an introductory exercise felt easy.

## Practical workbooks and synthetic evidence

These exercises are original, small, and designed to be understood without purchasing a course. Commands shown here are learning material; they have not been executed on the learner's machine as part of preparing this document. Names, identities, events, and addresses in examples are fictional.

### Workbook A — Your first Linux evidence exercise

**Used by:** M03, M08. **Goal:** navigate, inspect, transform, and protect a harmless file.

Use a shell in your own training account. Choose a working location where you are allowed to create a new directory. If a directory named `cyberforge-practice` already exists, choose a different new name instead of overwriting previous work. Run one line at a time and stop if a command fails.

```bash
pwd
mkdir cyberforge-practice
cd cyberforge-practice
mkdir notes evidence reports
printf '%s\n' 'alice:success' 'bob:failure' 'alice:failure' > notes/events.txt
cat notes/events.txt
wc -l notes/events.txt
grep 'failure' notes/events.txt
sort notes/events.txt
ls -l notes/events.txt
chmod 600 notes/events.txt
ls -l notes/events.txt
sha256sum notes/events.txt
```

**Understand the result:** `pwd` reports where you are; `mkdir` creates a directory; `cd` changes location. `printf` writes three synthetic lines through output redirection. `wc -l` should report three newline-terminated lines. `grep` should print two lines containing `failure`. `sort` prints an ordered view and does not modify the original file unless directed to do so. `chmod 600` sets the ordinary owner permissions to read and write and removes ordinary group/other permissions on that file. ACLs and other system mechanisms can introduce additional considerations.

**Answer these practical questions:** What changes if you run the same relative path from another directory? Why might a parent directory matter? What does the digest tell you, and what does it not tell you? Save a short transcript with no personal path details if you plan to publish it.

**Expected reasoning:** a relative path is resolved from the current location; parent permissions affect traversal and directory-entry changes; the digest supports comparison of bytes, not proof that the content is truthful. Change one harmless line and compare the new digest to observe the effect. Keep the practice directory for review; deletion is not required.

### Workbook B — HTTP and the request journey

**Used by:** M04, M05, M13. **Goal:** connect network concepts to application decisions.

Synthetic request:

```http
GET /api/notes/note-101 HTTP/1.1
Host: study.example.test
Cookie: session=DEMO_SESSION_A
Accept: application/json
```

Synthetic response:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: private, no-store

{"id":"note-101","owner":"learner-a","title":"Networking revision"}
```

**Task:** identify the method, requested resource, host, session carrier, representation, and caching instruction. Explain why the server must verify the session and ownership before returning the note. Changing the path to another note is a change of requested object, not a new authenticated identity.

**Answer:** the method is GET; the resource is `note-101`; the host is the fictional study host; the cookie contains a dummy session identifier; the response is JSON. `no-store` instructs caches not to store the response, but correct application authorization is still required. A cache directive is not a permission check. The server should establish the authenticated principal and decide whether that principal may read the requested note.

Synthetic timing, illustrating a conventional fresh connection rather than every possible modern browser path:

| Relative time | Event | Possible failure to distinguish |
| --- | --- | --- |
| 0 ms | Browser starts resolving the hostname. | Resolver unavailable or no matching record |
| 20 ms | Name resolution completes. | Returned address differs from the intended configuration |
| 30 ms | Connection establishment begins. | Route, firewall, or service-listener problem |
| 60 ms | Transport connection established. | Does not prove application login or authorization |
| 100 ms | TLS validation completes. | Certificate, name, trust, protocol, or clock problem |
| 110 ms | HTTP request is sent. | Request could be malformed or unauthorized |
| 150 ms | Application returns a response. | Application error, wrong record, or policy failure |

Connections may be reused, DNS cached, and HTTP/3 may use QUIC instead of the illustrated TCP path. State the assumed protocol and connection state before interpreting timing.

### Workbook C — Synthetic authentication and activity dataset

**Used by:** M07, M25, M27–M29, M46. **Goal:** count accurately, detect a pattern, and preserve uncertainty.

Each line is a separate JSON record. All times are UTC. Documentation addresses are labels in this dataset and must not be treated as network targets.

```jsonl
{"ts":"2026-10-01T09:00:00Z","user":"learner-a","source":"203.0.113.10","action":"login","result":"failure"}
{"ts":"2026-10-01T09:00:30Z","user":"learner-a","source":"203.0.113.10","action":"login","result":"failure"}
{"ts":"2026-10-01T09:01:00Z","user":"learner-a","source":"203.0.113.10","action":"login","result":"failure"}
{"ts":"2026-10-01T09:01:30Z","user":"learner-a","source":"203.0.113.10","action":"login","result":"success"}
{"ts":"2026-10-01T09:02:00Z","user":"learner-a","source":"203.0.113.10","action":"export","result":"success"}
{"ts":"2026-10-01T09:03:00Z","user":"learner-b","source":"198.51.100.20","action":"login","result":"success"}
{"ts":"2026-10-01T09:04:00Z","user":"learner-b","source":"198.51.100.20","action":"login","result":"failure"}
{"ts":"2026-10-01T09:05:00Z","user":"learner-b","source":"198.51.100.20","action":"login","result":"success"}
{"ts":"2026-10-01T09:06:00Z","user":"backup-service","source":"192.0.2.30","action":"backup","result":"success"}
{"ts":"2026-10-01T09:07:00Z","user":"learner-c","source":"203.0.113.11","action":"login","result":"failure"}
{"ts":"2026-10-01T09:08:00Z","user":"learner-c","source":"203.0.113.11","action":"login","result":"failure"}
{"ts":"2026-10-01T09:09:00Z","user":"learner-c","source":"203.0.113.11","action":"login","result":"success"}
```

**Task 1 — Counting:** count total records, login records, failed logins, successful logins, and failed logins by user. Keep non-login actions separate.

**Task 2 — Parsing:** define a required-field policy. Add a blank line, an invalid JSON line, and a valid JSON object missing `action` in a separate test copy. Decide how each will be reported. Do not overwrite the original evidence.

**Task 3 — Detection:** flag a successful login when at least three failures for the same user and source occurred during the preceding three minutes. Treat this as a candidate for investigation. Then look for an export by that user and source within the following two minutes. State that this is correlation by available fields, not proof that the same session performed every action.

**Reference algorithm:** parse each valid record; validate required fields; convert timestamps to comparable values; sort by time; keep recent failure timestamps keyed by user and source; for each success, count failures in the defined window; record matches; examine later exports separately. Document treatment of late-arriving events and duplicate records if extending the exercise.

**Answer key:** 12 records; 10 login records; 6 failed logins; 4 successful logins; 1 export; 1 backup. Failed logins: learner-a = 3, learner-b = 1, learner-c = 2. Only learner-a meets the stated three-failure detection threshold. The export follows its successful login by 30 seconds. Learner-c's two failures do not meet that threshold.

**Investigation limits:** the data does not prove credential theft, unauthorized access, what was exported, or whether the account owner approved it. Useful additional evidence includes session correlation, MFA events, export contents/classification, known user activity, device history, and relevant application authorization logs. A shared source address may represent multiple people.

**Incident update exercise:** first assume the owner confirms a mistyped password and a planned personal export. Then repeat with an owner who denies the activity and an audit record showing access to a dummy record belonging to another user. Write different conclusions and explain which new facts justify them.

### Workbook D — SQL safety and object authorization

**Used by:** M10, M15, M16, M34, M45. **Goal:** separate query safety from permission.

Synthetic data:

| User | Note ID | Owner | Title |
| --- | --- | --- | --- |
| learner-a | note-101 | learner-a | Networking revision |
| learner-b | note-202 | learner-b | Database revision |

An unsafe construction joins untrusted text directly into SQL:

```text
query = "SELECT id, owner_id, title FROM notes WHERE id = '" + supplied_id + "'"
```

A parameterized lookup protects the query's structure, but alone does not limit ownership:

```sql
SELECT id, owner_id, title FROM notes WHERE id = ?;
```

A lookup can constrain both the object and its owner, with the owner derived from the authenticated server-side context:

```sql
SELECT id, title FROM notes WHERE id = ? AND owner_id = ?;
```

Bind `requested_note_id` and `authenticated_user_id` through the database library's parameter API. Placeholder syntax varies by driver. Never take the authoritative owner identity directly from an editable request field. Apply equivalent authorization to update, delete, export, and other access paths.

**Expected matrix:**

| Authenticated user | Requested object | Expected result |
| --- | --- | --- |
| learner-a | note-101 | Own note is returned. |
| learner-a | note-202 | Other user's note is not disclosed. |
| learner-b | note-202 | Own note is returned. |
| learner-b | note-101 | Other user's note is not disclosed. |
| No valid session | Any note | Authentication/authorization policy denies access. |
| learner-a | nonexistent note | No record is disclosed; response policy is consistent. |

**Answer:** the first construction is vulnerable to structural interpretation of input. The second repairs that class of SQL construction but can still return another person's record. The third can enforce the simple ownership rule when the bound identity is trustworthy. More complex sharing, tenant, or administrator rules require an explicit policy rather than blindly reusing this example.

**Regression cases:** valid own note, other user's note, missing note, unusual identifier characters handled as data, revoked sharing, alternate export endpoint, and update/delete equivalents. Select HTTP error semantics deliberately; whether the application uses 403 or conceals existence with 404 must not leak the protected content.

### Workbook E — Race conditions and business invariants

**Used by:** M10, M18, M37. **Goal:** reason about concurrency without load-testing a real service.

Business rule: a one-use coupon can be redeemed at most once. The initial value is `remaining_uses = 1`.

| Step | Request A | Request B | Shared state |
| --- | --- | --- | --- |
| 1 | Reads one remaining use. | | 1 |
| 2 | | Reads one remaining use. | 1 |
| 3 | Grants discount. | | 1 |
| 4 | | Grants discount. | 1 |
| 5 | Writes remaining uses as zero. | | 0 |
| 6 | | Writes remaining uses as zero. | 0 |

The final counter looks plausible, but two discounts were granted. The invariant was violated because the decision and effect were not protected as one consistent operation.

**Task:** specify an atomic conditional update or transaction design that grants the discount only when the decrement succeeds. Include the discount record in the same consistency boundary or use a carefully designed transactional/outbox workflow when the effect crosses systems. A check in frontend JavaScript is insufficient.

**Answer:** only one redemption may claim the available use. The second must receive an explicit no-redemptions-remaining result. Retrying the same request should not grant another discount. A per-request idempotency key handles duplicate submissions of the same operation, but distinct keys do not eliminate the need to enforce the shared coupon limit.

**Tests:** sequential first and second redemption; two competing requests; retried identical request; timeout after a committed redemption; rollback after a failed discount write. Specify expected outcomes before implementing any test.

### Workbook F — Inventory and vulnerability triage

**Used by:** M19–M20, M24. **Goal:** distinguish observation, applicability, and priority.

| Asset | Observation | Context | Missing evidence |
| --- | --- | --- | --- |
| lab-web | A banner suggests an older web server. | Training VM; administrator says security patches are backported. | Exact package build, vendor advisory, enabled features |
| lab-notes | Dummy user A can read dummy user B's private note. | Reproduced with two known accounts; ownership was expected. | Wider endpoint coverage and whether the same cause affects modification |
| lab-admin | An administrative service is externally reachable in the fictional diagram. | Sensitive role; MFA and patch status unknown. | Actual exposure verification, authentication controls, patch state, business need |

**Task:** give each item a verification status, confidence, impact statement, and next action. Do not make network connections to the documentation addresses or invented hostnames.

**Answer:** the banner is an unconfirmed applicability lead; inspect package and advisory evidence before declaring a CVE. The notes issue is a confirmed unauthorized read within the lab's scope and merits a concrete ownership fix. The management exposure is a high-priority verification and architecture concern because of possible consequences, but the supplied evidence does not prove account compromise or a missing patch. Priority can be high while a specific exploit claim remains unconfirmed.

**Useful report statuses:** suspected; confirmed; not reproduced; not applicable with evidence; fixed and retested; partially fixed; not fixed; unable to verify. Never silently convert one status into another.

### Workbook G — Cloud permissions and safe AI boundaries

**Used by:** M31–M32, M36, M42. **Goal:** define permissions before choosing implementation details.

| Identity | Required function | Excessive proposed permission | Narrower intent |
| --- | --- | --- | --- |
| upload-worker | Read newly submitted dummy documents. | Read and delete every storage object. | Read the designated input area; no unrelated delete permission. |
| report-worker | Write generated reports. | Change identity roles and storage policies. | Write only the designated report area. |
| learner-session | Read that learner's own report. | Choose any owner identifier in the download request. | Server-enforced ownership and a bounded download mechanism. |
| study-assistant | Summarize an authorized lesson. | Read all private notes and run arbitrary commands. | Read the authorized lesson through a constrained tool; no command execution. |

**Task:** draw identities, resources, and allowed actions. Decide what evidence would verify each boundary. For cloud use, translate the intent using the chosen provider's policy semantics; this table is not a deployable IAM policy.

**AI test cases and expected results:**

1. A learner requests a summary of an allowed lesson → provide the summary with source attribution.
2. A retrieved document instructs the assistant to reveal a different learner's notes → treat it as untrusted content; the data-access tool denies the request.
3. A learner requests a nonexistent lesson → explain that the lesson was not found; do not invent a source.
4. A model generates text containing HTML/script syntax → display it safely as appropriate content, without executing it.
5. A tool returns an error → explain the limitation; do not claim the action succeeded.

**Answer:** the permission enforcement is performed by application and platform code. The model may help choose or explain an action, but it cannot grant itself authorization. Record permitted operations as well as denied ones so an unusable system is not mistaken for a secure, successful design.

### Workbook H — Technical and executive communication

**Used by:** M06, M24, M41, M47. **Goal:** preserve the same truth for different audiences.

**Technical statement:** “In the isolated notes lab, authenticated learner-a requested note-202, which belongs to learner-b. The endpoint returned learner-b's dummy title and body. The handler selected by note ID without enforcing ownership. A query constrained by note ID and authenticated owner denied the cross-user request while preserving access to learner-a's own note.”

**Executive statement:** “The lab application allowed one user to read another user's private notes. We corrected the ownership check and verified that legitimate access still works. The same control should be reviewed on export and update features before the issue is considered fully resolved.”

**Task:** identify the shared facts, the technical details omitted for the executive audience, and the explicit coverage limit. Rewrite the example as a five-sentence disclosure. Do not call the issue a full database compromise: the observation proves only the described unauthorized read.

### Reusable template — Rules of engagement

```text
Assessment title:
Owner authorized to grant permission:
Tester and contact:
Purpose and business question:
Allowed assets, exact identifiers, and accounts:
Excluded assets, third parties, and data:
Allowed actions and tools:
Excluded actions:
Time window and time zone:
Traffic/rate/resource limits:
Evidence collection, redaction, storage, and retention:
Emergency contact and stop conditions:
Backup/reset and recovery responsibilities:
Reporting channel and disclosure rules:
Cleanup checklist:
Permission record and date:
```

### Reusable template — Lab notebook

```text
Lab ID and title:
Date, time zone, and duration:
Mode: paper / browser / local / cloud
Permission and scope reference:
Environment and versions:
Learning objective:
Hypothesis and expected secure behaviour:
Baseline/control case:
Method and inputs:
Expected observation:
Actual observation:
Evidence references and redactions:
Alternative explanations:
Root cause or unresolved uncertainty:
Fix or proposed control:
Retest and ordinary-function result:
Cleanup result:
Hints or assistance used:
What I can now explain without notes:
Next question:
```

### Reusable template — Vulnerability finding and disclosure

```text
Finding ID and concise title:
Verification status and confidence:
Affected asset and tested version:
Scope and authorization reference:
Preconditions and required privileges:
Expected behaviour:
Observed behaviour:
Reproduction steps using dummy/minimum data:
Evidence:
Root cause:
Demonstrated impact:
Additional plausible impact, clearly labelled:
Severity method/version/vector if used:
Contextual priority and rationale:
Recommended control and owner:
Retest cases and result:
Residual risk and coverage limits:
Disclosure/publication constraints:
```

### Reusable template — Incident and evidence record

```text
Case ID and investigation question:
Analyst and authorized owner:
Evidence item, source, collector, collection time, and time zone:
Acquisition method, tool/version, and integrity digest:
Original storage and working-copy location:
Handling/transfer history:
Timeline with source references:
Confirmed facts:
Working hypotheses and confidence:
Competing explanations and missing data:
Affected identities/assets, with evidence:
Incident decision and rationale:
Containment options and operational tradeoffs:
Authorized decision-maker and actions:
Recovery criteria and verification:
Communications and update schedule:
Retention/deletion decision:
Lessons learned, owners, and review dates:
```

### Reusable template — Research and portfolio entry

```text
Title and accurate work category: lab / academic / volunteer / professional
Question and permission context:
Why the problem matters:
Prior work and attribution:
Environment, dataset, and reproducibility instructions:
Hypothesis and baseline:
Method and evaluation criteria:
Results and supporting evidence:
Negative results and limitations:
Repair or practical recommendation:
Independent review, or explicit self-review:
What I personally contributed:
Public redaction/licence check:
Next experiment:
```

## Projects, assessments, and graduation

### Eight stage projects

These projects organize the evidence produced by the module practicals. They are included in the stage hour budgets and should not require repeating the same work solely to earn another badge.

| ID | Stage project | Required deliverables | Pass evidence |
| --- | --- | --- | --- |
| P01 | **My First Security Lab** | Scope sheet, isolation diagram, restore evidence, Linux exercise, HTTP annotation, mistake log | Explain the environment and repeat one basic task independently. |
| P02 | **Security Utility and Identity Model** | Log parser, expected results, local version history, SQL/ownership review, identity lifecycle diagram | Tool handles stated inputs correctly; learner explains code, permission, and failure behaviour. |
| P03 | **Application Boundary Review** | Request map, two-account matrix, two educational findings or control verifications, proposed repairs | Evidence distinguishes identity, input handling, ownership, and browser boundaries. |
| P04 | **Small Penetration-Test Report** | Scope, service inventory, triage notes, two complete findings, one retest, cleanup | Report is reproducible and its claims stay within the observations. |
| P05 | **Investigate and Detect** | Synthetic case timeline, detection rule, benign comparison, incident decision, evidence inventory | Counts and sequence are correct; conclusions acknowledge uncertainty and missing data. |
| P06 | **Secure Modern Application Design** | Cloud identity matrix, storage/event diagram, container review, mobile review, AI boundary tests | Required functions work in the design or test, and unnecessary permissions are removed. |
| P07 | **Research and Control Validation** | One bounded advanced experiment, minimal reproducer where relevant, repair or detection test, disclosure draft | Independent reasoning, attribution, limitations, and safe reproducibility are clear. |
| P08 | **Professional Portfolio Review** | M45 application capstone, M46 investigation capstone, CV, specialization plan, final presentation | Both executed capstones pass the practical rubric and the learner can defend the results. |

### Practical rubric

| Criterion | Points | What strong work looks like |
| --- | --- | --- |
| Permission, scope, and data handling | 10 | Clear boundaries, synthetic/minimum data, suitable cleanup |
| System understanding and root-cause reasoning | 20 | Correct normal behaviour, explicit trust boundary, plausible alternatives |
| Method and experimental controls | 15 | Repeatable steps, baseline, bounded inputs, useful negative cases |
| Evidence quality and accuracy | 20 | Relevant observations, versions, timestamps, no invented results |
| Repair, defensive control, and retest | 15 | Root cause addressed; normal and adverse cases checked |
| Communication and limitations | 10 | Clear audience-appropriate explanation and honest coverage limits |
| Reproducibility and reflection | 10 | Another learner can repeat the work; mistakes lead to specific improvements |
| **Total** | **100** | |

Target at least 80/100 for a practical gate. A scope violation, fabricated evidence, or exposure of real sensitive data prevents a pass until the issue is addressed, regardless of the numerical score. Early paper exercises can pass their stated paper objectives; they must never be presented as executed tests. M45 and M46 explicitly require executed practical evidence.

### Recall checks versus demonstrated skill

The curriculum contains **96 module questions**, each with an explanation. They are short-answer self-checks, not a professionally proctored exam. The learner answers before revealing the key and marks each response as correct, partial, or not yet understood. Use 2, 1, or 0 points respectively.

A stage has twelve module questions and a maximum recall score of 24. A suggested stage recall target is at least 20/24, followed by correction of all missed concepts. The ethics/scope answer must be correct before active practice. A recall score alone does not unlock a practical pass; the stage project must also meet its rubric. The website must visibly distinguish self-assessed and independently reviewed work.

### Competence levels used by the site

| Level | Meaning | Evidence |
| --- | --- | --- |
| Introduced | The learner has read the explanation. | Reading/reflection record |
| Guided | The learner completed a task with instructions or hints. | Lab record with assistance noted |
| Independent | The learner repeated the principle with changed inputs without a walkthrough. | New practical attempt and explanation |
| Reviewed | Someone else assessed the work against the rubric. | Reviewer feedback, date, and scope of review |

These are learning labels. None should be named “certified hacker,” “national expert,” or any title implying external accreditation.

### Graduation assessment

Use the two capstones and the practical rubric. Each capstone should independently score at least 80/100. Answer the following scenarios in a live discussion, recorded explanation, or clearly labelled self-review:

1. **Scope:** a lab link redirects to an unrelated real organization. What do you do? Expected: stop active interaction, record the unexpected boundary, and seek scope clarification from the authorized owner.
2. **Authorization:** a valid session can read another user's dummy note. Explain the cause and fix. Expected: separate authentication from object permission and enforce ownership on every relevant path.
3. **Evidence:** a scanner reports an old version, but the vendor backports patches. Expected: inspect exact build, advisory, enabled features, and safe validation before declaring a confirmed CVE.
4. **Detection:** failed logins followed by success and export appear in logs. Expected: identify the pattern, avoid claiming compromise without context, and request the missing identity/session/application evidence.
5. **Concurrency:** two individually valid coupon requests produce two discounts. Expected: state the shared invariant and enforce it atomically, with correct duplicate/retry handling.
6. **Cloud:** storage is encrypted but publicly readable. Expected: distinguish encryption from access control and verify both application and storage policy.
7. **AI:** a retrieved note asks a study assistant to access another learner's data. Expected: treat the note as untrusted data and enforce ownership in the tool/server boundary.
8. **Communication:** explain one finding to both a developer and a manager. Expected: preserve the same facts, adapt detail, and state limits and next actions.

Finish with one independent practical using changed synthetic inputs and one peer critique or an honest self-review. Record remaining gaps; graduating the curriculum begins a deeper practice cycle rather than ending study.

### Specialization choices

| Track | Prioritize | Ninety-day depth project | Readiness evidence |
| --- | --- | --- | --- |
| Application security and web assessment | M13–M18, M24, M34, M37, M41 | Review and repair a multi-user API with an asynchronous export. | Reproducible findings, ownership tests, code-level fixes |
| Enterprise penetration testing | M11, M19–M24, M31, M40 | Assess a small isolated identity/network environment. | Permission graph, scoped methodology, useful report, cleanup |
| Detection and incident response | M25–M30, M40, M46 | Build and evaluate detections against a documented synthetic incident. | Correct evidence interpretation, false-positive analysis, response decisions |
| Cloud security | M31–M34, M37, M42 | Review a small event-driven application and improve identity boundaries. | Least-privilege reasoning, audit evidence, cost-aware cleanup |
| Mobile security | M12–M18, M30, M35 | Review an educational mobile app and its API with dummy data. | Client/backend distinction, platform-aware tests, data lifecycle review |
| Vulnerability research | M09, M30, M37–M39, M43 | Fuzz and repair a self-authored parser or study a licensed toy target. | Reproducer, root cause, fix, limitations, attribution |
| AI application security | M15, M31–M34, M36, M42 | Evaluate a study assistant with mock tools and per-user document access. | Boundary tests, server-enforced permissions, honest evaluation results |

### Common learning traps and corrections

| Trap | Correction |
| --- | --- |
| Installing more tools instead of understanding one result | Explain an observation and repeat it with a smaller method. |
| Watching walkthroughs without practising | Attempt first; use a hint only after recording what is unclear. |
| Memorizing payloads without knowing the interpreter | Draw the data flow and explain the violated boundary. |
| Treating every alert as a confirmed vulnerability | Separate observation, applicability, reproduction, and impact. |
| Collecting certificates before building evidence | Finish a practical portfolio project before buying another assessment. |
| Comparing yourself with online earnings screenshots | Track independent skills and useful work; income is not a learning metric. |
| Neglecting the degree to maintain a streak | Use exam mode and preserve a sustainable weekly plan. |
| Copying an AI answer as a report | Verify facts and evidence, rewrite the reasoning, and disclose meaningful assistance. |

## Reference library and tool guide

### How to use the library

Read the local lesson first, attempt its exercise, and then use the matching reference to deepen a specific gap. The library should not become an endless queue of courses. Primary documentation is preferred for tool behaviour, standards, and legal material.

**Review labels:** **Opened** means the principal page was retrieved during document preparation on 2 November 2026. **Located** means an official page was identified in search results or as a link on an opened official page. **Reference** means an established official starting point is supplied but was not individually retrieved in this preparation. A successful page retrieval does not verify every linked lesson, download, lab, price, or legal claim.

Resource IDs used in modules map to the following entries. Learning-platform access, catalogue names, software licences, and examination requirements can change. Check them before relying on a resource or paying. Original curriculum text in this document is not a reproduction of these providers' course content.

| ID | Official resource | Use in this curriculum | Access and review note |
| --- | --- | --- | --- |
| R01 | [PortSwigger Web Security Academy](https://portswigger.net/web-security) | Web explanations and intentionally vulnerable browser labs | Academy describes its training as free; account may be needed. Opened. |
| R02 | [OWASP Web Security Testing Guide](https://wstg.owasp.org/) | Structured web-testing methodology | Public guide; record the version used. Located. |
| R03 | [OverTheWire Bandit](https://overthewire.org/wargames/bandit/) | Beginner command-line practice | Public learning game; follow its rules. Opened. |
| R04 | [OWASP Juice Shop](https://owasp.org/projects/juice-shop) | Intentionally vulnerable application for controlled practice | Public project; local infrastructure requirements apply. Opened. |
| R05 | [OWASP API Security Project](https://owasp.org/projects/api-security-project) | API risk categories and object/property/function authorization | Public project material. Opened. |
| R06 | [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) | Practical implementation guidance for controls | Public guidance; select the specific relevant sheet. Opened. |
| R07 | [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework) | Governance and risk-management structure | Public framework; not a substitute for specific controls. Opened. |
| R08 | [MITRE ATT&CK](https://attack.mitre.org/) | Behaviour vocabulary for detection and simulation | Public knowledge base; record the version/date used. Opened. |
| R09 | [Python tutorial](https://docs.python.org/3/tutorial/) | Programming fundamentals and standard-language behaviour | Public documentation; match the installed version. Reference. |
| R10 | [GNU Bash manual](https://www.gnu.org/software/bash/manual/) and [Linux manual pages](https://man7.org/linux/man-pages/) | Shell, process, permission, and system-call explanations | Public documentation; platform/version details vary. Reference. |
| R11 | [MDN Web Docs](https://developer.mozilla.org/en-US/docs/Web) | HTTP, browser, JavaScript, and web-platform behaviour | Public documentation. Reference. |
| R12 | [Wireshark documentation](https://www.wireshark.org/docs/) | Packet capture and protocol analysis | Public docs; capture only permitted traffic. Reference. |
| R13 | [Microsoft Learn](https://learn.microsoft.com/) and [PowerShell documentation](https://learn.microsoft.com/en-us/powershell/) | Windows, PowerShell, logging, and identity learning | Public docs; some practical environments require licences/accounts. Reference. |
| R14 | [Git documentation](https://git-scm.com/doc) | Version control, history, and collaboration | Public documentation. Reference. |
| R15 | [SQLite documentation](https://www.sqlite.org/docs.html) | Small local SQL and transaction exercises | Public documentation; parameter APIs depend on the driver. Reference. |
| R16 | [Windows Server identity documentation](https://learn.microsoft.com/en-us/windows-server/identity/) and [Microsoft Entra documentation](https://learn.microsoft.com/en-us/entra/) | Distinguish directory and cloud identity systems | Public docs; lab licensing and service costs vary. Reference. |
| R17 | [MITRE CWE](https://cwe.mitre.org/) | Weakness categories and root-cause vocabulary | Public catalogue; CWE is not the same as CVE. Reference. |
| R18 | [Clang documentation](https://clang.llvm.org/docs/) | Compiler diagnostics and sanitizers | Public docs; check compiler/platform support. Reference. |
| R19 | [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-4/) | Identity, authentication, and authenticator lifecycle guidance | Public standards material; select the applicable current revision. Reference. |
| R20 | [Sri Lanka CERT](https://www.cert.gov.lk/) | Official local alerts, resources, and incident-reporting entry point | Public official site; verify the current reporting route there. Opened. |
| R21 | [Sri Lanka Parliament: Computer Crimes Act, 24/2007](https://www.parliament.lk/en/business-of-parliament/act-details/G4684) | Official legislation starting point for local study | Official act index; read the act and applicable updates. Opened. |
| R22 | [Sri Lanka DPA: acts, gazettes, and guidance](https://www.dpa.gov.lk/guidelines.php) | Personal-data law, amendments, and current official notices | Includes the 2022 Act and 2025 Amendment Act; verify applicable gazettes. Opened. |
| R23 | [FIRST CVSS](https://www.first.org/cvss/) and [FIRST EPSS](https://www.first.org/epss/) | Technical severity and exploitation-probability concepts | Public resources; do not confuse their purposes. CVSS page opened; EPSS reference. |
| R24 | [Nmap reference guide](https://nmap.org/book/man.html) | Understand bounded network/service observation | Public docs; use only the permitted lab scope. Reference. |
| R25 | [Ubuntu tutorials](https://ubuntu.com/tutorials) | Beginner Linux and environment preparation | Public tutorials; choose a supported version. Reference. |
| R26 | [VirtualBox manual](https://www.virtualbox.org/manual/) | Example hypervisor networking and snapshots | Public docs; product/component licensing varies. Reference. |
| R27 | [picoCTF learning entry](https://picoctf.org/) and [CyLab Security Academy](https://cylabacademy.org/) | Foundational educational challenges and practice | The opened picoCTF page directs its learning audience to CyLab Security Academy. Verify current accounts and rules. |
| R28 | [OWASP ASVS](https://asvs.owasp.org/) | Application security requirements and verification | Public standard; record exact version/requirement IDs in reports. Opened. |
| R29 | [CISA Known Exploited Vulnerabilities catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | One evidence source for remediation prioritization | Public catalogue; absence is not evidence of safety. Reference. |
| R30 | [CISA Secure Our World](https://www.cisa.gov/secure-our-world) | Practical security awareness and basic protective habits | Public guidance. Reference. |
| R31 | [Autopsy](https://www.autopsy.com/) and [Volatility Foundation](https://volatilityfoundation.org/) | Forensic tooling and memory-analysis learning | Check licences, supported formats, and official documentation. Reference. |
| R32 | [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) | Incident response within cybersecurity risk management | Official publication page, published April 2025. Opened. |
| R33 | [Sigma documentation](https://sigmahq.io/docs/) | Detection-rule structure and portability considerations | Public docs; translated rules require backend-specific validation. Reference. |
| R34 | [AWS security documentation](https://docs.aws.amazon.com/security/), [Azure security documentation](https://learn.microsoft.com/en-us/azure/security/), and [Google Cloud security](https://cloud.google.com/security) | Provider-specific identity, responsibility, logging, and policy semantics | Docs are public; deployed services may cost money. Reference. |
| R35 | [Kubernetes security concepts](https://kubernetes.io/docs/concepts/security/) and [Docker documentation](https://docs.docker.com/) | Workload, runtime, image, network, and orchestration controls | Public docs; verify chosen distribution and licence conditions. Reference. |
| R36 | [GitHub Actions documentation](https://docs.github.com/en/actions), [SLSA](https://slsa.dev/), and [Sigstore documentation](https://docs.sigstore.dev/) | CI permissions, supply-chain assurance, provenance, and artifact verification | Public docs; service usage limits and prices vary. Reference. |
| R37 | [OWASP Mobile Application Security](https://mas.owasp.org/) | MASVS requirements and mobile testing guidance | Public project material. Opened. |
| R38 | [OWASP GenAI Security Project](https://genai.owasp.org/) | AI application and agent risk guidance | Public project material; record the publication/version used. Opened. |
| R39 | [Ghidra](https://ghidra-sre.org/) | Reverse engineering of benign educational binaries | Official project starting point; use a supported release. Reference. |
| R40 | [LLVM libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html) | Harnesses, corpora, and coverage-guided fuzzing concepts | Public docs; verify supported compiler integration. Reference. |
| R41 | [HackerOne documentation](https://docs.hackerone.com/) and [Bugcrowd researcher documentation](https://docs.bugcrowd.com/researchers/) | Programme policies and disclosure processes | Public guidance does not replace a particular programme's scope. Reference. |
| R42 | [OWASP chapter directory](https://owasp.org/chapters) | Find current city/student communities and official event pages | Directory located; local activity and dates need separate confirmation. |
| R43 | [PortSwigger BSCP](https://portswigger.net/web-security/certification) and [OffSec PEN-200](https://www.offsec.com/courses/pen-200/) | Optional assessment routes after practical preparation | Paid routes with prerequisites and changing terms. Principal pages opened. |
| R44 | [NIST Post-Quantum Cryptography project](https://csrc.nist.gov/projects/post-quantum-cryptography) | Follow reviewed migration research and standards | Public project material; avoid inventing cryptographic designs. Reference. |

### A small, purposeful tool library

Install a tool when its module presents a question it can answer. Read the official documentation and know what traffic, files, credentials, and privileges it uses. This table is a learning map, not an instruction to install everything at once.

| Tool or family | First useful stage | Question it helps answer | Evidence to understand |
| --- | --- | --- | --- |
| Shell, file utilities, local manuals | A | What is this file, process, or permission? | Paths, ownership, output, exit status |
| Browser developer tools | A–C | What request did the application actually make? | Method, headers, body, storage, response |
| Python and standard libraries | B | Can I reproduce a data-analysis task reliably? | Validated input, exact output, errors, tests |
| Git | B | What changed and why? | Diff, history, scope of a commit |
| SQLite | B–C | Does data access preserve structure and ownership? | Query, bound values, result, transaction behaviour |
| Burp Suite Community Edition or OWASP ZAP | C | How does an authorized app respond to a controlled request change? | Baseline request, modified field, observed response |
| Nmap | D | Which expected services are observable within the allowed lab? | Target scope, method, port state, evidence limits |
| Wireshark or tcpdump | A, D–E | What happened on this observed connection? | Capture point, timing, protocol, missing visibility |
| Vulnerability scanners | D | Which hypotheses deserve validation? | Rule/version match, configuration applicability, false positives |
| Metasploit or similar training frameworks | D, optional | How does an understood lab vulnerability behave under a bounded reproduction? | Module assumptions, actions, result, cleanup; not a substitute for understanding |
| Password-audit tools such as Hashcat or John | B/D, optional | How do storage choices affect a controlled password-strength exercise? | Only self-created toy hashes, stated parameters, measured results, no real credentials |
| Windows event tools and PowerShell | B/E | Which identity performed which recorded action? | Event fields, tokens, effective permissions, timestamp semantics |
| Sigma-compatible detection tooling | E | Does a defined behaviour match the intended rule? | Required fields, translated query, test data, false positives |
| Autopsy and Volatility | E | Which artifacts support an investigation? | Acquisition context, source artifacts, integrity, limitations |
| Ghidra and a debugger | E/G | What does this benign toy binary do? | Code paths, data references, runtime observations |
| Cloud CLI and policy tools | F | What is configured and which identity can act? | Effective policies, resource inventory, audit records, cost |
| Container/image/IaC scanners | F | What build or configuration concerns need review? | Artifact identity, rule assumptions, runtime context |
| Compiler sanitizers and a fuzzer | G | Which controlled input causes a reproducible failure? | Harness, minimized input, build flags, root cause |

Public scanner templates and framework modules are executable or behaviour-defining inputs. Review their scope and effects before using them, even in a lab. Tool availability is never a reason to broaden the agreed target set.

### Optional certification decision

Use the degree and practical portfolio as the core. After completing relevant projects, compare an assessment's syllabus with the actual role you want, its prerequisites, current fees in your payment currency, software requirements, retake policy, renewal rules, and available study time. Do not buy multiple subscriptions simultaneously just to feel committed.

For web specialization, investigate the [BSCP preparation and requirements](https://portswigger.net/web-security/certification) after substantial independent web-lab practice. The official page also requires access to an active Burp Suite Professional subscription for the exam, so exam credit is not the only cost. For broader penetration testing, investigate [PEN-200's current prerequisites and assessment route](https://www.offsec.com/courses/pen-200/) after networking, operating-system, scripting, and reporting foundations. These are optional comparisons, not a claim that either is required by every Sri Lankan employer.

## Glossary and revision cards

### Core glossary

| Term | Plain-English meaning |
| --- | --- |
| Asset | Something valuable that a system or organization needs to protect. |
| Threat | A possible source or cause of harm. |
| Vulnerability | A weakness that can contribute to a security failure. |
| Risk | Possible harm considered with its likelihood, consequences, and context. |
| Control | A measure intended to prevent, detect, respond to, or recover from a problem. |
| Attack surface | The exposed functions and interfaces through which a system can be interacted with. |
| Trust boundary | A point where identity, ownership, privilege, or assumptions about trust change. |
| Authentication | Checking a claimed identity. |
| Authorization | Deciding whether an identity may perform an action on a resource. |
| Least privilege | Granting only the capabilities required for a defined task. |
| Defence in depth | Using complementary controls so one failure does not remove every protection. |
| Process | A running instance of a programme with execution state and an identity. |
| Service | A function provided by one or more processes, often available in the background. |
| Kernel | The operating-system component managing core resources and privileged operations. |
| Virtual machine | A guest computer environment managed by a hypervisor. |
| Container | An isolated process environment usually sharing a host kernel. |
| Snapshot | A point-in-time state used for supported restore operations; not a complete backup strategy. |
| IP address | An address for an interface in an IP networking context. |
| Port | A transport-layer endpoint identifier used with an address and protocol. |
| Subnet | A defined IP address range based on a network prefix. |
| Gateway | A next-hop system used to reach another network. |
| DNS | The distributed system for resolving names and associated records. |
| TCP | A transport protocol providing an ordered byte stream with reliability mechanisms. |
| UDP | A transport protocol carrying datagrams without TCP's delivery guarantees. |
| TLS | A protocol family for protected communication with configured authentication properties. |
| HTTP | A request/response application protocol used extensively by the web. |
| Origin | A browser security identity based on scheme, host, and port. |
| Cookie | Browser-managed data that may be attached to matching requests under defined rules. |
| Session | Application state representing a continuing interaction, often associated with an identity. |
| API | An interface through which software exposes operations or data to other software. |
| Encoding | Changing representation without necessarily providing confidentiality. |
| Encryption | Protecting data confidentiality with a cryptographic key and suitable scheme. |
| Hash | A fixed-size digest calculated from input; security properties depend on the algorithm and use. |
| Salt | A per-record value used with password hashing to prevent identical stored outcomes across users. |
| Digital signature | Asymmetric cryptographic evidence of data integrity and origin under a key trust model. |
| MFA | Authentication using more than one appropriate factor category. |
| OAuth | A framework for delegated authorization. |
| OpenID Connect | An identity layer built on OAuth 2.0. |
| SQL injection | Untrusted data changing the intended structure or meaning of a SQL statement. |
| XSS | Untrusted data becoming executable content in a browser context. |
| CSRF | An unwanted request taking advantage of credentials a browser attaches automatically. |
| CORS | Browser response-sharing rules for requests across origins. |
| SSRF | Untrusted input influencing a server's outbound requests across intended boundaries. |
| Path traversal | Access to paths beyond an intended filesystem boundary. |
| BOLA/IDOR | Broken object-level authorization; identifiers are used without a sufficient access check. |
| Race condition | Behaviour depending on competing operations whose timing breaks an intended invariant. |
| Idempotency | Repeating an operation has no additional intended effect beyond the first successful application. |
| CVE | An identifier and record for a publicly catalogued vulnerability. |
| CWE | A category describing a type of software or hardware weakness. |
| CVSS | A versioned system for describing technical vulnerability severity. |
| EPSS | An estimate of a defined probability of exploitation, distinct from severity. |
| False positive | A detection or finding that labels benign or unaffected behaviour as a problem. |
| False negative | A relevant problem that the detection or test fails to identify. |
| Precision | True positive predictions divided by all positive predictions, for a defined labelled dataset. |
| Recall | True positive predictions divided by all actual positive cases, for a defined labelled dataset. |
| SIEM | A system for collecting, searching, and correlating security-relevant event data. |
| EDR | Endpoint detection and response capabilities for observing and responding to host activity. |
| IOC | An observable indicator that may be associated with suspicious or malicious activity. |
| TTP | A tactic, technique, or procedure describing behaviour rather than only a static indicator. |
| DFIR | Digital forensics and incident response. |
| Chain of custody | A record of evidence acquisition, handling, and transfer. |
| IAM | Identity and access management. |
| RBAC | Role-based access control, assigning permissions through roles. |
| ABAC | Attribute-based access control, using attributes in a policy decision. |
| Tenant | A customer or organizational boundary within a shared application or platform. |
| SAST | Analysis of source or related code artifacts for security concerns without normal application execution. |
| DAST | Testing the observable behaviour of a running application. |
| SCA | Analysis of software components and dependencies. |
| SBOM | A structured inventory of components in a software artifact. |
| CI/CD | Automation supporting integration, testing, delivery, and sometimes deployment of software changes. |
| IaC | Infrastructure represented and managed through versioned configuration or code. |
| Fuzzing | Exploring programme behaviour with generated or mutated inputs under a defined harness. |
| Sanitizer | Instrumentation that detects certain classes of runtime programming errors. |
| ASLR | Randomization of parts of a process's memory layout to complicate some exploitation methods. |
| Firmware | Software closely associated with a device's hardware operation and boot/runtime functions. |
| OT | Systems that monitor or control physical processes. |
| Prompt injection | Untrusted content influencing an AI system beyond the content's intended authority. |
| RAG | Retrieval-augmented generation: supplying retrieved content to support a model's output. |
| Scope | The agreed boundaries and conditions of an assessment or exercise. |
| Retest | A targeted check of whether a reported cause and related behaviour were corrected. |
| Responsible disclosure | Coordinating a vulnerability report and any publication under appropriate policies and agreements. |

### Starter revision cards

These are additional study aids; they do not change the count of 96 module self-check questions.

| Front | Back |
| --- | --- |
| Identity versus permission? | Authentication establishes who; authorization decides what that identity may do. |
| Is a public website a permitted target? | No. Reachability is not authorization. |
| What makes a finding reproducible? | Known context, preconditions, controlled steps, expected/actual result, and relevant evidence. |
| What does HTTPS establish? | A protected connection and configured hostname authentication, not the operator's honesty. |
| Does a random object ID enforce ownership? | No. Check permission on the server. |
| What does parameterized SQL protect? | The statement's structure from untrusted values; ownership is a separate policy. |
| What is the core XSS question? | Where does untrusted data become executable browser content? |
| Does CORS authorize non-browser API clients? | No. Server authorization must stand independently. |
| Why are password salts not secret? | Their role is uniqueness, not confidentiality; password hashing still needs appropriate cost. |
| Is a CVE match a confirmed affected system? | No. Verify the product, build, configuration, reachable condition, and evidence. |
| Why can two valid requests cause a failure? | Their combined timing can violate a shared invariant. |
| Does encryption fix a broad storage policy? | No. Authorized reads can still return decrypted data. |
| What does a matching SHA-256 digest support? | Consistency of bytes relative to a compared digest, not truth or authorship. |
| What is a detection rule missing without telemetry? | The evidence needed to evaluate its logic. |
| Why can a high-accuracy detector still overwhelm a team? | Rare incidents and large benign volumes can create many false positives; examine base rates. |
| Is one successful AI boundary test a guarantee? | No. Enforce permissions in code and evaluate varied defined cases. |
| What proves cleanup? | A verified final resource/account/configuration state, not merely an intention to remove it. |
| What makes a lab result professional? | Correct scope, sound reasoning, evidence, useful repair, honest limits, and clear communication. |

## Sri Lankan professional pathway

### Build a reputation through useful evidence

Begin with the degree's computing, networking, and software projects. Ask lecturers about supervised security work on purpose-built teaching systems. Join a university computing or security society and contribute a small workshop, documented tool, or permitted CTF explanation. Use the [OWASP chapter directory](https://owasp.org/chapters) to identify current relevant communities; confirm local events on official pages before planning travel or payments. This document does not claim a particular Colombo or university chapter is currently active.

Follow [Sri Lanka CERT's official site](https://www.cert.gov.lk/) for local advisories, educational resources, and the current incident-reporting entry point. The site is a source of professional context, not permission to test an organization mentioned in an advisory. Drafting a report in a workbook does not send it to CERT or any other organization.

### Local legal reading

Study the official [Computer Crimes Act, No. 24 of 2007 entry](https://www.parliament.lk/en/business-of-parliament/act-details/G4684) and the [Data Protection Authority's acts, amendments, gazettes, and guidance](https://www.dpa.gov.lk/guidelines.php). The DPA's published index includes the Personal Data Protection Act, No. 9 of 2022 and the Personal Data Protection (Amendment) Act, No. 22 of 2025. Do not rely on an older blog post's commencement date; the applicable provisions, amendments, gazettes, and current official guidance need to be checked for a real engagement.

The practical learning rule is clear: obtain a suitable written scope, minimize collected data, use an authorized reporting channel, and respect the owner and provider's conditions. Exact legal obligations in a real case require reading the relevant current provisions and obtaining qualified advice where needed. This curriculum is educational guidance, not an opinion on whether a particular live action is lawful.

### Local experience milestones

| Milestone | Concrete action | Evidence to keep |
| --- | --- | --- |
| First foundation term | Finish P01–P02 and explain a security principle to a classmate. | Lab notes, a small original tool, feedback |
| First application term | Finish P03–P04 and connect a degree assignment to secure coding. | Report, patch, tests, lecturer feedback where available |
| Defensive exposure | Finish P05 and explain an ambiguous incident without exaggeration. | Timeline, rule evaluation, response decisions |
| Internship preparation | Prepare the M47 portfolio and identify roles through official employer and university channels. | Accurate CV, tailored project summaries, application tracker |
| Community contribution | Give an approved beginner workshop or contribute documentation to an open project. | Slides or contribution with permission and attribution |
| Specialization | Finish one ninety-day project and seek technically specific feedback. | Reproducer, report, review notes, corrected version |
| Longer-term credibility | Repeat useful work, collaborate responsibly, and publish permitted original research. | Sustained evidence and references from people who can assess the work |

There is no required deadline for becoming a “leading” professional. A reliable junior who explains limits and fixes mistakes is a better starting point than an inflated title.

### Affordable learning choices

Prioritize public documentation, the built-in workbooks, and provider labs with clearly available free access. Check whether the university provides hardware, licensed systems, library materials, or learning subscriptions. Use paper and synthetic-data exercises when a cloud or multi-machine setup would be expensive. Keep a monthly learning budget in LKR and account for exchange rates, taxes, software subscriptions, cloud usage, and renewals before a purchase.

During unreliable connectivity, use downloaded lessons and local datasets. Back up notes before travel or device servicing. Write portfolio explanations in clear English for a broad audience; explaining the same concept in Sinhala or Tamil can strengthen understanding and help local peers. Do not upload degree material, employer data, or private reports into a learning service without permission.

## Website experience and page content

### Product identity and purpose

**Working name:** CyberForge Academy. **Tagline:** “Understand systems. Find weaknesses. Build better defences.” The name is a proposed project identity, not a claim about trademark availability or affiliation.

The learner's main question on every visit is: **What should I do next, why does it matter, and how will I know I learned it?** The interface should answer that before showing decorative statistics.

**Homepage headline:** “Build real cybersecurity skills, one clear step at a time.”

**Homepage supporting copy:** “Start with your first command. Learn how systems work, practise in legal labs, investigate weaknesses, and build a portfolio you can explain. A complete study path designed to fit alongside your degree.”

**Primary action:** “Start from zero.” **Secondary action:** “Explore the roadmap.” **Returning learner action:** “Continue learning.”

**Curriculum facts:** 8 stages, 48 modules, 144 compact lessons, 48 practical briefs, 96 module self-check questions, 8 stage projects, and 2 final practical capstones within the last stage. These describe content volume, not a claim that 48 live labs are hosted inside the site.

### Visual direction

Use a polished dark study interface with a calm technical character. Create visual interest through a clear roadmap, subtle grid lines, original vector diagrams, excellent spacing, and purposeful progress feedback. Avoid animated code rain, unreadable glowing text, fake intrusion alerts, or decorative terminals that imply real access.

| Element | Proposed treatment |
| --- | --- |
| Main background | Deep navy `#090F1B` |
| Reading/panel surfaces | Slightly lighter navy `#111B2D`, with restrained borders |
| Main text | Near-white `#E7EDF7` |
| Secondary text | Muted blue-grey `#A8B4C7`, subject to contrast verification |
| Primary learning action | Mint `#86EFAC` with a dark text foreground |
| Links and information | Cyan `#67E8F9` |
| Needs review | Amber `#FBBF24`, paired with text/icon meaning |
| Error state | A high-contrast red treatment with explicit explanatory text |
| Typography | Readable system sans-serif for lessons; monospace for code and evidence |
| Reading width | Approximately 65–80 characters per line, adjustable text size |
| Motion | Brief transitions for navigation/progress; honour reduced-motion preferences |
| Light theme | An equally complete reading theme, not an inverted screenshot |

On desktop, use a collapsible navigation sidebar, main learning area, and optional lesson outline. On mobile, use a compact header and accessible navigation drawer or labelled bottom destinations. Keep the current lesson and its next action prominent. Tables and code may scroll inside their own labelled regions without forcing the entire page sideways.

### Information architecture

Routes below are proposed browser routes, not existing files or implemented pages. Static hosting must have an explicit route strategy: hash routing or a verified history fallback.

| Page | Proposed route | Main content and actions | Required empty/error state |
| --- | --- | --- | --- |
| Welcome | `/` | Value proposition, curriculum facts, start/continue, roadmap preview | Returning learner can restore a backup instead of restarting. |
| Dashboard | `/dashboard` | Continue lesson, this week's plan, due review, next practical, progress by evidence type | “Your first mission: learn what you are protecting.” |
| Roadmap | `/roadmap` | Eight stages, prerequisites, expected effort, evidence gates, accessible list view | Explain recommended prerequisites without hiding preview access. |
| Lesson reader | `/learn/:moduleId/:lessonId` | Teaching text, examples, outline, notes, references, recall prompt, next lesson | Invalid ID shows a useful not-found page and roadmap link. |
| Lab library | `/labs` | Filter by topic, mode, stage, cost label, setup needs, estimated effort | “No labs match these filters. Clear filters or choose another mode.” |
| Lab detail | `/labs/:labId` | Objective, prerequisites, scope, method, evidence, hints, completion rubric | External provider unavailable: show saved brief and a suitable paper alternative if one exists. |
| Practice workbench | `/practice` | Synthetic HTTP, log, permission, and race exercises; command-learning sandbox | State clearly when an exercise is a simulation. |
| Quiz and revision | `/review` | Module questions, answer reveal, self-rating, due cards, weak topics | “Nothing due. Review a weak concept or continue your path.” |
| Project gallery | `/projects` | Eight stage briefs, required outputs, submission status, rubric | No fabricated examples presented as the learner's completed work. |
| Project workspace | `/projects/:projectId` | Checklist, local evidence notes, rubric, review status, export | Explain missing required evidence and how to add it. |
| Notebook | `/notebook` | Searchable lesson-linked notes, templates, bookmarks, local export | “Capture what you observed, what it means, and what remains uncertain.” |
| Resource library | `/resources` | Official references, topic filters, review dates, access labels | Broken/unknown link can be reported locally and marked for review. |
| Glossary | `/glossary` | Plain definitions, related lessons, revision-card action | Unknown term gives spelling suggestions and a search link. |
| Sri Lanka pathway | `/sri-lanka` | Official sources, local study/career milestones, budget guidance | No fabricated events, rankings, employer endorsements, or live listings. |
| Career and specialization | `/career` | Track comparison, portfolio checklist, ninety-day plan, optional assessments | “Choose a problem you want to solve, then build evidence.” |
| Settings and data | `/settings` | Theme, reading size, study hours, exam mode, export/import, delete/reset | Explain storage limits and confirm destructive data operations. |
| Search | `/search` | Search lessons, labs, questions, definitions, and references by text/ID | Show query and filters; suggest relevant terms without inventing results. |
| Help and scope | `/help` | How to study, practice rules, data behaviour, keyboard help, FAQs | Clear route back to the current lesson. |

### First-use flow

1. Welcome the learner with the homepage copy. No fake live-user count, earnings claim, or “become elite in thirty days” promise.
2. Ask only for useful local preferences: preferred display name (optional), weekly study hours, existing experience, and browser-first versus local-lab availability.
3. Offer the starting diagnostic and explain that unfamiliar answers simply choose a starting point.
4. Set the default plan to M01 with a short explanation of permission and scope.
5. Show exactly one next lesson, a realistic duration, and where progress is stored.
6. Offer export/import and exam mode through settings without blocking the first lesson.

**Onboarding copy:** “You do not need to know the tools yet. Start by understanding the system, make one observation, and explain it clearly.”

**Storage copy for the proposed first release:** “Your progress and notes are saved in this browser on this device. Clearing site data or changing devices can remove access to them. Export a backup when you want to keep a separate copy.” This copy must change if actual storage behaviour changes.

### Dashboard behaviour

The dashboard should show four useful areas: the next lesson, a weekly plan, concepts due for review, and a practical/project requiring evidence. Completion counts start at zero for a new profile. Demo data, if offered for preview, must be clearly labelled and isolated from actual progress.

Show separate indicators for lessons read, practicals completed, independent attempts, and reviewed projects. A learner who has read every page but completed no practicals should see that distinction. “Time studied” comes from a user-entered or transparent timer record and must not treat an idle browser tab as continuous learning.

**Next-action examples:** “Read M04-L2: Protocol roles”; “Finish LAB-07: compare your counts with the answer key”; “Retest the ownership fix”; “Review authentication versus authorization.”

**Exam mode copy:** “Keep the habit, reduce the load. Your plan now prioritizes two short reviews and one practical reflection each week.”

### Lesson reader behaviour

Each lesson displays its stage/module context, prerequisites, learning outcome, estimated reading/practice distinction, content version, and references. Use a sticky but unobtrusive progress position, table of contents, and a visible next step. Completing a reading action is reversible and does not mark the lab complete.

Support highlighting or a simpler “Save note about this section” action, code copy with visible feedback, expandable glossary definitions, and print-friendly output. A copied command should not be executed automatically. External examples should not open a new session or launch a lab without the learner choosing that action.

**Reflection prompt:** “Explain the idea in your own words. What would you expect to observe if the control worked?”

**Completion copy:** “Reading recorded. Put the idea into practice when you are ready.”

### Labs and the practice workbench

Every lab card shows its mode: Paper exercise, Browser training provider, Isolated local lab, or Owned cloud lab. Show required software, expected evidence, approximate effort, a cost caveat where relevant, and whether the resource is external. A “Launch lab” button is permitted only when it actually opens an available environment; otherwise use “Read setup” or “Open provider.”

Built-in practice experiences for the first complete release:

| Exercise | Data and behaviour | Completion evidence |
| --- | --- | --- |
| Command-learning sandbox | Fixed in-memory filesystem and a documented small command allowlist; no host-shell access | Learner navigates, reads a synthetic file, and explains permissions. |
| HTTP inspector | Workbook B request/response with clickable fields and explanations | Correctly identify method, resource, session carrier, and needed server checks. |
| Authorization matrix | Workbook D dummy users and notes; switch policy between flawed and fixed models | Own access succeeds; cross-user access is denied after the repair. |
| Log investigator | Workbook C dataset with local filtering, counts, timeline, and an answer reveal | Counts match; learner distinguishes a lead from proof of compromise. |
| Race simulator | Workbook E step-through interleaving and atomic variant | Learner identifies the violated invariant and explains why the repaired model permits one redemption. |
| Scope classifier | M01 scenarios with explanations | Learner distinguishes allowed, excluded, and needs-clarification actions. |

The command-learning sandbox must state “Simulation: commands affect only this exercise.” Unsupported commands receive an explanation of the supported set. It must not use `eval`, spawn a shell, accept a remote target for scanning, or claim to be a real Kali machine. Real VM/cloud labs remain separate explicit environments.

Provide three hint levels where useful: a concept reminder, a relevant observation to inspect, and a guided explanation. Record hints used without punishment. Provider solutions must not be copied into the site without permission.

### Questions, revision, and progress

Use the supplied short-answer questions exactly as authored, with their explanations hidden until the learner chooses to reveal them. Self-rating is honest and simple. Do not claim reliable automatic marking of free text unless a separate validated assessment system is actually implemented. Deterministic workbench tasks may check exact known results.

Review scheduling starts with roughly 1, 3, 7, and 21 days, adjusted by the learner's self-rating. Display due dates in the selected local time zone. Allow snoozing during examinations without deleting history. Use a topic list and evidence breakdown as the primary progress visualization; a radar chart must never imply a measured professional capability that the underlying data does not support.

Optional points: 5 per completed lesson reflection, 5 per module self-check after correction, and 25 per completed practical give 50 points per module. Award at most once per content item; retakes improve learning records without creating infinite points. Stage-project review can award 75 points and the final review 100, for a planned maximum of 3,100 points. Points measure participation under these rules, not expertise or national rank. The two self-checks each earn 5 points; the total module calculation is 3 × 5 + 2 × 5 + 25 = 50.

Badges should name evidence: “First documented lab,” “Ownership check repaired,” “Incident timeline completed,” and “Capstone reviewed.” Never grant a badge for opening an external link alone.

### Notebook, portfolio, and exports

Notes belong to stable lesson/module IDs, support search, and show a save state. Start with plain text or safely rendered Markdown. Store only synthetic or sanitized evidence notes by default; arbitrary sensitive attachments are not necessary for the first release. Provide templates from this document and export selected notes/reports in readable Markdown plus a versioned JSON backup for full restoration.

A portfolio export should include the work category, scope, original contribution, evidence, limits, and review status. Let the learner preview and remove private content before exporting. Export does not publish or send the document anywhere.

### Search and offline reading

Index the actual course content, IDs, glossary, labs, and references. Support useful aliases such as “permissions” → authorization, “login” → authentication, and “blue team” → defence/detection. Display the matched sentence and where it appears. A search for an absent topic should say so and suggest adjacent material, not fabricate a lesson.

Provide explicit offline downloads of the site's own lesson content and synthetic datasets, plus a status showing what is cached and when. Do not claim offline access to external hosted labs, third-party videos, or material that has not been downloaded or licensed for that use. A service worker needs an appropriate secure origin, supported browser, and a completed initial download. Clearing browser data can remove cached content and progress.

### Accessibility and performance

Target WCAG 2.2 AA for the implemented interface and verify the actual interactions. Include semantic headings, keyboard navigation, visible focus, a skip link, labelled controls, accessible dialogs, text alternatives for diagrams, and status feedback announced appropriately. Never rely on colour alone. Support zoom, reduced motion, a useful light theme, and readable touch controls.

Use text and lightweight original vectors for core learning. Avoid autoplay video and large decorative backgrounds. Set a performance budget, lazy-load nonessential content, and test under a constrained network profile. The site should remain useful on a modest laptop or phone. If an external resource fails, the local explanation and lab brief should still be readable.

### Frequently asked questions — ready-to-use copy

**“I know nothing about hacking. Can I start here?”** Yes. Start with M01 and follow the foundation stage. You will learn the computer, network, programming, and security ideas before advanced testing.

**“Do I need Kali Linux?”** No. Use your existing system for early learning. Add a suitable lab environment when a practical requires it.

**“Will this make me Sri Lanka's best hacker?”** It can organize serious study and practice. Professional standing depends on years of demonstrated skill, trusted work, original contribution, and continuing learning.

**“Can I test my university's website?”** Only within explicit authorization from someone entitled to grant it and an agreed scope. Student status or having an account is not permission.

**“Is everything inside this website?”** Lessons, revision, planning, synthetic exercises, and notes are designed to live here. Some practicals use external training providers or your own isolated environment, clearly labelled on each lab.

**“Is the learning path free?”** The local curriculum is intended to be usable without a paid course subscription. Hardware, connectivity, some external labs, cloud use, and optional exams may have costs. Each resource should state its known access conditions.

**“What if exams interrupt my progress?”** Turn on exam mode, keep short reviews, and return when ready. Your progress is not deleted because you missed a day.

**“Where is my progress saved?”** In the proposed first release, this browser on this device. Export a backup before clearing site data or moving to another device. Any future synchronization feature must explain its actual storage and privacy behaviour.

**“Does the terminal run commands on my computer?”** The built-in command exercise is a simulation with synthetic files. Real local labs have separate setup instructions and require you to choose and control that environment.

**“Do completion badges replace certifications or experience?”** No. They record learning activities. Practical evidence, independent review, professional experience, and external assessments have different meanings.

## Content model and implementation requirements

This section is a proposed implementation contract. It does not mean an application, database, lab service, or integration has already been created.

### Recommended first implementation

Build a static learning application with semantic HTML, responsive CSS, JavaScript modules, structured course data, and browser storage. The core requirements do not need a server that executes security tools. A component framework can be introduced if it makes the implementation clearer, but it should not become a prerequisite for reading lessons or exporting progress.

Use IndexedDB for structured progress and notes when available, with a clear in-memory fallback if persistence is unavailable. Small display preferences may use simpler browser storage. Treat storage failure as a visible state; do not show “saved” before the write succeeds. Use a service worker for explicitly downloaded first-party offline content, with versioned caches and controlled update behaviour.

Keep this master document as the editorial source during the first implementation. Convert sections to content records systematically and verify all IDs, text, questions, answer explanations, and resource links. A beautiful dashboard containing only module titles does not satisfy the learning requirement.

### Entities and relationships

| Entity | Required fields | Important rules |
| --- | --- | --- |
| Curriculum | ID, title, version, language, stages, review date | Version content separately from application code. |
| Stage | ID, title, order, module IDs, planned hours, project ID | Hours must match the defined module budgets. |
| Module | ID, stage, title, prerequisites, hours, lesson IDs, lab ID, question IDs, references | Stable IDs; exactly three lessons and two self-checks in edition 1.0. |
| Lesson | ID, module ID, title, body, outcome, references, content version | Preserve teaching text; reading completion is separate from practical completion. |
| Lab | ID, module ID, mode, objective, setup, method, expected evidence, rubric, resources | Clearly distinguish a simulation, a brief, an external provider, and a runnable local lab. |
| Question | ID, module ID, prompt, answer, explanation, related lesson IDs | Self-rating by default; no fabricated automatic assessment. |
| Project | ID, stage ID, required outputs, rubric, capstone links | Reuse module evidence without pretending an unseen project was executed. |
| Resource | ID, title, URL, provider, purpose, access note, review status/date | Show when the link or offering has not been recently checked. |
| Glossary term | ID, term, aliases, definition, related lessons | Definitions remain available without a network call. |
| Progress | Item ID, state, timestamp, content version, evidence/review type | Record reading, guided, independent, and reviewed states distinctly. |
| Quiz attempt | Question ID, learner answer, self-rating, answer-reveal state, timestamp | Retakes append useful history without repeatedly awarding points. |
| Review card | ID, linked concept, next due date, last rating, history | Time-zone-aware schedule; no penalty for exam-mode pauses. |
| Note | ID, linked item IDs, plain/Markdown body, created/updated times | Render safely; keep local by default. |
| Study plan | Weekly minutes, available days, exam mode, next items, time zone | Do not schedule more work than the chosen budget. |
| Backup | Schema version, curriculum version, export time, preferences, records | Validate before import; preview changes and preserve a rollback option. |

Example module metadata, ready to guide later extraction:

```json
{
  "id": "M01",
  "stageId": "A",
  "title": "Ethical practice, scope, and security principles",
  "plannedHours": 8,
  "prerequisites": [],
  "lessonIds": ["M01-L1", "M01-L2", "M01-L3"],
  "labId": "LAB-01",
  "questionIds": ["M01-Q1", "M01-Q2"],
  "resourceIds": ["R07", "R20", "R21", "R22"],
  "contentVersion": "1.0"
}
```

Example initial progress record:

```json
{
  "schemaVersion": "1.0.0",
  "curriculumVersion": "1.0",
  "timeZone": "Asia/Colombo",
  "weeklyStudyMinutes": 480,
  "examMode": false,
  "lessonProgress": {},
  "labProgress": {},
  "questionAttempts": [],
  "projectReviews": [],
  "notes": [],
  "bookmarks": [],
  "reviewCards": []
}
```

The empty progress record is intentional. Do not seed a real learner with invented completion, study time, streaks, reviews, or achievements.

### Progress calculation and scheduling

Calculate the lesson reading percentage from completed lesson IDs divided by 144 for this edition. Calculate practical completion separately from completed practical IDs divided by 48, and show whether completion was guided, independent, or reviewed. Calculate project status from eight stage projects and the required practical capstones. Do not merge these into an unexplained single “hacker skill percentage.”

The next-action recommender can be deterministic: continue an unfinished lesson; otherwise choose a due review within its allocated study slot; otherwise choose the next ready lesson or practical under the selected path. If a prerequisite is missing, explain why it is recommended and link to it. Learners may browse advanced reading while the site accurately labels practical readiness.

Store assistance and hint use as learning context. A corrected self-check can count toward recall completion, but independent competence requires a changed task without a walkthrough. Version changes may mark an item for review without deleting historical evidence.

### Data handling and import/export

The first release should collect only optional display preferences, learning records, and the notes the learner deliberately creates. No advertising trackers or unnecessary identity fields are needed. Local browser storage is not an encrypted evidence vault, so explain that sensitive professional data belongs in an appropriate separate system.

An export should contain readable metadata and a schema version. Before import, validate structure, types, size, IDs, and supported schema versions; reject executable content and unsupported fields that could alter application behaviour. Treat imported strings as untrusted text. Provide a preview showing additions and conflicts, let the learner choose merge or replace, and keep a pre-import backup when practical. Never overwrite existing notes silently.

A reset needs a specific confirmation naming what will be deleted, plus an export option. Selective deletion should distinguish notes, progress, and cached lessons. An offline cache refresh must not clear the progress database. If persistence is blocked or full, show a persistent notice and allow immediate export of in-memory work.

### Application security requirements

- Render lesson and imported note content using a deliberately restricted Markdown/HTML policy. Treat raw HTML, URLs, and code snippets according to their context; never execute imported text.
- Use a restrictive content-security policy compatible with the actual implementation, and avoid dynamic code evaluation.
- Keep the command sandbox in a controlled in-memory model; it must not connect learner input to an operating-system shell or unrestricted network requests.
- Limit external links to safe schemes and use appropriate isolation for new tabs. External-provider content should open explicitly; do not embed untrusted pages with unnecessary permissions.
- Keep credentials and provider keys out of static assets, progress exports, notes, and logs. A real AI integration requires a suitable server-side boundary and separate data/cost design.
- If synchronization is added later, enforce ownership on the server for every record and operation. A browser-side user ID is not an authorization check.
- Review dependencies and licenses; use maintained libraries only when they serve a clear requirement.
- Ensure example commands and datasets use synthetic targets and visible lab scope. The learning platform must not offer an unrestricted scan-any-target endpoint.

### Release scope

| Release | Included | Exit condition |
| --- | --- | --- |
| 0 — This document | Complete first curriculum, teaching text, practical briefs, answers, templates, page content, and implementation contract | Content structure and internal consistency reviewed; no website implementation required. |
| 1 — Complete personal learning site | All authored content, roadmap, lesson reader, search, labs catalogue, six built-in practice experiences, revision, notes, progress, projects, settings, export/import, offline reading | Every required user flow works with accurate content and no placeholder-only modules. |
| 2 — Optional account synchronization | Authenticated per-user storage, conflict handling, recovery, updated privacy information | Ownership and data-recovery tests pass; local work can migrate safely. |
| 3 — Optional learning enhancements | Reviewed translations, additional original labs, richer specialist lessons, consented collaboration, or a real bounded AI tutor | Each feature has authored content, clear data/cost behaviour, and verified functionality. |

Optional future features must not appear as working controls in release 1. An AI tutor with no backend, a fake terminal, or a progress dashboard with hardcoded statistics is not an acceptable substitute for the requested learning experience.

### Editorial maintenance

Review fast-changing platform, law, certification, and identity guidance before release and periodically afterward. Record exact standard versions in assessed work. Check external links and provider availability, and offer a correction log with content version/date. Do not label a lesson “updated today” unless its content was actually reviewed that day.

When expanding an advanced topic, add a bounded objective, prerequisites, explanation, example, practical procedure, expected evidence, hints, solution reasoning, repair, retest, references, and a limitation statement. Preserve stable IDs or supply a migration so existing bookmarks and notes continue to work.

## Release acceptance checklist

### Content preparation — the current deliverable

- [x] The document contains eight stages and all modules M01–M48 in order.
- [x] Every module has three identified lessons, one identified practical, two identified questions with answers, and references.
- [x] Module budgets total 860 hours and agree with stage totals.
- [x] The first-month schedule does not promise to finish more work than its estimated hours allow.
- [x] Synthetic log counts and authorization/race answer keys are internally consistent.
- [x] The eight workbooks and five reusable templates are readable and usable independently.
- [x] All reference IDs used by modules exist in the reference table.
- [x] Internal contents links resolve to the intended headings.
- [x] Legal and provider-specific notes distinguish checked sources from unverified or changeable details.
- [x] The document clearly distinguishes curriculum content, practical briefs, and future website functionality.

These boxes are editorial review items; they are not learner progress. Their final state should reflect checks actually completed during document preparation.

### Website implementation — future verification

- [ ] All 144 lesson bodies, 48 lab briefs, and 96 question/answer pairs are present; no empty lesson cards or placeholder paragraphs remain.
- [ ] A new learner can start M01, save a note, complete a reflection, and resume after a reload.
- [ ] Reading completion does not automatically mark a practical or project complete.
- [ ] Roadmap stages, prerequisites, counts, and suggested next steps come from content data.
- [ ] Search finds exact IDs and meaningful topic text; absent results remain honest.
- [ ] All six practice experiences provide accurate feedback using only their intended synthetic state.
- [ ] The command sandbox cannot execute on the host or contact arbitrary network targets.
- [ ] Log exercise counts match Workbook C, including malformed-input handling where supported.
- [ ] Authorization and race simulations demonstrate both allowed ordinary behaviour and the repaired boundary.
- [ ] Self-check answers remain hidden until requested; self-assessment is labelled honestly.
- [ ] Review scheduling and exam mode preserve history and use the selected time zone consistently.
- [ ] Export/import restores representative notes, progress, bookmarks, and settings without executing imported content.
- [ ] Import conflicts, unsupported versions, storage failures, and destructive resets have clear user flows.
- [ ] A fresh profile starts at zero; demo content cannot contaminate learner records.
- [ ] Downloaded first-party lessons work offline after a successful initial cache; external labs are labelled online-only.
- [ ] Updating cached content does not delete notes or progress.
- [ ] Deep links, refresh, back/forward navigation, and invalid routes behave correctly on the actual host.
- [ ] Keyboard, focus, screen-reader labels, text contrast, zoom, light theme, and reduced motion have been checked.
- [ ] Mobile layout remains usable with long titles, code blocks, tables, and an open navigation drawer.
- [ ] External resources, licences, access notes, legal references, and certification requirements are reviewed before publication.
- [ ] No invented testimonials, earnings, national ranking, professional accreditation, or live-lab availability claims appear.
- [ ] Any hosted release reports its real deployment result and known verification limits.

### Definition of a useful learning session

The learner leaves with one clearer mental model, one meaningful observation, or one improved piece of evidence. The site should make that progress easy to see and easy to resume. Its purpose is to help a student become capable through sustained practice, careful reasoning, and trusted work.
