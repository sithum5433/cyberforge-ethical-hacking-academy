#!/usr/bin/env python3
"""Build the self-contained CyberForge reader from the existing Markdown volumes."""
import ast
import html
import json
import math
import re
from pathlib import Path

import markdown

WORKSPACE = Path(__file__).resolve().parents[1]
ASSETS = Path(__file__).resolve().parent / "reader"
OUTPUT_HTML = WORKSPACE / "THE_SRI_LANKAN_ELITE_HACKERS_BIBLE_READER.html"

# Short display names; the original chapter text is preserved in full.
PRESENTATION = [
    ("Foundations & roadmap", "Build your foundations, find your direction, and learn the rules of ethical practice.", "Foundations", "compass", "mint"),
    ("Linux & command line", "Get comfortable with the filesystem, permissions, processes, and your terminal.", "Foundations", "terminal", "blue"),
    ("Networks & protocols", "Follow the packet. Understand the connections that make the internet work.", "Foundations", "network", "peach"),
    ("Security programming", "Turn ideas into useful tools with Python, JavaScript, C, and PowerShell.", "Foundations", "code", "purple"),
    ("Reconnaissance & OSINT", "Understand an authorized attack surface and turn observations into questions.", "Application security", "radar", "blue"),
    ("Server-side web security", "Understand injection, authentication, access control, and server-side boundaries.", "Application security", "shield", "mint"),
    ("APIs & client-side security", "Explore browser trust, API permissions, business logic, and responsible disclosure.", "Application security", "globe", "purple"),
    ("Enterprise network security", "Assess services, cryptography, and segmentation in a controlled environment.", "Systems & defence", "network", "blue"),
    ("Privilege & hardening", "Trace permission boundaries and make Linux and Windows systems more resilient.", "Systems & defence", "lock", "peach"),
    ("Active Directory & identity", "Connect the dots between identities, policies, permissions, and enterprise trust.", "Systems & defence", "layers", "purple"),
    ("Reverse engineering & cloud", "Explore binary analysis, mobile platforms, cloud systems, and wireless security.", "Systems & defence", "cpu", "mint"),
    ("Investigation & reporting", "Work through cases, examine telemetry, and communicate findings clearly.", "Systems & defence", "activity", "peach"),
    ("Ports & protocols", "A practical reference for network services, protocol behaviour, and hardening.", "Reference", "network", "blue"),
    ("Vulnerabilities & OWASP", "Connect vulnerability categories to their causes, controls, and verification.", "Reference", "shield", "mint"),
    ("Command-line toolkit", "Find the commands, flags, and examples you need while working through a lab.", "Reference", "terminal", "purple"),
    ("Detection & forensics", "Explore event sources, detection rules, investigation queries, and forensic tools.", "Reference", "activity", "blue"),
    ("40 hands-on labs", "Put the concepts to work with structured exercises in controlled environments.", "Reference", "flask", "mint"),
    ("Cryptography & glossary", "Revisit cryptography, technical vocabulary, and questions for active recall.", "Reference", "book", "peach"),
    ("CVE case studies", "Study the architecture behind documented vulnerabilities and their repairs.", "Reference", "radar", "purple"),
    ("DevSecOps & hardening", "Bring security into configuration, software delivery, and infrastructure review.", "Reference", "code", "mint"),
    ("Code review & threat models", "Follow trust boundaries through code and design controls you can verify.", "Reference", "layers", "peach"),
]


def load_volumes():
    """Read the shared literal catalogue without importing PDF rendering libraries."""
    source = (WORKSPACE / "scripts" / "build_encyclopedia_pdf.py").read_text(encoding="utf-8")
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "VOLUMES" for t in node.targets):
            return ast.literal_eval(node.value)
    raise ValueError("The source volume catalogue was not found.")


def flatten_toc(items):
    result = []
    for item in items:
        if item["level"] <= 2:
            result.append({"id": item["id"], "title": html.unescape(re.sub(r"<[^>]+>", "", item["name"])), "level": item["level"]})
        result.extend(flatten_toc(item.get("children", [])))
    return result


def build_interactive_reader():
    catalogue = load_volumes()
    if len(catalogue) != len(PRESENTATION):
        raise ValueError("Update the display catalogue to match the source volumes.")
    volumes, templates = [], []
    total_lines = 0
    for index, (part, original_title, subtitle, filename, _) in enumerate(catalogue):
        raw = (WORKSPACE / "chapters" / filename).read_text(encoding="utf-8")
        sid = f"vol-{index + 1}"
        converter = markdown.Markdown(
            extensions=["fenced_code", "tables", "toc", "sane_lists"],
            extension_configs={"toc": {"slugify": lambda text, sep, prefix=sid: prefix + "-" + re.sub(r"[^a-z0-9]+", sep, text.lower()).strip(sep)}},
        )
        fenced = False
        safe_lines = []
        for line in raw.splitlines():
            if line.lstrip().startswith(("```", "~~~")):
                fenced = not fenced
                safe_lines.append(line)
            elif not fenced:
                safe_lines.append(line.replace("<", "&lt;").replace(">", "&gt;"))
            else:
                safe_lines.append(line)
        body = converter.convert("\n".join(safe_lines))
        body = re.sub(r'href="(?:javascript|data|vbscript):[^"\n]*"', 'href="#"', body, flags=re.IGNORECASE)
        title, description, category, icon, color = PRESENTATION[index]
        line_count = len(raw.splitlines())
        total_lines += line_count
        volumes.append({
            "id": sid, "number": index + 1, "part": part, "title": title,
            "originalTitle": original_title, "description": description,
            "subtitle": subtitle, "category": category, "icon": icon, "color": color,
            "lines": line_count, "readMinutes": max(1, math.ceil(len(raw.split()) / 220)),
            "toc": flatten_toc(converter.toc_tokens),
        })
        templates.append(f'<template id="content-{sid}">{body}</template>')
    payload = json.dumps({"volumes": volumes, "totalLines": total_lines}, ensure_ascii=False).replace("<", "\\u003c")
    document = (ASSETS / "shell.html").read_text(encoding="utf-8")
    replacements = {
        "__READER_CSS__": (ASSETS / "styles.css").read_text(encoding="utf-8"),
        "__READER_JS__": (ASSETS / "app.js").read_text(encoding="utf-8"),
        "__READER_DATA__": payload,
        "__READER_CONTENT__": "\n".join(templates),
    }
    for marker, replacement in replacements.items():
        document = document.replace(marker, replacement)
    OUTPUT_HTML.write_text(document, encoding="utf-8")
    print(f"Built CyberForge: {len(volumes)} volumes, {total_lines:,} source lines, {OUTPUT_HTML.stat().st_size / 1024 / 1024:.2f} MB")
    print(f"Output: {OUTPUT_HTML}")


if __name__ == "__main__":
    build_interactive_reader()
