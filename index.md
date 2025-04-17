---
layout: default
title: /
permalink: /
---




#  👹 R X V 

Welcome to my reverse engineering and security-focused blog.
Here you'll find categorized write-ups and technical explorations.

---

## 🛡️ Anti-Cheat Posts

_Research and techniques related to bypassing or analyzing anti-cheat systems._
{:.category-desc}

---

## 🧬 Anti-Tamper Posts

_Exploring executable protection, obfuscation, and counter-tampering methods._
{:.category-desc}

---

## 🦠 Malware Posts

_Analysis and breakdowns of malware behaviors, obfuscation, and payload delivery._
{:.category-desc}

<ul>
{% assign filtered_posts = site.posts | where_exp: "post", "post.categories contains 'Malware'" %}
{% for post in filtered_posts %}
  <li>[{{ post.date | date: "%Y-%m-%d" }}] : <a href="{{ post.url }}">{{ post.title }}</a></li>
{% endfor %}
</ul>

---

## 🧩 CTF Posts

_Write-ups and notes on CTF challenges related to reverse engineering, anti-debugging, and more._
{:.category-desc}

<ul>
{% assign filtered_posts = site.posts | where_exp: "post", "post.categories contains 'CTF'" %}
{% for post in filtered_posts %}
  <li>[{{ post.date | date: "%Y-%m-%d" }}] : <a href="{{ post.url }}">{{ post.title }}</a></li>
{% endfor %}
</ul>

---

## 🧠 Windows Internals Posts

_Deep dive into Windows kernel, API, and internal system behavior._
{:.category-desc}

---
<br>
Thanks for stopping by! More posts coming soon.
{:.prompt-tip }
