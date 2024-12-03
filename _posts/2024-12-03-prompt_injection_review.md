---
layout: post
title: "Prompt Injection in LLM : Review"
date:   2024-12-03
tags: [LLM, AI Security,prompt injection]
comments: true
author: Xiaodie Qin
---

## [1]Prompt Injection attack against LLM-integrated Applications

Cite as: Liu Y, Deng G, Li Y, et al. Prompt Injection attack against LLM-integrated Applications[J]. arXiv preprint arXiv:2306.05499, 2023.

### 总结

提出HOUYI，这是一种开创性的黑盒提示注入攻击方法，使用LLM从用户交互中推断出目标应用程序的语义，并应用不同的策略来构建注入的提示。旨在促进对LLM集成应用程序的提示词注入攻击。  

在评估过程中，作者成功地展示了HOUYI的有效性，识别出两个值得注意的漏洞利用场景：提示词滥用和提示词泄漏。将HOUYI应用于36个现实世界的LLM集成应用程序，发现其中31个应用程序容易受到及时注入的影响。


### 提示词注入

提示注入：恶意用户使用有害提示来覆盖 LLM 的原始指令。

现有的提示词注入攻击可以分为两类：

- 将有害提示注入到应用程序输入中。目标是操纵应用程序响应不同的查询，而不是实现最初的目的。此类攻击通常以具有已知上下文或预定义提示的应用程序为目标。从本质上讲，它们利用系统自身的架构来绕过安全措施，破坏整个应用程序的完整性。
    
- （毒害应用程序查询的外部资源 ）鉴于许多现代 LLM 集成应用程序与 Internet 连接以提供其功能，攻击者将有害负载注入 Internet 资源。

### 攻击类别

现有的提示注入攻击的模式是什么？

**Direct Injection**

这种方法属于最简单的攻击形式，攻击者直接将恶意命令附加到用户输入中，此·附加命令旨在诱骗LLM执行用户意外的操作。

**Escape Characters**

注入转义字符，例如“\n”,”\t”等，以中断提示。

**Context Ignoring**

注入一个恶意的提示句，旨在操纵LLM，使其忽略前面的上下文，只关注后面的提示。

## [2]Not what you’ve signed up for: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injection
Cite as: Greshake K, Abdelnabi S, Mishra S, et al. Not what you've signed up for: Compromising real-world llm-integrated applications with indirect prompt injection[C]//Proceedings of the 16th ACM Workshop on Artificial Intelligence and Security. 2023: 79-90.

### 总结

作者认为大语言集成应用模糊了数据和指令之间的界限，他们使用间接提示注入揭示了新的攻击媒介，使得攻击者可以将提示注入到可能被检索到的数据中，远程利用LLM集成应用程序。

### LLM 集成应用程序

LLM 现在正以快节奏速度集成到其他应用程序中。这些工具可以提供交互式聊天和检索到的搜索结果或文档的摘要，并通过调用其他 API 代表用户执行操作。

### 间接提示词注入

LLM 集成应用通过检索来增强 LLM 模糊了数据和指令之间的界限。到目前为止，一直假设对抗性提示是由利用该系统的恶意用户直接执行的。作者表明攻击者现在可以通过战略性地将提示注入可能在推理时检索的数据来远程影响其他用户的系统。如果检索和摄取，这些提示可以间接控制模型。
