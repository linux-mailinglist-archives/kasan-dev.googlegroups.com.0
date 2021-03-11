Return-Path: <kasan-dev+bncBDX4HWEMTEBRBK43VKBAMGQEYQOJJTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3d.google.com (mail-vs1-xe3d.google.com [IPv6:2607:f8b0:4864:20::e3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 23565337FB8
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 22:37:48 +0100 (CET)
Received: by mail-vs1-xe3d.google.com with SMTP id j8sf795402vsj.5
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 13:37:48 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615498667; cv=pass;
        d=google.com; s=arc-20160816;
        b=zU54hv4ZzcUBpQS5+gSZdYMDWG/GILSCyjmyS9sjnoHdVuRxRGFXnbttKPlYXxOTX2
         /YjAMlMRWZUD+blwfO/OvJHirBaG3iPGB8yfmVOPsr7/gfX9Mqztd90i/51Z9gj5KeCA
         990U0aIoGJjlDGC7TeRAaelikXLm4ZaiIxLPvy5/m78GtlQgBa7NabVXzufyBQs/bNDh
         tCVCMjB6WIEGcLlx/eRi2egLPhFhisR9PI8Sq2xCbNj43gwEdDAQ5hHFD7bqIIvJsvrJ
         J9gxemvIVaXwdk7hubcfFrpWA35iTLQhUGWXZI4Oq1CmzFVe+9LjA2P9O1aZcZVPblhq
         hz0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=+8lDFkvvHgQG663XCF656gNTpQzHr8VzkX7yZhYGwyk=;
        b=bcmcreBBz2jGo7EYbFLEhdjfBZpk8IDERFumutk2bQ5axpJJZZ/wWvSh+QQ1FADC8n
         +ST/p16qwo3YwZZ7gitFfKKm+g3x9f6gZl1kzpTYK358tbCfmpnXqUg9xAKpWjeDAyPu
         6QMyfrQ4dUNmqrUcEJe3jw4NagvvPl889I6xvnMZAivve5hD081NRj5X2uQ0sxYxsMSt
         V7n3raggHnR7IlZX8OaxTVTubOaKHBElBZ412yqzPSsUnVuy4bMqqb98TzcEXwMd56oI
         PIYKrBdsGPN6X3OaL4LIxvmKh80YDWeNvmXUSznFvKJ7of6tzZyuvAXsNIAMj9B4DKNy
         CXsw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ESbdDH1d;
       spf=pass (google.com: domain of 3qo1kyaokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3qo1KYAoKCfcZmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+8lDFkvvHgQG663XCF656gNTpQzHr8VzkX7yZhYGwyk=;
        b=AzkqjuiQe0igAmW4q7gLWxmJMCPj7cpJ04CCjRCgAiyRWncuLMy0dBIPl+IyShmaRW
         ROSLbuxw3TGd5axkYyc6/EMKHzB8lt3bBHQ6dUr3TMbskLw6zQyjJfU7kirXtTjevI2v
         G0PSKo2KBW8cHQJR91TIZP6tSMbIXVkEyBDlITC2CXrL8TYNKsum4svAdlZJAvpqKh+q
         LYoEorcl3RPuHhqRHCgFVWOLVFPlmHPLT4PFBbFhKgM+CgjIQRaMpKECtvQ5LLVcNjE1
         KlW/jROeyhKRr372pipEZtVP+OZWxG9JZufR01PFzAxt38f5Xn9XFlo6oQntBgLWFLJS
         f6XQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+8lDFkvvHgQG663XCF656gNTpQzHr8VzkX7yZhYGwyk=;
        b=gkSpGZjQezQxSGehUnAk0LZapW1tZKa8agO1z0mByZnRWgcDpg2IV9MagJJ8tm0Sv2
         gFAQGGQ44an4ZwFuM/JgtgdqDlUeE2TBuiuKsAI8wY4QnrkWawTrBx7F1M7fare4IraU
         eOT6/2ZQTtYczWKLoe8QwsYrBOe56h86hAZhoWhPnmoImsSwelAM77dUQueeoyYjzcyi
         0DA1mWFryEFikJCUzW8wNY8fpGT+/sec+RZiKO3/gD3g8J9rOaxJNIvYL6Hf8IIf+lFt
         Qawkf0jgIKKvwBM12hiTq86O0GLdrAf4wPYurOowhylHRtXYYkij57JW36eMFEU9v6Hy
         g5QQ==
X-Gm-Message-State: AOAM531RefF5r7VSiKtW+uXy892BgF7NJzeEKkdzuFxtw6ieLjgbtCKk
	gDKt0461+4dg3Ob9v3v/NOk=
X-Google-Smtp-Source: ABdhPJz6pKWFaQLByFJT4GlMU32s51G28HiBRmzxdK68iL3UQSgM1iqQfrcVAAxR0f0Xqh7b194euw==
X-Received: by 2002:ab0:1c06:: with SMTP id a6mr6802540uaj.6.1615498667260;
        Thu, 11 Mar 2021 13:37:47 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac5:c89b:: with SMTP id n27ls391460vkl.1.gmail; Thu, 11 Mar
 2021 13:37:46 -0800 (PST)
X-Received: by 2002:a1f:a9c9:: with SMTP id s192mr6586820vke.22.1615498666699;
        Thu, 11 Mar 2021 13:37:46 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615498666; cv=none;
        d=google.com; s=arc-20160816;
        b=reydji7AZQIVTikSmXyRq/MoWeylYJ7X3XJCgyqPEE4kXVZOUvP9E1eDbvdMVHPqOg
         s44vjaTuHhToIGE/jKH38zK2/rTYvB4/P0g8xXpraa8ccma/apLejJeTdSJ8a2ygcxvO
         FoX2CYyPkU8E3gx1Ao/dGjcQiUlNGc42pS3IyXN8fJk3urK/S7N2QXmLMrMJ7FDWXpro
         XV25px4xhsrM2RtwbZd+sljTYfBtgqJs2JPr5U1Ic5oaESgVsv7ks0df8Ie9nLmwbn/E
         by+k+XRAp9ILjGyjVanRKBJkb5lXrPMraq3gzPZhi0XFJU+rdKR2jJQKo8IqC90IxemF
         CTYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=ftjCjXXHVhB6VMD5t3OFCFAtHdmXgYbSUPbbr/Gj6M0=;
        b=EAsEpFTmoeHNsK8k5hxQZl05ePpDGsfdEDtIiYSEfa8AwpmWOlbPNLfQR6E6+pDWrD
         gtq+k96+MY+jR1az1ETnjtBhxS9M+lEV24vkUkngeXsFxJd21nwR1J9ysOgFxAOE67mj
         NHtN20/zhHyj7K8oM6xqM5KjDSJkAR/Xq3sqADiu0iQBYSCCs0qZCBKrH8bO5Bqv2o1p
         znbT5TqvVyEstFl4j2BKF3+sdBM8A6sqFk7L4ZQISJ7T/Mv+e/hnowFw33kGLWOAoAdU
         vjybqdkfsLmNrSVB7oAF4Ky/UIKVKBpPCKbHFuk9icfFmLM92+Vh9KUCMLa3cRxJ9+RS
         1hew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ESbdDH1d;
       spf=pass (google.com: domain of 3qo1kyaokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3qo1KYAoKCfcZmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id p23si214791vkm.1.2021.03.11.13.37.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Mar 2021 13:37:46 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qo1kyaokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id 130so16707557qkm.0
        for <kasan-dev@googlegroups.com>; Thu, 11 Mar 2021 13:37:46 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:95a:d8a8:4925:42be])
 (user=andreyknvl job=sendgmr) by 2002:a0c:f541:: with SMTP id
 p1mr9682518qvm.14.1615498666324; Thu, 11 Mar 2021 13:37:46 -0800 (PST)
Date: Thu, 11 Mar 2021 22:37:21 +0100
In-Reply-To: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
Message-Id: <6cb4988a241f086be7e7df3eea79416a53377ade.1615498565.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH 09/11] kasan: docs: update shadow memory section
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ESbdDH1d;       spf=pass
 (google.com: domain of 3qo1kyaokcfczmcqdxjmukfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3qo1KYAoKCfcZmcqdxjmukfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Update the "Shadow memory" section in KASAN documentation:

- Rearrange the introduction paragraph do it doesn't give a
  "KASAN has an issue" impression.
- Update the list of architectures with vmalloc support.
- Punctuation, readability, and other minor clean-ups.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 31 ++++++++++++++-----------------
 1 file changed, 14 insertions(+), 17 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index f5c746a475c1..2b61d90e136f 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -304,14 +304,11 @@ checking gets disabled.
 Shadow memory
 -------------
 
-The kernel maps memory in a number of different parts of the address
-space. This poses something of a problem for KASAN, which requires
-that all addresses accessed by instrumented code have a valid shadow
-region.
-
-The range of kernel virtual addresses is large: there is not enough
-real memory to support a real shadow region for every address that
-could be accessed by the kernel.
+The kernel maps memory in several different parts of the address space.
+The range of kernel virtual addresses is large: there is not enough real
+memory to support a real shadow region for every address that could be
+accessed by the kernel. Therefore, KASAN only maps real shadow for certain
+parts of the address space.
 
 By default
 ~~~~~~~~~~
@@ -323,10 +320,9 @@ page is mapped over the shadow area. This read-only shadow page
 declares all memory accesses as permitted.
 
 This presents a problem for modules: they do not live in the linear
-mapping, but in a dedicated module space. By hooking in to the module
-allocator, KASAN can temporarily map real shadow memory to cover
-them. This allows detection of invalid accesses to module globals, for
-example.
+mapping but in a dedicated module space. By hooking into the module
+allocator, KASAN temporarily maps real shadow memory to cover them.
+This allows detection of invalid accesses to module globals, for example.
 
 This also creates an incompatibility with ``VMAP_STACK``: if the stack
 lives in vmalloc space, it will be shadowed by the read-only page, and
@@ -337,9 +333,10 @@ CONFIG_KASAN_VMALLOC
 ~~~~~~~~~~~~~~~~~~~~
 
 With ``CONFIG_KASAN_VMALLOC``, KASAN can cover vmalloc space at the
-cost of greater memory usage. Currently this is only supported on x86.
+cost of greater memory usage. Currently, this is supported on x86,
+riscv, s390, and powerpc.
 
-This works by hooking into vmalloc and vmap, and dynamically
+This works by hooking into vmalloc and vmap and dynamically
 allocating real shadow memory to back the mappings.
 
 Most mappings in vmalloc space are small, requiring less than a full
@@ -358,10 +355,10 @@ memory.
 
 To avoid the difficulties around swapping mappings around, KASAN expects
 that the part of the shadow region that covers the vmalloc space will
-not be covered by the early shadow page, but will be left
-unmapped. This will require changes in arch-specific code.
+not be covered by the early shadow page but will be left unmapped.
+This will require changes in arch-specific code.
 
-This allows ``VMAP_STACK`` support on x86, and can simplify support of
+This allows ``VMAP_STACK`` support on x86 and can simplify support of
 architectures that do not have a fixed module region.
 
 For developers
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6cb4988a241f086be7e7df3eea79416a53377ade.1615498565.git.andreyknvl%40google.com.
