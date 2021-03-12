Return-Path: <kasan-dev+bncBDX4HWEMTEBRBM7TVWBAMGQEWNTGFGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id DCD60338FE4
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:24:51 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id i26sf9839970ljn.13
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:24:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615559091; cv=pass;
        d=google.com; s=arc-20160816;
        b=j0lnCvJtMFCeUg42XAGvbr80EAtXhfGt6wjB011nrixL8vtOn5OGOUQy+kS2MmKyK+
         fZR2sKoi3JDhkYyAI/8ZqdA3deJMUpHCFfUkyBZA/I0KplpVsdvOQKqov6BINu/ZrS67
         /zQPzKM9hmLBw3eEO8KmD1MuF700uuSwjIVzKd+R4ptEK5ocf44mmr28zDq+rhNm/ioS
         Qldb2gvEbbzLUhn9xUo03hAJAiRUzK7Enasi1lxPMTYx08zxyQwuLhs2HzN/YYNDKcy3
         xuQJ300Jvqt/1plKSb5NJXeRqHBu8OYOr0BjLma7V8txF52D1uAqYUPRL9DUy+yti7hT
         87Gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=3IiPxKwM7TRYfyYLfeWLPCv/Ai2cb1PEWpKJHFRfxf4=;
        b=d6yZWFa/KbOXUjEZlnXsFElduY5FHlSbbEyX6ebhSiR/Ct6kRMpzto/+EJGanytje5
         hvIpEkm5UOdufNB4mU0eFI5WpkW4bdloyeYdRt+x5U9k+6nOyP+wHsSzwvY8Pc9bf70C
         F7hdgNE2Tw+KQIpbOSe85kMUFidIOiQQrnSSF+K9uV2Tx9mqcIFXr1iEk/xcdSHskCmJ
         Mr16g0IsFxGt7A5oG5XXH5wc9dckyA19T+fMT3ZUAYp73qLiJD7wsuBgnG/nRSULfqxx
         b+TnxXho+ajyQDCcFbdxsOs/sPTXRlbDa5aIcqsN5CWvF0+HqyqULD7cOrViMvRnutoD
         Tf9g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JVujzVqw;
       spf=pass (google.com: domain of 3sxllyaokcdo6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3sXlLYAoKCdo6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3IiPxKwM7TRYfyYLfeWLPCv/Ai2cb1PEWpKJHFRfxf4=;
        b=SrC6eDTQkEeWyprCS4XbJaMe7CW/1xLN5kLywBfmZCU/uMOItSrZnE5GOJE4kCxjf/
         v9INYl3lFyPhKuX09glOS8SJ1lS8YESTy/QRvOSUXNB6qyi2t3Hh3RRcv7EtCyJCAp00
         rMGI4zTEmYc6q9Ebk/5dLs6aTjjbeUBqNz1hQJPou+k8pMu4AZeCskOaob3j+7T+lIhe
         I3jnARfVaz1gBFgmdB6ZC0LJx0DeEM24UnHF8pZXj3GmbCVu5dLSzSkzq6xYrq9Jvz4h
         5oIEudEfi6X+c2HFK6Lf2Xy6wwNn/IBkvc03yNjszk9QFtRK3wuu/04Cgz2lHgpgbOos
         LIIg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3IiPxKwM7TRYfyYLfeWLPCv/Ai2cb1PEWpKJHFRfxf4=;
        b=GSQX8+KHhfBiPNJSZwoZ7+EDEt98J+gxqhw5JzGtf5J7FEQXhkmjK5F1IjKhX4/Evv
         p8KPpNWdr76V7VL+R0zgzNvEIlcQchJqm3lSNg3srG7b7/l+sHijyBTARWRzbaRbUGUL
         fx3oiygd0z+EadmaxsKX3CdvOR4BmX/+3p7ARWO/5z7VMuq/4HFese+psguE+nsb0UVf
         GVJYZ54vFPxbcTRhb07o19gKU16+GoUFiz1+/1JJo5hmree/4Dg/t/ZkUobijx7507fq
         RaDtpux5YcyJfZTZRcCx+wQqH49/xzLNxcrLRlJ9I9964yV7XqHK78WGezHDMgptO5mj
         s/0A==
X-Gm-Message-State: AOAM533rRPJpzyWuQytsdCQr3i2aE01PrIts25cQNCZuM7BLK7Q+xsgG
	rY16wQ9/PVgeYiUEQnFnccU=
X-Google-Smtp-Source: ABdhPJzE0k5PiXTOpEh1Ki8bn5Jghx06g7Ug580I6us/6nFlchbCErcDl69tjgKxTgCS2aPDxycuMA==
X-Received: by 2002:ac2:5ed0:: with SMTP id d16mr5486409lfq.569.1615559091513;
        Fri, 12 Mar 2021 06:24:51 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9212:: with SMTP id k18ls1971823ljg.8.gmail; Fri, 12 Mar
 2021 06:24:50 -0800 (PST)
X-Received: by 2002:a2e:924e:: with SMTP id v14mr2605413ljg.362.1615559090530;
        Fri, 12 Mar 2021 06:24:50 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615559090; cv=none;
        d=google.com; s=arc-20160816;
        b=wi7ldGqEeDnzJzJMdkB1sQSEPRIfaEx3GS+bhe5eI67QozIj3YLWDuHkNuEkHM1zK+
         qkI3SYA8zmhtTneuA5/4Q+VjXtDT9GnOhbpSvhGP2VhqmbBmXN5AZmRpcMMXTbTFuROa
         DkJAXf5NqM4GXvP0c7KqTvFtxZKgrcH9kENpP/rhKCFmzKh94d+RmoHXgyzenbsFLJzY
         133Gc+IOSFLiOc9GyWlLkbb10tUyYJMZT3VFBkf5oW35EpoKvYxQroSPtZsuUj81+AB0
         aAGGXR/osEjRWvDXDTCQ/TLGpSy0ftBKo11fA/Bv6CEXYFGWKiuIh+RaymkjvZ16jTgJ
         xbpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Ma9yDdtcKZ7wj/wPd+7FYcq2cw0HWN/l0auDvo6fPoI=;
        b=hrcnWMadvbwyykKKPU6LLILkgIknIAZ2//wrKrjLs0UYzqb3Ym1oDMwiOB+kBQBbMv
         2XbBtB/gBhOWJ0OTV10lZY1i1R3k9SMpxXNr388Wrw5zed//8MKXvV2aSvYCdrRNMOPX
         laonOLXIcHjp3P1QyH0s/OwRiN5i6CQT8xdw93Tr8RBFwE194b4yIi4DV8zWphs7vCdu
         8RdbfQI1JoSuU77HhPxda0NrabjKUpWw2nCyeGWmfEPbvbPkinG/HG0wyu950MXdbR0n
         1KYe9z1TxIKbYcqBhXOZuqHIO+h3gWfaWk643NGh4UZfcE3NfArR5LCNwLSd4ZfE9Ri0
         Cuag==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=JVujzVqw;
       spf=pass (google.com: domain of 3sxllyaokcdo6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3sXlLYAoKCdo6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id i30si243416lfj.6.2021.03.12.06.24.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 06:24:50 -0800 (PST)
Received-SPF: pass (google.com: domain of 3sxllyaokcdo6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id s192so5408677wme.6
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 06:24:50 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:95a:d8a8:4925:42be])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c18e:: with SMTP id
 y14mr2248623wmi.1.1615559089958; Fri, 12 Mar 2021 06:24:49 -0800 (PST)
Date: Fri, 12 Mar 2021 15:24:29 +0100
In-Reply-To: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
Message-Id: <f2f35fdab701f8c709f63d328f98aec2982c8acc.1615559068.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH v2 06/11] kasan: docs: update GENERIC implementation details section
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=JVujzVqw;       spf=pass
 (google.com: domain of 3sxllyaokcdo6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3sXlLYAoKCdo6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
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

Update the "Implementation details" section for generic KASAN:

- Don't mention kmemcheck, it's not present in the kernel anymore.
- Don't mention GCC as the only supported compiler.
- Update kasan_mem_to_shadow() definition to match actual code.
- Punctuation, readability, and other minor clean-ups.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 27 +++++++++++++--------------
 1 file changed, 13 insertions(+), 14 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 1189be9b4cb5..986410bf269f 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -200,12 +200,11 @@ Implementation details
 Generic KASAN
 ~~~~~~~~~~~~~
 
-From a high level perspective, KASAN's approach to memory error detection is
-similar to that of kmemcheck: use shadow memory to record whether each byte of
-memory is safe to access, and use compile-time instrumentation to insert checks
-of shadow memory on each memory access.
+Software KASAN modes use shadow memory to record whether each byte of memory is
+safe to access and use compile-time instrumentation to insert shadow memory
+checks before each memory access.
 
-Generic KASAN dedicates 1/8th of kernel memory to its shadow memory (e.g. 16TB
+Generic KASAN dedicates 1/8th of kernel memory to its shadow memory (16TB
 to cover 128TB on x86_64) and uses direct mapping with a scale and offset to
 translate a memory address to its corresponding shadow address.
 
@@ -214,23 +213,23 @@ address::
 
     static inline void *kasan_mem_to_shadow(const void *addr)
     {
-	return ((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
+	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
 		+ KASAN_SHADOW_OFFSET;
     }
 
 where ``KASAN_SHADOW_SCALE_SHIFT = 3``.
 
 Compile-time instrumentation is used to insert memory access checks. Compiler
-inserts function calls (__asan_load*(addr), __asan_store*(addr)) before each
-memory access of size 1, 2, 4, 8 or 16. These functions check whether memory
-access is valid or not by checking corresponding shadow memory.
+inserts function calls (``__asan_load*(addr)``, ``__asan_store*(addr)``) before
+each memory access of size 1, 2, 4, 8, or 16. These functions check whether
+memory accesses are valid or not by checking corresponding shadow memory.
 
-GCC 5.0 has possibility to perform inline instrumentation. Instead of making
-function calls GCC directly inserts the code to check the shadow memory.
-This option significantly enlarges kernel but it gives x1.1-x2 performance
-boost over outline instrumented kernel.
+With inline instrumentation, instead of making function calls, the compiler
+directly inserts the code to check shadow memory. This option significantly
+enlarges the kernel, but it gives an x1.1-x2 performance boost over the
+outline-instrumented kernel.
 
-Generic KASAN is the only mode that delays the reuse of freed object via
+Generic KASAN is the only mode that delays the reuse of freed objects via
 quarantine (see mm/kasan/quarantine.c for implementation).
 
 Software tag-based KASAN
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f2f35fdab701f8c709f63d328f98aec2982c8acc.1615559068.git.andreyknvl%40google.com.
