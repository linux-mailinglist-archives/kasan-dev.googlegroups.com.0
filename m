Return-Path: <kasan-dev+bncBAABBPUKXCHAMGQEDWIQENY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 5DC76481F9D
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:15:10 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id eg23-20020a056402289700b003f80a27ca2bsf17586116edb.14
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:15:10 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891710; cv=pass;
        d=google.com; s=arc-20160816;
        b=Kt7xmjS6iFOOqnOn6+zvQ6pox4pt4kBoUsoWW5z5e5DkfJvYPasR/OfUJmGkSeaaGn
         kFKNrFf049Q687EVmyzkc0BIKyv454nAlVjJmGDUhfmpol/HAy5OZow6wut7lPKgjT8W
         RFudi8RbH5iNthqXlpmTMnc50V9CtWWQgGrDAml0NB414fxuBA9l5o3V8BNi7bC6wNIt
         RSqM+SN/fsgGbiV8jC14SEg8GQr2xXWbaVG4UQExzesMOr4Xa9bv7k1PIAK99WknKA9k
         +v3Qjh7l9v3t7e2yFD94XshK0VwIO3HDNaemUM572bbXYYhJ+ScdopYXfJeLxRyuYoRE
         RgHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=fwMjsm0kX92giVj5Ck9ay/OaPRw8mAX3YpcPs00NNMk=;
        b=K3Q3oob2hw46YqeYTd7tVCMJGvBSBMQLtlSk3LQMzoLId0Cn90ICZidxftJjxpPyu+
         T0/C2AEohkDVv9cBRuFmuPIquhJl1nSfCpEtv0fwcyfXxVXJ+8bnBxDfcb4N6ADfL/K2
         iPicIJ96EVnsy1SR+yon84mVpJJ+ozaWXGl+g0p7Lo1Ne3AP0oM96kzckIvEdyCbxLxg
         8GjfsDwAi8iZ8K5Yrp19gfghCefD8UBJCpXP6pEmu0XUJxetEghBlc6w//s4U746eiYJ
         nyJl1X+/cT5HW1WrRHdDcmAkLe+tzlvmaCasEMIHLwldMLODEX9EyE1wlnEHRGow6sAD
         dlIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=L0fhz0WO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fwMjsm0kX92giVj5Ck9ay/OaPRw8mAX3YpcPs00NNMk=;
        b=k6j9bK/f+Yu5PbpNMGwSQ1l35GjuWpxzZ6i/akhDttd0Kki9HHFqjOAvJ70GJyV9Z7
         zV3Q+AboqGKQCdNAsGG+7XxnlPfxCpONTkIq8JAMDvUBBjhzwfZKrF7XhPIJcTqZF4ey
         tknBYcK3FHL+FJFVKRWwgjEUCYzah9D4zzTs5+WCzNkqbD9YpVOmqv8YG6fwJQjePvsd
         21HJV0Q7CObcoxHCa5A6gppDGmwr/3AVPSwI6Xyj3z5wMcrbBkN0RGudz+yl9D1Wnf1s
         RuZerpgAMRDXKAo6YZeb9GFHMkG21VpZ+GJJoK3maj1dUVQHnlGbZ1h2PNESwrSEMh/G
         LENg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fwMjsm0kX92giVj5Ck9ay/OaPRw8mAX3YpcPs00NNMk=;
        b=bFXD5CRjQdq8Kwwe8ZGliLMYK6r9DEFLXp8BM7AsQI0mB2kd/yCK2WVK/xIptqiXDB
         j7Ck5MxRBlqmqnxYjj6ZSsZGxkecCFPQdLeKRvUDWrKGwRnlZdrTHLgQzzV80cmDNNjK
         bshsk0LMyKcLXZgscqRZx++5oFiJZvBsEf/9G9VhizkVz1qnwpOcbfsvmLT8d8zMJeWi
         jT+w1audp2Nh+5Us2ItnfnhV5l8rFaGf+ovKTK774r0EMpgSunBAECy1935PzQOTdK32
         O3UFqfAxEJu/duHInhCA8+mhjWzoTU/iBX4Poxw2vdHsIkMO7V/lCjwuRBhnKeJE6Rlm
         9Uag==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533zyoEaLOe1sU7vSPs336oY3QGj2pfHUwuEcJKvgDFiZkQXgpKH
	WyB0LYDEWRVFd5K9ztPpFhc=
X-Google-Smtp-Source: ABdhPJwBJ8Vp7WCpoZ5uB5rOeIiEIM99s80NMK+ey6YmTsfvzMzC00V321/7O77KeYy5RIY9RuQEMA==
X-Received: by 2002:a05:6402:2744:: with SMTP id z4mr32139267edd.68.1640891710170;
        Thu, 30 Dec 2021 11:15:10 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:270e:: with SMTP id y14ls198065edd.1.gmail; Thu, 30
 Dec 2021 11:15:09 -0800 (PST)
X-Received: by 2002:a05:6402:1907:: with SMTP id e7mr31524572edz.44.1640891709546;
        Thu, 30 Dec 2021 11:15:09 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891709; cv=none;
        d=google.com; s=arc-20160816;
        b=CTUZ0VwrUm0u8pLN2pddANzhATOL7Hp21sa8Im5O8rIQQTNxY3DGuyM+NIaecOx6+T
         423+qH59UIJbx3la/QzH0wV6ujOfj9oSx6Td01Vq5gDms8JgOFQ/FQMOXoaZW2a81Ydo
         EgTuK4EAvMH91EYpiIZcEnWqSkC9Gz4u1b5Ey97G75L5iQUot38kITEVt9FOM7assQ4d
         fQwoSvUSAqYDMRDUVk1mTmEAQpWcbhEzFf8lgIADdVuveaKxge1giOSCT38bBgs9pPjA
         dlGjl9J/z5FXxdm3byCAVu4YAcQCKpUBLra24XjPsaVQgvOIaIjJCmq9URImGC5PpCnY
         9Ynw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4jFZKwC+1fGM+Zh4UMZz7D7AiRXqN4olJqxCqj+PmMQ=;
        b=UsRcV1dGoXtanoaT7VwBeSb3cIwSIcC4yxvRzPZFP91nlie/etnYYnA6KfiWz3ngPb
         a8wVMYDVOanQFkJc5VcTygH8cmwiym/XzqH7M94HaE5ZXJG6VLebO7b+vnYRi0afAvtm
         5VXxpHyyiSrQ6xeMSVgF8jVzoAqP7Osstzr0Cpb/qkHV6ny66lejIyRz1ucJ9xptmx9m
         PoTEHRZEkZN0/JiCXVoFkxRMlYDAqIMMAAn77yuIOkTN+AAEcN6akDWh/a2TnBdMcJE1
         lbG60b63VbWIwgOfxN7f28B5sGNz7m+fkcEODr9iYws9RaR75rt3Z1mGEFyvUNsfL7EI
         6EEw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=L0fhz0WO;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id v5si963421edy.3.2021.12.30.11.15.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:15:09 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v5 20/39] kasan: add wrappers for vmalloc hooks
Date: Thu, 30 Dec 2021 20:14:45 +0100
Message-Id: <e234c974d83c90869e440872a534f96c9db44d1a.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=L0fhz0WO;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Add wrappers around functions that [un]poison memory for vmalloc
allocations. These functions will be used by HW_TAGS KASAN and
therefore need to be disabled when kasan=off command line argument
is provided.

This patch does no functional changes for software KASAN modes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>
---
 include/linux/kasan.h | 17 +++++++++++++++--
 mm/kasan/shadow.c     |  5 ++---
 2 files changed, 17 insertions(+), 5 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 46a63374c86f..da320069e7cf 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -424,8 +424,21 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end);
 
-void kasan_unpoison_vmalloc(const void *start, unsigned long size);
-void kasan_poison_vmalloc(const void *start, unsigned long size);
+void __kasan_unpoison_vmalloc(const void *start, unsigned long size);
+static __always_inline void kasan_unpoison_vmalloc(const void *start,
+						   unsigned long size)
+{
+	if (kasan_enabled())
+		__kasan_unpoison_vmalloc(start, size);
+}
+
+void __kasan_poison_vmalloc(const void *start, unsigned long size);
+static __always_inline void kasan_poison_vmalloc(const void *start,
+						 unsigned long size)
+{
+	if (kasan_enabled())
+		__kasan_poison_vmalloc(start, size);
+}
 
 #else /* CONFIG_KASAN_VMALLOC */
 
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index bf7ab62fbfb9..39d0b32ebf70 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -475,8 +475,7 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	}
 }
 
-
-void kasan_unpoison_vmalloc(const void *start, unsigned long size)
+void __kasan_unpoison_vmalloc(const void *start, unsigned long size)
 {
 	if (!is_vmalloc_or_module_addr(start))
 		return;
@@ -488,7 +487,7 @@ void kasan_unpoison_vmalloc(const void *start, unsigned long size)
  * Poison the shadow for a vmalloc region. Called as part of the
  * freeing process at the time the region is freed.
  */
-void kasan_poison_vmalloc(const void *start, unsigned long size)
+void __kasan_poison_vmalloc(const void *start, unsigned long size)
 {
 	if (!is_vmalloc_or_module_addr(start))
 		return;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/e234c974d83c90869e440872a534f96c9db44d1a.1640891329.git.andreyknvl%40google.com.
