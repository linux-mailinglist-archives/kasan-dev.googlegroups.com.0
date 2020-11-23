Return-Path: <kasan-dev+bncBDX4HWEMTEBRB2NQ6D6QKGQEOSX3CJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53f.google.com (mail-pg1-x53f.google.com [IPv6:2607:f8b0:4864:20::53f])
	by mail.lfdr.de (Postfix) with ESMTPS id E47BA2C157B
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:15:38 +0100 (CET)
Received: by mail-pg1-x53f.google.com with SMTP id a27sf13357477pga.6
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:15:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162537; cv=pass;
        d=google.com; s=arc-20160816;
        b=glQbFtFvXh3dSXuseOyclQy61H3rZeJpoboHCkVSqmqsBCHCtLhWtIAapwkAM2yAlF
         EM22cWhnqdz2ocI7J9VHvIRXeE1swprXs6wm3MdxLViMYVoWSXzAMj1omKsrKWuPD93e
         N2q5Yic838ucNuDQK4ANoqllbGVzIwx8DTOE41wNkFlNsGnD4hyFMp8tYL+3Q0urRBVw
         Od9Cl2DC8ybXDgc+iVXbN3MR5vA68npfnibUJvbBdJptENuZ4RGLsjtEHSzi0tRW+Hke
         hWAVPMc78fIgDV2WtYD+CuUB8+scpFra9dnhw7rDD393PG+EUJ+fn8FLMS9ALwxaoXgF
         igCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=w8mmFsD3PclFt+NxNQBU7WARFAKBD09e58BjdxgkxP0=;
        b=0DEttROmtrZHFFO+cqJy4xiEINlIs7+Xjs1iL5qQND2Uu0bRNV8/ivME0NyupnFYi8
         Vn+6YdMgjPIvfDMrGzHrqUOYZFLL2DYTUSEiJ7duRlb6PO+6Qy2ftiP8uWb5qALNvfJ8
         Ulpp/tzJC6ue4X17DOgroeA138ZpurnppGNM/aalFKvEh7Ng9eJOEhUksbhEl92ScYy3
         5+E/HoOvfY7Yuye27QJ7/IUPjLMQin8z7URctrFeDgbHlwJgTxc9hUWi4KC0GNxOL2Dm
         yHD3x9qLeNOoiUNDAke53yjn40y1cTHG6g/Rrbujcj0werNpajv472DqExTOgtuOg/wM
         R1WQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Va6STH1a;
       spf=pass (google.com: domain of 3abi8xwokcy0r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3aBi8XwoKCY0r4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=w8mmFsD3PclFt+NxNQBU7WARFAKBD09e58BjdxgkxP0=;
        b=PvdulMG+xj0iI+9Vjz3zNlm7zjqaGwmX48eO0fAV3LpQmf8NihYZxXxDiMrr2+QNFD
         p6wFiEMc1mijbnmnEKfayEJ2SLe43TXQqp2UbpBVrRhpAFnRKBVEaiPdVVOpgISOjKYh
         vIk4+EYDImO5s7hcRoUrO4QpsHylHlVda3j9Gf9+24gMX8BQWGukuarHdEpvYfFLH/8n
         aYB5wfVFmU4mBnduN3TukjYrB9HJWmzT47kYvA32xAYrj1I3bgsl+nl6tDm09nxotdZN
         a9sM6cmdwMxkWWb1+BxI/aF69lgvDpJ04Bl6dXCr7WUPykPxbEIea9Nq/UoJZJ2SJPi0
         M6Uw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=w8mmFsD3PclFt+NxNQBU7WARFAKBD09e58BjdxgkxP0=;
        b=qhd1JIn7lo/2b99EJvspzc/bF3d902gYiqQDhgb++xyQNX7M25JyExRFTnKY25O74Z
         0ifBtVgb/fvme7zk2sHc+mPSUiXElgCpZITNPaNwcWujscIP9HPsgv5xpSxF3u26N7bD
         BqFrziqI1ITjNucEABquFiN+S9RpzrfqkarBUGe+ApEcf4VnkF77SCcrGznnJe7v9JCJ
         SiR2xX8zkQSQawZMewTIsG2sYi4WJCtxn8jM3+W1cDpMZnx3UBuXVyMT3EnWLT7v411l
         H6d9wtwAoK26t0fKv2vpkU3Ei5rZZ09FVKPgW5j/+M7aH5e7211zpDynmtq1lBk1spks
         i6XQ==
X-Gm-Message-State: AOAM530J4f8+BZgoC9dT3MpzMmMlbVR0a5Dy86/bYLvQ3J/ynogjl+En
	iS9/JQFzn4J+Fchrhny4V9k=
X-Google-Smtp-Source: ABdhPJxCyfkE/phs+D79svYmuct82z8RFfJV0sLsPCSgCLloa/eQzZq6ZjoPAcYCnB+E3tkqkJwffg==
X-Received: by 2002:a65:64cc:: with SMTP id t12mr977904pgv.126.1606162537679;
        Mon, 23 Nov 2020 12:15:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:ee93:: with SMTP id a19ls3581042pld.10.gmail; Mon,
 23 Nov 2020 12:15:37 -0800 (PST)
X-Received: by 2002:a17:90a:5c85:: with SMTP id r5mr649603pji.199.1606162537233;
        Mon, 23 Nov 2020 12:15:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162537; cv=none;
        d=google.com; s=arc-20160816;
        b=Dt106qBSFOTDGH1y5D6FNZsS+Z/H2gZVbOc6mKSQt2/tluvQZtTdq2wRSGD69OIims
         sXrpkKzBCk0ltSExT1mnvSOZ1piwRBGyksRM+uugYGZzjC0piTFEYDio/nYM+1YDpV+i
         S9NmfoYZe7qhHdfmHF/uqSKettc90egzcB3Cq2IEPyI07aB2RJ8kEjvmNAq3fWfxVWlD
         38F3RPYFcUoYdYgAgaZGdpbL4aTp9+9cZttWKb2pbyyyz+kEC+2cNZeQ8yDWRQoTjXXA
         Gyx4vUTZrhr1Ef4GjieTWQMCZq9HLQt58s5svQFbTliTZ4cI7XOJwmOwjpBCFC1CgMgl
         5XIw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=jlSh18JA+tyc0YTMYNGOzncWOn17Ui2VWegewVhQQAI=;
        b=rh+kr4PTfI+KEqdCgx8CYT877JxC3bLX99zQicAXuAwyKURfjKsF1JaPb9J9ykHMT2
         C61P6+w3Z2E8mqawjr1KyGMv0H0XoMTXuXX53Ca4r5uhHL6nfyuCH8z90cDBE59Q1nJH
         enYNYeyHvYfNUyDdx/oU2ALXKDxUofmgAzyXFeDkYxJjECawLBBsTrsondNDaEqxJfhB
         NX8VFpeZJ2GkU9DETOwppNfqKoU8WKrUwY8fR9vle05IzOLk7LvumA+BjtXbxeD9bBXl
         d0nxE5Jv3s69c7yDDm3knyiBC5fZcVo6bqijJTgZG67TeDC8V8cVUwT/xZsNPZT+/t4r
         4BeA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Va6STH1a;
       spf=pass (google.com: domain of 3abi8xwokcy0r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3aBi8XwoKCY0r4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id 123si83200pge.3.2020.11.23.12.15.37
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:15:37 -0800 (PST)
Received-SPF: pass (google.com: domain of 3abi8xwokcy0r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id r124so8099699qkd.8
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:15:37 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:804a:: with SMTP id
 68mr1172222qva.1.1606162536399; Mon, 23 Nov 2020 12:15:36 -0800 (PST)
Date: Mon, 23 Nov 2020 21:14:48 +0100
In-Reply-To: <cover.1606162397.git.andreyknvl@google.com>
Message-Id: <37497e940bfd4b32c0a93a702a9ae4cf061d5392.1606162397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606162397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v4 18/19] kasan, mm: allow cache merging with no metadata
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>, Vincenzo Frascino <Vincenzo.Frascino@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Va6STH1a;       spf=pass
 (google.com: domain of 3abi8xwokcy0r4u8vf14c2x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3aBi8XwoKCY0r4u8vF14C2x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--andreyknvl.bounces.google.com;
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

The reason cache merging is disabled with KASAN is because KASAN puts its
metadata right after the allocated object. When the merged caches have
slightly different sizes, the metadata ends up in different places, which
KASAN doesn't support.

It might be possible to adjust the metadata allocation algorithm and make
it friendly to the cache merging code. Instead this change takes a simpler
approach and allows merging caches when no metadata is present. Which is
the case for hardware tag-based KASAN with kasan.mode=prod.

Co-developed-by: Vincenzo Frascino <Vincenzo.Frascino@arm.com>
Signed-off-by: Vincenzo Frascino <Vincenzo.Frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Link: https://linux-review.googlesource.com/id/Ia114847dfb2244f297d2cb82d592bf6a07455dba
---
 include/linux/kasan.h | 21 +++++++++++++++++++--
 mm/kasan/common.c     | 11 +++++++++++
 mm/slab_common.c      |  3 ++-
 3 files changed, 32 insertions(+), 3 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 2610438120ce..83860aa4e89c 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -81,17 +81,30 @@ struct kasan_cache {
 };
 
 #ifdef CONFIG_KASAN_HW_TAGS
+
 DECLARE_STATIC_KEY_FALSE(kasan_flag_enabled);
+
 static __always_inline bool kasan_enabled(void)
 {
 	return static_branch_likely(&kasan_flag_enabled);
 }
-#else
+
+#else /* CONFIG_KASAN_HW_TAGS */
+
 static inline bool kasan_enabled(void)
 {
 	return true;
 }
-#endif
+
+#endif /* CONFIG_KASAN_HW_TAGS */
+
+slab_flags_t __kasan_never_merge(void);
+static __always_inline slab_flags_t kasan_never_merge(void)
+{
+	if (kasan_enabled())
+		return __kasan_never_merge();
+	return 0;
+}
 
 void __kasan_unpoison_range(const void *addr, size_t size);
 static __always_inline void kasan_unpoison_range(const void *addr, size_t size)
@@ -238,6 +251,10 @@ static inline bool kasan_enabled(void)
 {
 	return false;
 }
+static inline slab_flags_t kasan_never_merge(void)
+{
+	return 0;
+}
 static inline void kasan_unpoison_range(const void *address, size_t size) {}
 static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
 static inline void kasan_free_pages(struct page *page, unsigned int order) {}
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 249ccba1ecf5..da79f340f3a6 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -87,6 +87,17 @@ asmlinkage void kasan_unpoison_task_stack_below(const void *watermark)
 }
 #endif /* CONFIG_KASAN_STACK */
 
+/*
+ * Only allow cache merging when stack collection is disabled and no metadata
+ * is present.
+ */
+slab_flags_t __kasan_never_merge(void)
+{
+	if (kasan_stack_collection_enabled())
+		return SLAB_KASAN;
+	return 0;
+}
+
 void __kasan_alloc_pages(struct page *page, unsigned int order)
 {
 	u8 tag;
diff --git a/mm/slab_common.c b/mm/slab_common.c
index 0b5ae1819a8b..075b23ce94ec 100644
--- a/mm/slab_common.c
+++ b/mm/slab_common.c
@@ -19,6 +19,7 @@
 #include <linux/seq_file.h>
 #include <linux/proc_fs.h>
 #include <linux/debugfs.h>
+#include <linux/kasan.h>
 #include <asm/cacheflush.h>
 #include <asm/tlbflush.h>
 #include <asm/page.h>
@@ -54,7 +55,7 @@ static DECLARE_WORK(slab_caches_to_rcu_destroy_work,
  */
 #define SLAB_NEVER_MERGE (SLAB_RED_ZONE | SLAB_POISON | SLAB_STORE_USER | \
 		SLAB_TRACE | SLAB_TYPESAFE_BY_RCU | SLAB_NOLEAKTRACE | \
-		SLAB_FAILSLAB | SLAB_KASAN)
+		SLAB_FAILSLAB | kasan_never_merge())
 
 #define SLAB_MERGE_SAME (SLAB_RECLAIM_ACCOUNT | SLAB_CACHE_DMA | \
 			 SLAB_CACHE_DMA32 | SLAB_ACCOUNT)
-- 
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/37497e940bfd4b32c0a93a702a9ae4cf061d5392.1606162397.git.andreyknvl%40google.com.
