Return-Path: <kasan-dev+bncBC7OBJGL2MHBBHHOSGFAMGQELH3JMZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id AE9C440F680
	for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 13:08:12 +0200 (CEST)
Received: by mail-lf1-x13c.google.com with SMTP id g4-20020a19ac04000000b003eb3973e4e2sf6447355lfc.17
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Sep 2021 04:08:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1631876892; cv=pass;
        d=google.com; s=arc-20160816;
        b=DQ4JNZ1HsE0WWJ3rqvZ5tLVxo8sHx9o9NZ312nVcImJPeXfpz6dd/gVkxC850X9DRT
         1NXSRd1CQddwsiBF8tYc+dl/B+W3d7zObPI/IXho0HMwNlO1tbsjJtUrUhy5V96+jX67
         /EohY8SFVLAwVSiYhlxZSO4vuMiKHW+h2yqnh+bXfDEpwbG6prGBeFZOAUUcmGbOvT17
         Ky+D7UpQCqOYdptHXu7OTfsgTX51AsV+QQIA3h0iwdQSieJNM3IZ+CGleN44fAC7YaTE
         WcF1yTvEZis+/DLMo5dCUJKuPsXsYxBpwoUjRNrqCKgmXtkYNNTtCI9idAXkARyhGztU
         vaLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=/Af+HrwrEfiLg2RVN4/tzTdJXFiRZsdSZ8Wq0xn6E+k=;
        b=UyN8H19Mdp76RTFFPuLBmPP8TLtfwrIvpDHneFWp+g+D3Oj96U9vI6g21deVkCpAhc
         ujX0XrsYVjAheT+u5QRxN67jU6EOSSlwxzz+i+pJbEMpGxROw9i78H0FXbqLPCkmozpe
         0Zqu7nlm/kDIm8C4jBp/+aaEuMmDPHtoriDWFbBHkg7+4oknAPNSda86Q0c+i5Tw2GtB
         IPpkcDJnLjkDU+IyOnQwd2F7FzJ9V7Eh1pqoRZ/d6qXrJr6oqo6yAUaA8gQj8YKQZzIQ
         HngFMqdNmEEQSX+QuFKJINjE+hq+4qw9tTjZFm2AS7T4gASFiiNg7rLzzVlvp/AoZ8AT
         bnwg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pSdK3RNT;
       spf=pass (google.com: domain of 3gndeyqukcsslsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3GndEYQUKCSsLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=/Af+HrwrEfiLg2RVN4/tzTdJXFiRZsdSZ8Wq0xn6E+k=;
        b=Y0kUwOqEvIaIaflbJaktpWTV50GydYm4+H+n+2hbSqOYoBlpn/+TOY2zjTe+VOGkON
         xLKXV6ad8NPWPiKevzP5mNozUWmb1whGpgMg5ovDmDpOTwpFmezFiDrwIlJJl3Lx3jVF
         ssYZ/KGbrhRkWaoZqnJBctoDJ9G0dK728o04xnb2xrZinDd90HnfxyGoh31ONh9JURaS
         3/oD8gm2wLMD8re4j/1KlQUR4OIvXujxUQVKPz9eam14Vmae6IL0Igli4RFvzfqf10MP
         Sl2FWL2rCCh8tQkI68TQ+s2hwjufkaLqUvIWsN6iHny/Fc9/4iG4KXqI9Us8IJIefLg0
         MmPA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/Af+HrwrEfiLg2RVN4/tzTdJXFiRZsdSZ8Wq0xn6E+k=;
        b=BYQ9BrBbH9Ltmm0lra5mut3o8ATkXoAPxuh6lF+RXREakxBfaRYN3QcebqDCcVHyrD
         n/m4s6CoHPYcifIcUN2QCHmn/igabqHMPzF0x6svjDOOSWgu0JH4KfXGPKkNdso4BuB2
         6f166/cAJB5xcYXh7agCB6wMWYmT0A+N04Uk/3oEU83T3/UTLMc5HkWx22Xg7KYjXuLC
         kHF+NfhRnW136rG7LmfQxwAkSH5ZQeJb0KODVj6n5EWHuQzWFiTkIVh9NCpuXmavDvpf
         5P50+xXNqYTrmkd8XgqRP4kRv4UeE8vNsxIwk2uhil7z/FA6kwH1Unq7FbB7tZ+2GMIJ
         OdGA==
X-Gm-Message-State: AOAM531EWbdRSNtJoHoaCmalpj08Peqw0IXDjUXlzbIZBxJdZ4CLVC/X
	S+/Oc+1C+CXum5M7FBHa0+Y=
X-Google-Smtp-Source: ABdhPJyv0fArmUqzBskqgJyhvHYf/oJq61yku02bQGLfrj/WOCdsV8trAhNfCWhOuxxFsf2JgmjVCg==
X-Received: by 2002:a05:6512:2003:: with SMTP id a3mr7547857lfb.654.1631876892214;
        Fri, 17 Sep 2021 04:08:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:261a:: with SMTP id bt26ls1592387lfb.3.gmail; Fri,
 17 Sep 2021 04:08:11 -0700 (PDT)
X-Received: by 2002:ac2:5182:: with SMTP id u2mr7729228lfi.676.1631876891071;
        Fri, 17 Sep 2021 04:08:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1631876891; cv=none;
        d=google.com; s=arc-20160816;
        b=fsbDdT78L8XKHisrwkPqtBqxNqviMXILJwHgzvdSG3k6VazdSuvvHjN76RmKKfROkX
         hpX/7a4jcYmk0CPc1+AmwtCy5zwSWg2vOUup0JF+6t0AxeZsDwE6G9VzJEYY7c9U6fQh
         MdWy8jYGwCteEoTaAq/VMmrBQWkFOzxKJH4TyFdHWptQLpX+Ds68ORdzqvkWbQIG7MNh
         fl6aleA8uKmzQrv7d/JhN2hJOfIIt62etaHCv96RiAbc0sPJS8yNmsNKSPFH+/ozzVM0
         kE61fqHbYF4u9UveS9C5UkTrZnjMovB9P7YoeG1h+GjIx4wwnvEB4rxvzUvuPX0fFsRA
         mGsA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=41pNklJY3f6bJq0CDDORqOJ/YTpKyKNMUQMh29DmX70=;
        b=qTDS41IOSmgy4cDBsBlJxVjRHJswhRn4MAfDd6bJ2O67qGdxgO9E9/JZk6a2HKtTy7
         tT6vvIgh2CYK8opvpuRZzE16j9fevXuVME6T6zTRkRE47iFxLab2Ta4HduMQu/B7bL/M
         soWCQ8YMzE3/jflyXZpl1jJ0LLoFyrGBnEm83D3pjs18v7+bKzp/DJyLw6iSBPv/NzPM
         H+JN9RTbWE6jN8yZM0pIcc1fL4yLY9qtt5FtbIVED0AkpXmETEBfS/3rjncTz/zbLL/x
         sbEFdfTHrhMG/ssIPuH5nZRwLS2+rnNi5ukALG1fhxYkvLPUSt8ybTMlpSw8ZpB8n4vA
         DfXQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=pSdK3RNT;
       spf=pass (google.com: domain of 3gndeyqukcsslsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3GndEYQUKCSsLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id f16si654583ljj.3.2021.09.17.04.08.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Sep 2021 04:08:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gndeyqukcsslsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id m16-20020a7bca50000000b002ee5287d4bfso1637729wml.7
        for <kasan-dev@googlegroups.com>; Fri, 17 Sep 2021 04:08:11 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:1a57:84a3:9bae:8070])
 (user=elver job=sendgmr) by 2002:a05:600c:8a9:: with SMTP id
 l41mr14384504wmp.29.1631876890388; Fri, 17 Sep 2021 04:08:10 -0700 (PDT)
Date: Fri, 17 Sep 2021 13:07:54 +0200
Message-Id: <20210917110756.1121272-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.33.0.464.g1972c5931b-goog
Subject: [PATCH 1/3] kfence: count unexpectedly skipped allocations
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Andrew Morton <akpm@linux-foundation.org>
Cc: Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Aleksandr Nogikh <nogikh@google.com>, Taras Madan <tarasmadan@google.com>, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=pSdK3RNT;       spf=pass
 (google.com: domain of 3gndeyqukcsslsclynvvnsl.jvtrhzhu-klcnvvnslnyvbwz.jvt@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3GndEYQUKCSsLScLYNVVNSL.JVTRHZHU-KLcNVVNSLNYVbWZ.JVT@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Maintain a counter to count allocations that are skipped due to being
incompatible (oversized, incompatible gfp flags) or no capacity.

This is to compute the fraction of allocations that could not be
serviced by KFENCE, which we expect to be rare.

Signed-off-by: Marco Elver <elver@google.com>
---
 mm/kfence/core.c | 20 ++++++++++++++++----
 1 file changed, 16 insertions(+), 4 deletions(-)

diff --git a/mm/kfence/core.c b/mm/kfence/core.c
index 7a97db8bc8e7..2755800f3e2a 100644
--- a/mm/kfence/core.c
+++ b/mm/kfence/core.c
@@ -112,6 +112,8 @@ enum kfence_counter_id {
 	KFENCE_COUNTER_FREES,
 	KFENCE_COUNTER_ZOMBIES,
 	KFENCE_COUNTER_BUGS,
+	KFENCE_COUNTER_SKIP_INCOMPAT,
+	KFENCE_COUNTER_SKIP_CAPACITY,
 	KFENCE_COUNTER_COUNT,
 };
 static atomic_long_t counters[KFENCE_COUNTER_COUNT];
@@ -121,6 +123,8 @@ static const char *const counter_names[] = {
 	[KFENCE_COUNTER_FREES]		= "total frees",
 	[KFENCE_COUNTER_ZOMBIES]	= "zombie allocations",
 	[KFENCE_COUNTER_BUGS]		= "total bugs",
+	[KFENCE_COUNTER_SKIP_INCOMPAT]	= "skipped allocations (incompatible)",
+	[KFENCE_COUNTER_SKIP_CAPACITY]	= "skipped allocations (capacity)",
 };
 static_assert(ARRAY_SIZE(counter_names) == KFENCE_COUNTER_COUNT);
 
@@ -272,7 +276,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 	}
 	raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);
 	if (!meta)
-		return NULL;
+		goto no_capacity;
 
 	if (unlikely(!raw_spin_trylock_irqsave(&meta->lock, flags))) {
 		/*
@@ -289,7 +293,7 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 		list_add_tail(&meta->list, &kfence_freelist);
 		raw_spin_unlock_irqrestore(&kfence_freelist_lock, flags);
 
-		return NULL;
+		goto no_capacity;
 	}
 
 	meta->addr = metadata_to_pageaddr(meta);
@@ -349,6 +353,10 @@ static void *kfence_guarded_alloc(struct kmem_cache *cache, size_t size, gfp_t g
 	atomic_long_inc(&counters[KFENCE_COUNTER_ALLOCS]);
 
 	return addr;
+
+no_capacity:
+	atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_CAPACITY]);
+	return NULL;
 }
 
 static void kfence_guarded_free(void *addr, struct kfence_metadata *meta, bool zombie)
@@ -740,8 +748,10 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 	 * Perform size check before switching kfence_allocation_gate, so that
 	 * we don't disable KFENCE without making an allocation.
 	 */
-	if (size > PAGE_SIZE)
+	if (size > PAGE_SIZE) {
+		atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_INCOMPAT]);
 		return NULL;
+	}
 
 	/*
 	 * Skip allocations from non-default zones, including DMA. We cannot
@@ -749,8 +759,10 @@ void *__kfence_alloc(struct kmem_cache *s, size_t size, gfp_t flags)
 	 * properties (e.g. reside in DMAable memory).
 	 */
 	if ((flags & GFP_ZONEMASK) ||
-	    (s->flags & (SLAB_CACHE_DMA | SLAB_CACHE_DMA32)))
+	    (s->flags & (SLAB_CACHE_DMA | SLAB_CACHE_DMA32))) {
+		atomic_long_inc(&counters[KFENCE_COUNTER_SKIP_INCOMPAT]);
 		return NULL;
+	}
 
 	/*
 	 * allocation_gate only needs to become non-zero, so it doesn't make
-- 
2.33.0.464.g1972c5931b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210917110756.1121272-1-elver%40google.com.
