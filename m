Return-Path: <kasan-dev+bncBDX4HWEMTEBRB5URTGBAMGQE2GTX54I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 93A973312A4
	for <lists+kasan-dev@lfdr.de>; Mon,  8 Mar 2021 16:55:35 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id z18sf4543692ljz.7
        for <lists+kasan-dev@lfdr.de>; Mon, 08 Mar 2021 07:55:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615218935; cv=pass;
        d=google.com; s=arc-20160816;
        b=yP8/Aw08dTHvE+2cXfmZ4C9qMP+yY17cXaFlD2/7v/Az+RItV2SxfBZjkxA+Dej8az
         mA3W9PT7SPE7Rn7om7mUS+H/6JQnBQP2H+F6NY+bmPr/9IGuD28bb/JHr7EusBjaWocf
         TYwGAH68J4KEQD7dVLSnqW4Avx5xTUVoQ6TsDDRo3Sb6VaUlSKqAZ0d8xmFpMYvP2/60
         Ky+HYfXEj6ub2um1xyODzTl1DIdn6QNSrW8T4hI+jjWeFw4VOL82Op9Kvglgq8zSmTlm
         PCw/l0rfQyBEjK/8KiZogg3M8iNXEEuRx8cOiqPqBdybzgRBbrceooZdU+jM+SrtOdgo
         NQCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=EWgAPAd8MREVYJw681egjV6fV0Ec3fDXi33YaSOg/y0=;
        b=issCOHWLoalGBLeoUauKulT0/QbLWAvkHj+tdKTeXl34vuLzaNKiBMHBTko2EbTdZr
         BoFhQobIhLhm3IhlROc7ZpcBYhyO0r3WYO7S/l3pJBd7a7BDEbsxi8zfXK07bB+Q8kDm
         BGxk3v7CsznR0rV1e8FuxQ71QShrVFwvgmAmszIbTSe1u1VeYNQ7JIDpqrkieCNLQ6Np
         WftoggPDqzxshW7X0phLAO3dirlYeeOWhWSGq2UhC94iyQS2ZqUR55RRfBXsS1STj3sv
         8T6y2B4bAoVjPRENQ+MNcDOdT33zpeHXRczifKhsITAqC0qmAVQThstX2P5XM5j5Cx+e
         Oqeg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bzQ6TpLM;
       spf=pass (google.com: domain of 39uhgyaokcagivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=39UhGYAoKCagIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=EWgAPAd8MREVYJw681egjV6fV0Ec3fDXi33YaSOg/y0=;
        b=YY08G4r1orTgkh4wgWK7PN07+CxAcG0RMkT313e4GpIkmeny5eehgoQq+x5pg5P9MC
         rAI32LLHwcYwWPjUWbduM9UoJwl216cKTwtaa1WTQ/pUeKrkOKVKFYvDlVkjMz6g62Tm
         m9gYxQVFvLI5hEz2byYRRUkwddNOmZdVpbIQ946VrjaTSkVzNxBc80ltk9VITtk6bj6j
         AKqrmz8LUO0a2Vj7ieqLp12BCq2FgOeLAWWDURU0i9cDQx3/270BFrPRUO9O2Rp0YujN
         U6/P5OuaEjllY+SwbzkOwgJSH2iBlyuEcCmRTafoiAQSeDiFuDNwfhS/3k2zwb6J1HCE
         uxrg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EWgAPAd8MREVYJw681egjV6fV0Ec3fDXi33YaSOg/y0=;
        b=Uwf32qf81y79mZU4Wlj2R6m6nRZinZt7mnWjxGVXAl+sYjh6dyR5RcoFEMiUXzZyrp
         pAvQKM6tVC08X1LT6ZJIHQA8OXWn2qoIUXXHuRj4dtU3+nv8MTw52YhxfolSx6tir6e3
         ZvGsINDqFVPdPrkUw7TAzdZE7emR/G4WYqClikeJpo/6HE80eZH+c5P5vDINxzM4Qb2i
         rT+0CFTWJP/uDHm2Y2t73vxECZsB1Z5GmWzKAPHa+ZpMpnVjOTOUeFOTQLFLCQL/6r2L
         JFLwKKe6hNyKl+wkOLLd1k3HGc6Ybjbd2CWaxH7UZEJLFle7rx/MjeNeBeG6xg2ghv2p
         zKgA==
X-Gm-Message-State: AOAM532ro70iSt6C1eu/wZEpE1iNeYNtQfnJdtba36N+24MvDuhgwLNd
	BprIYY0U/9UEBBf2MU4XogE=
X-Google-Smtp-Source: ABdhPJx61R4MQ3WgqU5WNeo+xUrR7l2/rAeG073y82U6pdzZlHHnc1arNU9n9RWuGq9x4i8ienw/Zw==
X-Received: by 2002:ac2:46c1:: with SMTP id p1mr14281907lfo.161.1615218935130;
        Mon, 08 Mar 2021 07:55:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9191:: with SMTP id f17ls3548748ljg.11.gmail; Mon, 08
 Mar 2021 07:55:34 -0800 (PST)
X-Received: by 2002:a2e:b4b1:: with SMTP id q17mr14453911ljm.497.1615218934067;
        Mon, 08 Mar 2021 07:55:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615218934; cv=none;
        d=google.com; s=arc-20160816;
        b=YPMUIG7Ifwu2fFd2+7/bab8ToRj4BviikNaOMrd+Y0qfkg1XCtA7sGInbFBP/zElsP
         24RRXrKu4HBPq9oKdmkxTRoHTjhk/JU9vYKzXKfavD97qc3l2bN6GBIXlfpUtlQt1buX
         6G3KXTGozNt5SxrNtCSa3YFdSnq6ySN0lWlzNHDYf0hARHq7eFuWYj/JZjjS3nAQo+zS
         xpXWA/2tRUVWwzKvMh5J6Udyk2FlflQdsch74FVvRwMun9Dx8aEqW2LlaFU0GBm/ffph
         wXzaXWMVtwOBIl68Cmd9tiB7sTYg6EXegGyy3/l1eCG5tHsgqvQ/tu+xV/Ur7vGBlyKX
         03KQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=X6Kq0xGmQS5bAjA8d68Q+kULujL4fPHXHY/8pBMKlOo=;
        b=0euTMnhN1dPuksr8+jWRjjRDQLdF3ycLuaeMgo+NL7ZLSp/C6xxCHC0wj2O/KQ0h0K
         9F+WPTn0ZSGDT4IoKs9FTcCH83zdQb8EsuQVEQq3py4pVSwgRNYbt9zq2W+8VpNpZfM6
         JNp0GMSo6YO89ytRMQyjcpWt9GL1WHbUqEb/vY9RXquHzlTrmrEsAvW50EKqfK0NdzHi
         iPq+pUDOeDa/fLarnoeZVqxD5qxbM7x/2y2FVXeprA4+tO+yn34ooLFKrxlEeXj6BdrA
         yOtQr/ho21q+r/OJPnOIozwqvLS6D3dXrc2PHbaF0+wZdVJcid0n4JqkxHo7Q2WxGhoU
         1SPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bzQ6TpLM;
       spf=pass (google.com: domain of 39uhgyaokcagivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=39UhGYAoKCagIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id m6si74374ljp.7.2021.03.08.07.55.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 08 Mar 2021 07:55:34 -0800 (PST)
Received-SPF: pass (google.com: domain of 39uhgyaokcagivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id z6so4997672wrh.11
        for <kasan-dev@googlegroups.com>; Mon, 08 Mar 2021 07:55:34 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:85fb:aac9:69ed:e574])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c188:: with SMTP id
 y8mr22255933wmi.76.1615218933600; Mon, 08 Mar 2021 07:55:33 -0800 (PST)
Date: Mon,  8 Mar 2021 16:55:18 +0100
In-Reply-To: <cover.1615218180.git.andreyknvl@google.com>
Message-Id: <fe28431edf155e4749cd0f0b25c957f50744914d.1615218180.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1615218180.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.1.766.gb4fecdf3b7-goog
Subject: [PATCH v2 5/5] kasan, mm: integrate slab init_on_free with HW_TAGS
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bzQ6TpLM;       spf=pass
 (google.com: domain of 39uhgyaokcagivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=39UhGYAoKCagIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
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

This change uses the previously added memory initialization feature
of HW_TAGS KASAN routines for slab memory when init_on_free is enabled.

With this change, memory initialization memset() is no longer called
when both HW_TAGS KASAN and init_on_free are enabled. Instead, memory
is initialized in KASAN runtime.

For SLUB, the memory initialization memset() is moved into
slab_free_hook() that currently directly follows the initialization loop.
A new argument is added to slab_free_hook() that indicates whether to
initialize the memory or not.

To avoid discrepancies with which memory gets initialized that can be
caused by future changes, both KASAN hook and initialization memset()
are put together and a warning comment is added.

Combining setting allocation tags with memory initialization improves
HW_TAGS KASAN performance when init_on_free is enabled.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h | 10 ++++++----
 mm/kasan/common.c     | 13 +++++++------
 mm/slab.c             | 15 +++++++++++----
 mm/slub.c             | 43 ++++++++++++++++++++++++-------------------
 4 files changed, 48 insertions(+), 33 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 85f2a8786606..ed08c419a687 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -203,11 +203,13 @@ static __always_inline void * __must_check kasan_init_slab_obj(
 	return (void *)object;
 }
 
-bool __kasan_slab_free(struct kmem_cache *s, void *object, unsigned long ip);
-static __always_inline bool kasan_slab_free(struct kmem_cache *s, void *object)
+bool __kasan_slab_free(struct kmem_cache *s, void *object,
+			unsigned long ip, bool init);
+static __always_inline bool kasan_slab_free(struct kmem_cache *s,
+						void *object, bool init)
 {
 	if (kasan_enabled())
-		return __kasan_slab_free(s, object, _RET_IP_);
+		return __kasan_slab_free(s, object, _RET_IP_, init);
 	return false;
 }
 
@@ -313,7 +315,7 @@ static inline void *kasan_init_slab_obj(struct kmem_cache *cache,
 {
 	return (void *)object;
 }
-static inline bool kasan_slab_free(struct kmem_cache *s, void *object)
+static inline bool kasan_slab_free(struct kmem_cache *s, void *object, bool init)
 {
 	return false;
 }
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 7ea747b18c26..623cf94288a2 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -322,8 +322,8 @@ void * __must_check __kasan_init_slab_obj(struct kmem_cache *cache,
 	return (void *)object;
 }
 
-static inline bool ____kasan_slab_free(struct kmem_cache *cache,
-				void *object, unsigned long ip, bool quarantine)
+static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
+				unsigned long ip, bool quarantine, bool init)
 {
 	u8 tag;
 	void *tagged_object;
@@ -351,7 +351,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache,
 	}
 
 	kasan_poison(object, round_up(cache->object_size, KASAN_GRANULE_SIZE),
-			KASAN_KMALLOC_FREE, false);
+			KASAN_KMALLOC_FREE, init);
 
 	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine))
 		return false;
@@ -362,9 +362,10 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache,
 	return kasan_quarantine_put(cache, object);
 }
 
-bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
+bool __kasan_slab_free(struct kmem_cache *cache, void *object,
+				unsigned long ip, bool init)
 {
-	return ____kasan_slab_free(cache, object, ip, true);
+	return ____kasan_slab_free(cache, object, ip, true, init);
 }
 
 static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
@@ -409,7 +410,7 @@ void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
 			return;
 		kasan_poison(ptr, page_size(page), KASAN_FREE_PAGE, false);
 	} else {
-		____kasan_slab_free(page->slab_cache, ptr, ip, false);
+		____kasan_slab_free(page->slab_cache, ptr, ip, false, false);
 	}
 }
 
diff --git a/mm/slab.c b/mm/slab.c
index 936dd686dec9..3adfe5bc3e2e 100644
--- a/mm/slab.c
+++ b/mm/slab.c
@@ -3425,17 +3425,24 @@ static void cache_flusharray(struct kmem_cache *cachep, struct array_cache *ac)
 static __always_inline void __cache_free(struct kmem_cache *cachep, void *objp,
 					 unsigned long caller)
 {
+	bool init;
+
 	if (is_kfence_address(objp)) {
 		kmemleak_free_recursive(objp, cachep->flags);
 		__kfence_free(objp);
 		return;
 	}
 
-	if (unlikely(slab_want_init_on_free(cachep)))
+	/*
+	 * As memory initialization might be integrated into KASAN,
+	 * kasan_slab_free and initialization memset must be
+	 * kept together to avoid discrepancies in behavior.
+	 */
+	init = slab_want_init_on_free(cachep);
+	if (init && !kasan_has_integrated_init())
 		memset(objp, 0, cachep->object_size);
-
-	/* Put the object into the quarantine, don't touch it for now. */
-	if (kasan_slab_free(cachep, objp))
+	/* KASAN might put objp into memory quarantine, delaying its reuse. */
+	if (kasan_slab_free(cachep, objp, init))
 		return;
 
 	/* Use KCSAN to help debug racy use-after-free. */
diff --git a/mm/slub.c b/mm/slub.c
index f53df23760e3..37afe6251bcc 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -1532,7 +1532,8 @@ static __always_inline void kfree_hook(void *x)
 	kasan_kfree_large(x);
 }
 
-static __always_inline bool slab_free_hook(struct kmem_cache *s, void *x)
+static __always_inline bool slab_free_hook(struct kmem_cache *s,
+						void *x, bool init)
 {
 	kmemleak_free_recursive(x, s->flags);
 
@@ -1558,8 +1559,25 @@ static __always_inline bool slab_free_hook(struct kmem_cache *s, void *x)
 		__kcsan_check_access(x, s->object_size,
 				     KCSAN_ACCESS_WRITE | KCSAN_ACCESS_ASSERT);
 
-	/* KASAN might put x into memory quarantine, delaying its reuse */
-	return kasan_slab_free(s, x);
+	/*
+	 * As memory initialization might be integrated into KASAN,
+	 * kasan_slab_free and initialization memset's must be
+	 * kept together to avoid discrepancies in behavior.
+	 *
+	 * The initialization memset's clear the object and the metadata,
+	 * but don't touch the SLAB redzone.
+	 */
+	if (init) {
+		int rsize;
+
+		if (!kasan_has_integrated_init())
+			memset(kasan_reset_tag(x), 0, s->object_size);
+		rsize = (s->flags & SLAB_RED_ZONE) ? s->red_left_pad : 0;
+		memset((char *)kasan_reset_tag(x) + s->inuse, 0,
+		       s->size - s->inuse - rsize);
+	}
+	/* KASAN might put x into memory quarantine, delaying its reuse. */
+	return kasan_slab_free(s, x, init);
 }
 
 static inline bool slab_free_freelist_hook(struct kmem_cache *s,
@@ -1569,10 +1587,9 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
 	void *object;
 	void *next = *head;
 	void *old_tail = *tail ? *tail : *head;
-	int rsize;
 
 	if (is_kfence_address(next)) {
-		slab_free_hook(s, next);
+		slab_free_hook(s, next, false);
 		return true;
 	}
 
@@ -1584,20 +1601,8 @@ static inline bool slab_free_freelist_hook(struct kmem_cache *s,
 		object = next;
 		next = get_freepointer(s, object);
 
-		if (slab_want_init_on_free(s)) {
-			/*
-			 * Clear the object and the metadata, but don't touch
-			 * the redzone.
-			 */
-			memset(kasan_reset_tag(object), 0, s->object_size);
-			rsize = (s->flags & SLAB_RED_ZONE) ? s->red_left_pad
-							   : 0;
-			memset((char *)kasan_reset_tag(object) + s->inuse, 0,
-			       s->size - s->inuse - rsize);
-
-		}
 		/* If object's reuse doesn't have to be delayed */
-		if (!slab_free_hook(s, object)) {
+		if (!slab_free_hook(s, object, slab_want_init_on_free(s))) {
 			/* Move object to the new freelist */
 			set_freepointer(s, object, *head);
 			*head = object;
@@ -3235,7 +3240,7 @@ int build_detached_freelist(struct kmem_cache *s, size_t size,
 	}
 
 	if (is_kfence_address(object)) {
-		slab_free_hook(df->s, object);
+		slab_free_hook(df->s, object, false);
 		__kfence_free(object);
 		p[size] = NULL; /* mark object processed */
 		return size;
-- 
2.30.1.766.gb4fecdf3b7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fe28431edf155e4749cd0f0b25c957f50744914d.1615218180.git.andreyknvl%40google.com.
