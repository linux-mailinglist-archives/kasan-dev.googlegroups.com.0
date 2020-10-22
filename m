Return-Path: <kasan-dev+bncBDX4HWEMTEBRB7UNY36AKGQEYZNHBQA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 45A9A295FB7
	for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 15:20:00 +0200 (CEST)
Received: by mail-yb1-xb3f.google.com with SMTP id c9sf1766321ybs.8
        for <lists+kasan-dev@lfdr.de>; Thu, 22 Oct 2020 06:20:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603372799; cv=pass;
        d=google.com; s=arc-20160816;
        b=nPaPA/xM630EjXrJdbvqvxz0nmzWO/lKdH39mDo2FR0hguAhp33eLxFIo3lu7lRnUJ
         dvloq6gCO9bpJmnp9Y/PKZydiSmxAhaXFmje+m5VKJNYVQgslSueGy36qlD0ey5YH3Xk
         DZjYboU2QFy+mGL5Jr/WAND8zL2PzVzyYF75ObTUsyQ1heN9Zo18Vtz9nptAAyQH8+bh
         foLjJp/hn5qh145chpjVRnjDLKPfygb5IU2L53hY+JbInxJPAmjtPpgwyhWphFATwjel
         2GubLBEWGyiXirme+yKFjZnWOWZadq1C5SW+fli8EY9hsfiblS5mIT++EuQ17EnljdOe
         rwYw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=6YxMiadkcYukfhTC4TniM4njTIOooqrsIHeM7FCzsSs=;
        b=EuI7gMUyioqRN3MYszMdbDbbpXX2oB9DpnSZVMGfxUPciRNJFVNKaqTGWyilptViP+
         2OJNt8FBFFr/c0wvVIWc4vsNraiwJvsn96DwOl/bbXNwBcADfI8n+OvcEwt9UhGLnGqT
         kalHrAhUDGko8KH+N/NN8m6DSAP15kxqbcf9NaWMm/9dvKn+NK5zqdoUffpTRapof70p
         Y2nE3YxY7h01g7/MJbRT1XONjDLJU6T+OscxxyZRy4Mlmhwx/zM5vNOXT8wqVCuXyZou
         FaJIqNInQjvjyru/TLsu0xHyPGUP0NKQQIgolcM8pvqX0iJl8RbMuRugtQ4BL7m7xz6o
         UXqQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VesxqZfV;
       spf=pass (google.com: domain of 3_yarxwokcvqw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3_YaRXwoKCVQw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=6YxMiadkcYukfhTC4TniM4njTIOooqrsIHeM7FCzsSs=;
        b=qZMLTjM2aOdstgM0TKHf1CGDKQTEenTNoxIaV7HAjMraYsfGUWubKchIvgGakBB/vR
         H1Cyo9/RKynhsXeKdFjAmaV0COEt1VKaF0EMUCdmFSSsF41so08QZvhen/ZTM+fRQzjy
         ZkvNfryCcodtp5TJPRvYaBSjEKN5onFh1+hg8GqObLYTCX5Tokxen1buWIGhmtbwH3sN
         OKJVqJfxlb0xjAkj0y+1Ilh+JZQ9CRb7Ez3APaVnAsGT6TPs0KmFGKlCGJDWc3ZPnO2n
         IGdXLTvcbc0vH7BWBzh5htbe797tKpdm3c6WfKpKIzr66w3zYWLLLmkX0ISQn2Pju5TE
         yvEQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6YxMiadkcYukfhTC4TniM4njTIOooqrsIHeM7FCzsSs=;
        b=Ltx+gMWm9SbNk4rApUYG2Ji/GUHNyIaCASJHSQzdLVA5vUqiKBnOKZKc9YPOaPkS2u
         RIg0j+H7+kO/LuN0p/TUA84lJyKNbl2oiJrqAbepjTXGnIcDL7GopmYz6p/pW25KrawO
         CZxickUPz6GTAcn6iS4NT5PqDrxdmKRG+5lGilIViSvXelkcfNDkcn0oZ2YhOdtcAvKA
         KbFh8o0Txhq5KKhgLz0ECOsaMGlAhc8K9sjzrWos+wCxziNG/9j//JluBRRRuWFZmd11
         d1nIYXebz6U/PO5Hwh7EmFkfpuUIKs98wSReFhvbGqYmutsfM28P0eQb7oEGedNILXP0
         DTVQ==
X-Gm-Message-State: AOAM533RB++dhZn7KUofbs+AeffoCbc2ZIvLbQmjZZEFQfkS22iZ+P0H
	W2Nyga5DIzPB8rePiRvm/J4=
X-Google-Smtp-Source: ABdhPJwu6T0fDEgX2UngOYrdN0VbETpjaJWLDvy4Z0YKXeu1OUzme8KFK6Mam6R2+H7BTV4Slz6jdA==
X-Received: by 2002:a25:aa72:: with SMTP id s105mr3471589ybi.105.1603372799099;
        Thu, 22 Oct 2020 06:19:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:700b:: with SMTP id l11ls815323ybc.5.gmail; Thu, 22 Oct
 2020 06:19:58 -0700 (PDT)
X-Received: by 2002:a25:a407:: with SMTP id f7mr3463778ybi.128.1603372798497;
        Thu, 22 Oct 2020 06:19:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603372798; cv=none;
        d=google.com; s=arc-20160816;
        b=lCmZZ+dKx6ociMT5iDyqgDr4tQx0wqQLcGdp1b+Xi7PHf+v/DeOinm4/Xg6pT1L25w
         eS/aNtPxJV2dyknmUB6t2odlrL+zdosiKF5766/nG1U47gmtPCyE0sp2ZX9KvOHyb8nx
         aZoZqmGhIjwPjsgzPNPs+gisrkxvXbEAmZxWcSaJgqgvVWKutYjF5cc47Rcyhr2UozsN
         kpQI8l4fmQrtAAMMow5soIaonosXCnZS49SNWzWT/PHvywBL9RP86sAm/XK9ioq40ATp
         oMiZ5d5SK6ccBQUvxQGIvyO/J6VU+lCsmu4SIHQZrHrG56iDWhWNmxbe/I/FJXuR7IX/
         enVA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=hXyFPEk4foicA9MHUn1LEAgXXkiWJy7tayx5woeXroY=;
        b=RORcI3116FUTrMNy5xLKYyiNMvV4QV0scUR14PYvJVAIUJIxtIFyF8cZAHwXufeLPP
         dnqYi4yxnhfc/iwJVUdCUfGj7zrpQiTNmRTLTkN+yExOFVFFFfoCk7EjC3i+kzY/wZZO
         Z80AJ7yew2MS75Q8pQbMtW0dfR8Rv1hx/pvPv95q6GYoU+sfTDT1/xaw0QkUhVwFFPPz
         qHUyg3wt70iX1lIKswHd/0593WAmGT05BvEcesiPg8B9ziYgYze7wBxWHFH/hyWA3V7v
         D6NGsk4PH0tUd3DvD35AeaOgzYssvOVDhDiKUKsm5jqtoUlJotOfDQQd1OWp+RvaUjhh
         2uGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VesxqZfV;
       spf=pass (google.com: domain of 3_yarxwokcvqw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3_YaRXwoKCVQw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id h89si147016ybi.5.2020.10.22.06.19.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 22 Oct 2020 06:19:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_yarxwokcvqw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id y77so1000893qkb.8
        for <kasan-dev@googlegroups.com>; Thu, 22 Oct 2020 06:19:58 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:8d05:: with SMTP id
 r5mr2364576qvb.31.1603372797908; Thu, 22 Oct 2020 06:19:57 -0700 (PDT)
Date: Thu, 22 Oct 2020 15:19:06 +0200
In-Reply-To: <cover.1603372719.git.andreyknvl@google.com>
Message-Id: <6a4a7626bf280871518656f4fa89cb064740baf7.1603372719.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1603372719.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.0.rc1.297.gfa9743e501-goog
Subject: [PATCH RFC v2 14/21] kasan: add and integrate kasan boot parameters
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Kostya Serebryany <kcc@google.com>, 
	Peter Collingbourne <pcc@google.com>, Serban Constantinescu <serbanc@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VesxqZfV;       spf=pass
 (google.com: domain of 3_yarxwokcvqw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3_YaRXwoKCVQw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
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

TODO: no meaningful description here yet, please see the cover letter
      for this RFC series.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/If7d37003875b2ed3e0935702c8015c223d6416a4
---
 mm/kasan/common.c  |  92 +++++++++++++-----------
 mm/kasan/generic.c |   5 ++
 mm/kasan/hw_tags.c | 169 ++++++++++++++++++++++++++++++++++++++++++++-
 mm/kasan/kasan.h   |   9 +++
 mm/kasan/report.c  |  14 +++-
 mm/kasan/sw_tags.c |   5 ++
 6 files changed, 250 insertions(+), 44 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 1a5e6c279a72..cc129ef62ab1 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -129,35 +129,37 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 	unsigned int redzone_size;
 	int redzone_adjust;
 
-	/* Add alloc meta. */
-	cache->kasan_info.alloc_meta_offset = *size;
-	*size += sizeof(struct kasan_alloc_meta);
-
-	/* Add free meta. */
-	if (IS_ENABLED(CONFIG_KASAN_GENERIC) &&
-	    (cache->flags & SLAB_TYPESAFE_BY_RCU || cache->ctor ||
-	     cache->object_size < sizeof(struct kasan_free_meta))) {
-		cache->kasan_info.free_meta_offset = *size;
-		*size += sizeof(struct kasan_free_meta);
-	}
-
-	redzone_size = optimal_redzone(cache->object_size);
-	redzone_adjust = redzone_size -	(*size - cache->object_size);
-	if (redzone_adjust > 0)
-		*size += redzone_adjust;
-
-	*size = min_t(unsigned int, KMALLOC_MAX_SIZE,
-			max(*size, cache->object_size + redzone_size));
+	if (static_branch_unlikely(&kasan_stack)) {
+		/* Add alloc meta. */
+		cache->kasan_info.alloc_meta_offset = *size;
+		*size += sizeof(struct kasan_alloc_meta);
+
+		/* Add free meta. */
+		if (IS_ENABLED(CONFIG_KASAN_GENERIC) &&
+		    (cache->flags & SLAB_TYPESAFE_BY_RCU || cache->ctor ||
+		     cache->object_size < sizeof(struct kasan_free_meta))) {
+			cache->kasan_info.free_meta_offset = *size;
+			*size += sizeof(struct kasan_free_meta);
+		}
 
-	/*
-	 * If the metadata doesn't fit, don't enable KASAN at all.
-	 */
-	if (*size <= cache->kasan_info.alloc_meta_offset ||
-			*size <= cache->kasan_info.free_meta_offset) {
-		cache->kasan_info.alloc_meta_offset = 0;
-		cache->kasan_info.free_meta_offset = 0;
-		*size = orig_size;
-		return;
+		redzone_size = optimal_redzone(cache->object_size);
+		redzone_adjust = redzone_size -	(*size - cache->object_size);
+		if (redzone_adjust > 0)
+			*size += redzone_adjust;
+
+		*size = min_t(unsigned int, KMALLOC_MAX_SIZE,
+				max(*size, cache->object_size + redzone_size));
+
+		/*
+		 * If the metadata doesn't fit, don't enable KASAN at all.
+		 */
+		if (*size <= cache->kasan_info.alloc_meta_offset ||
+				*size <= cache->kasan_info.free_meta_offset) {
+			cache->kasan_info.alloc_meta_offset = 0;
+			cache->kasan_info.free_meta_offset = 0;
+			*size = orig_size;
+			return;
+		}
 	}
 
 	*flags |= SLAB_KASAN;
@@ -165,10 +167,12 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 
 size_t kasan_metadata_size(struct kmem_cache *cache)
 {
-	return (cache->kasan_info.alloc_meta_offset ?
-		sizeof(struct kasan_alloc_meta) : 0) +
-		(cache->kasan_info.free_meta_offset ?
-		sizeof(struct kasan_free_meta) : 0);
+	if (static_branch_unlikely(&kasan_stack))
+		return (cache->kasan_info.alloc_meta_offset ?
+			sizeof(struct kasan_alloc_meta) : 0) +
+			(cache->kasan_info.free_meta_offset ?
+			sizeof(struct kasan_free_meta) : 0);
+	return 0;
 }
 
 struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
@@ -270,8 +274,10 @@ void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
 	if (!(cache->flags & SLAB_KASAN))
 		return (void *)object;
 
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	__memset(alloc_meta, 0, sizeof(*alloc_meta));
+	if (static_branch_unlikely(&kasan_stack)) {
+		alloc_meta = kasan_get_alloc_meta(cache, object);
+		__memset(alloc_meta, 0, sizeof(*alloc_meta));
+	}
 
 	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
 		object = set_tag(object, assign_tag(cache, object, true, false));
@@ -308,15 +314,19 @@ static bool __kasan_slab_free(struct kmem_cache *cache, void *object,
 	rounded_up_size = round_up(cache->object_size, KASAN_GRANULE_SIZE);
 	kasan_poison_memory(object, rounded_up_size, KASAN_KMALLOC_FREE);
 
-	if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
-			unlikely(!(cache->flags & SLAB_KASAN)))
-		return false;
+	if (static_branch_unlikely(&kasan_stack)) {
+		if ((IS_ENABLED(CONFIG_KASAN_GENERIC) && !quarantine) ||
+				unlikely(!(cache->flags & SLAB_KASAN)))
+			return false;
+
+		kasan_set_free_info(cache, object, tag);
 
-	kasan_set_free_info(cache, object, tag);
+		quarantine_put(cache, object);
 
-	quarantine_put(cache, object);
+		return IS_ENABLED(CONFIG_KASAN_GENERIC);
+	}
 
-	return IS_ENABLED(CONFIG_KASAN_GENERIC);
+	return false;
 }
 
 bool kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
@@ -355,7 +365,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 	kasan_poison_memory((void *)redzone_start, redzone_end - redzone_start,
 		KASAN_KMALLOC_REDZONE);
 
-	if (cache->flags & SLAB_KASAN)
+	if (static_branch_unlikely(&kasan_stack) && (cache->flags & SLAB_KASAN))
 		set_alloc_info(cache, (void *)object, flags);
 
 	return set_tag(object, tag);
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index d259e4c3aefd..20a1e753e0c5 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -33,6 +33,11 @@
 #include "kasan.h"
 #include "../slab.h"
 
+/* See the comments in hw_tags.c */
+DEFINE_STATIC_KEY_TRUE_RO(kasan_enabled);
+EXPORT_SYMBOL(kasan_enabled);
+DEFINE_STATIC_KEY_TRUE_RO(kasan_stack);
+
 /*
  * All functions below always inlined so compiler could
  * perform better optimizations in each of __asan_loadX/__assn_storeX
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 915142da6b57..bccd781011ad 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -8,6 +8,8 @@
 
 #define pr_fmt(fmt) "kasan: " fmt
 
+#include <linux/init.h>
+#include <linux/jump_label.h>
 #include <linux/kasan.h>
 #include <linux/kernel.h>
 #include <linux/memory.h>
@@ -17,10 +19,175 @@
 
 #include "kasan.h"
 
+enum kasan_arg_mode {
+	KASAN_ARG_MODE_OFF,
+	KASAN_ARG_MODE_PROD,
+	KASAN_ARG_MODE_FULL,
+};
+
+enum kasan_arg_stack {
+	KASAN_ARG_STACK_DEFAULT,
+	KASAN_ARG_STACK_OFF,
+	KASAN_ARG_STACK_ON,
+};
+
+enum kasan_arg_trap {
+	KASAN_ARG_TRAP_DEFAULT,
+	KASAN_ARG_TRAP_ASYNC,
+	KASAN_ARG_TRAP_SYNC,
+};
+
+enum kasan_arg_fault {
+	KASAN_ARG_FAULT_DEFAULT,
+	KASAN_ARG_FAULT_REPORT,
+	KASAN_ARG_FAULT_PANIC,
+};
+
+static enum kasan_arg_mode kasan_arg_mode __ro_after_init;
+static enum kasan_arg_stack kasan_arg_stack __ro_after_init;
+static enum kasan_arg_fault kasan_arg_fault __ro_after_init;
+static enum kasan_arg_trap kasan_arg_trap __ro_after_init;
+
+/* Whether KASAN is enabled at all. */
+DEFINE_STATIC_KEY_FALSE_RO(kasan_enabled);
+EXPORT_SYMBOL(kasan_enabled);
+
+/* Whether to collect alloc/free stack traces. */
+DEFINE_STATIC_KEY_FALSE_RO(kasan_stack);
+
+/* Whether to use synchronous or asynchronous tag checking. */
+static bool kasan_sync __ro_after_init;
+
+/* Whether panic or disable tag checking on fault. */
+bool kasan_panic __ro_after_init;
+
+/* kasan.mode=off/prod/full */
+static int __init early_kasan_mode(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	if (!strcmp(arg, "off"))
+		kasan_arg_mode = KASAN_ARG_MODE_OFF;
+	else if (!strcmp(arg, "prod"))
+		kasan_arg_mode = KASAN_ARG_MODE_PROD;
+	else if (!strcmp(arg, "full"))
+		kasan_arg_mode = KASAN_ARG_MODE_FULL;
+	else
+		return -EINVAL;
+
+	return 0;
+}
+early_param("kasan.mode", early_kasan_mode);
+
+/* kasan.stack=off/on */
+static int __init early_kasan_stack(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	if (!strcmp(arg, "off"))
+		kasan_arg_stack = KASAN_ARG_STACK_OFF;
+	else if (!strcmp(arg, "on"))
+		kasan_arg_stack = KASAN_ARG_STACK_ON;
+	else
+		return -EINVAL;
+
+	return 0;
+}
+early_param("kasan.stack", early_kasan_stack);
+
+/* kasan.trap=sync/async */
+static int __init early_kasan_trap(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	if (!strcmp(arg, "ASYNC"))
+		kasan_arg_trap = KASAN_ARG_TRAP_ASYNC;
+	else if (!strcmp(arg, "sync"))
+		kasan_arg_trap = KASAN_ARG_TRAP_SYNC;
+	else
+		return -EINVAL;
+
+	return 0;
+}
+early_param("kasan.trap", early_kasan_trap);
+
+/* kasan.fault=report/panic */
+static int __init early_kasan_fault(char *arg)
+{
+	if (!arg)
+		return -EINVAL;
+
+	if (!strcmp(arg, "report"))
+		kasan_arg_fault = KASAN_ARG_FAULT_REPORT;
+	else if (!strcmp(arg, "panic"))
+		kasan_arg_fault = KASAN_ARG_FAULT_PANIC;
+	else
+		return -EINVAL;
+
+	return 0;
+}
+early_param("kasan.fault", early_kasan_fault);
+
 void __init kasan_init_tags(void)
 {
-	init_tags(KASAN_TAG_MAX);
+	if (!cpu_supports_tags())
+		return;
+
+	/* First, preset values based on the mode. */
+
+	switch (kasan_arg_mode) {
+	case KASAN_ARG_MODE_OFF:
+		return;
+	case KASAN_ARG_MODE_PROD:
+		static_branch_enable(&kasan_enabled);
+		break;
+	case KASAN_ARG_MODE_FULL:
+		static_branch_enable(&kasan_enabled);
+		static_branch_enable(&kasan_stack);
+		kasan_sync = true;
+		break;
+	}
+
+	/* Now, optionally override the presets. */
 
+	switch (kasan_arg_stack) {
+	case KASAN_ARG_STACK_OFF:
+		static_branch_disable(&kasan_stack);
+		break;
+	case KASAN_ARG_STACK_ON:
+		static_branch_enable(&kasan_stack);
+		break;
+	default:
+		break;
+	}
+
+	switch (kasan_arg_trap) {
+	case KASAN_ARG_TRAP_ASYNC:
+		kasan_sync = false;
+		break;
+	case KASAN_ARG_TRAP_SYNC:
+		kasan_sync = true;
+		break;
+	default:
+		break;
+	}
+
+	switch (kasan_arg_fault) {
+	case KASAN_ARG_FAULT_REPORT:
+		kasan_panic = false;
+		break;
+	case KASAN_ARG_FAULT_PANIC:
+		kasan_panic = true;
+		break;
+	default:
+		break;
+	}
+
+	/* TODO: choose between sync and async based on kasan_sync. */
+	init_tags(KASAN_TAG_MAX);
 	pr_info("KernelAddressSanitizer initialized\n");
 }
 
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index f7ae0c23f023..00b47bc753aa 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -2,9 +2,18 @@
 #ifndef __MM_KASAN_KASAN_H
 #define __MM_KASAN_KASAN_H
 
+#include <linux/jump_label.h>
 #include <linux/kasan.h>
 #include <linux/stackdepot.h>
 
+#ifdef CONFIG_KASAN_HW_TAGS
+DECLARE_STATIC_KEY_FALSE(kasan_stack);
+#else
+DECLARE_STATIC_KEY_TRUE(kasan_stack);
+#endif
+
+extern bool kasan_panic __ro_after_init;
+
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
 #else
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index dee5350b459c..426dd1962d3c 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -97,6 +97,10 @@ static void end_report(unsigned long *flags)
 		panic_on_warn = 0;
 		panic("panic_on_warn set ...\n");
 	}
+#ifdef CONFIG_KASAN_HW_TAGS
+	if (kasan_panic)
+		panic("kasan.fault=panic set ...\n");
+#endif
 	kasan_enable_current();
 }
 
@@ -159,8 +163,8 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
 		(void *)(object_addr + cache->object_size));
 }
 
-static void describe_object(struct kmem_cache *cache, void *object,
-				const void *addr, u8 tag)
+static void describe_object_stacks(struct kmem_cache *cache, void *object,
+					const void *addr, u8 tag)
 {
 	struct kasan_alloc_meta *alloc_meta = kasan_get_alloc_meta(cache, object);
 
@@ -188,7 +192,13 @@ static void describe_object(struct kmem_cache *cache, void *object,
 		}
 #endif
 	}
+}
 
+static void describe_object(struct kmem_cache *cache, void *object,
+				const void *addr, u8 tag)
+{
+	if (static_branch_unlikely(&kasan_stack))
+		describe_object_stacks(cache, object, addr, tag);
 	describe_object_addr(cache, object, addr);
 }
 
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 4db41f274702..b6d185adf2c5 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -33,6 +33,11 @@
 #include "kasan.h"
 #include "../slab.h"
 
+/* See the comments in hw_tags.c */
+DEFINE_STATIC_KEY_TRUE_RO(kasan_enabled);
+EXPORT_SYMBOL(kasan_enabled);
+DEFINE_STATIC_KEY_TRUE_RO(kasan_stack);
+
 static DEFINE_PER_CPU(u32, prng_state);
 
 void __init kasan_init_tags(void)
-- 
2.29.0.rc1.297.gfa9743e501-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6a4a7626bf280871518656f4fa89cb064740baf7.1603372719.git.andreyknvl%40google.com.
