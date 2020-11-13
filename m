Return-Path: <kasan-dev+bncBDX4HWEMTEBRBJMNXT6QKGQENJF2XWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id ECAC22B2839
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 23:20:21 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id c17sf4413135lfh.20
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Nov 2020 14:20:21 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605306021; cv=pass;
        d=google.com; s=arc-20160816;
        b=z2dmAuAz4/8XACTxLpFjtdRUC5OEbTn9ZcqZwvLhkyQUcalhVXlp00yJM7AZac0RNq
         vwaX7Ezc9V08+FAmzmf9PgpplVcJUOOgfA85J7OY3BD3Aha01xGduXbLPdtx6H7zup9d
         l2UCPrBu397XhGiiI2jL1dur3QeDD7fCaYnRbZsU6Zxnl0WSDqRRQoUgTS1EN4A3aLQ/
         7APZKZoJ2R6ugaTyJ4EfQSEsuFgUJDi9rNnesjib/oP460jzfqK7LbV3zHSqncBJIHYB
         ly2gudGlD+KMyeoivB3LcH7bkAXs/758k2KYCRqt0A5qic+w1yS1SzwVTsYnTmIg62fD
         jGlg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=QrWS+Cs++2dAjdXhUiXALu1XP7z7HG04gPZ1Qyg/Y0c=;
        b=KkoRJVc3IiOgbjjEwGkAPQod5TmcopsCL8+EuL4lV4nX5K1oCMa9fkl0E+c9jahr8K
         CCWmv6+SzySekpX30Eg9J53FLTOB6kjivDR7qMh79ghL0LlDQQijsl5fB4Sk9HTueXkn
         Vo7CUfaM1zYqGe3Jv6pJJAYat/8rOEmVpQ9O4366FO+/Zi0+McdbTqysDNqhNUdtCA6z
         cGzhjXOf+i74soxjaddlq6OZ+cVV+aDKYbnxmwItALMi88XmlA1lJCxIOMtSoC2Ton0v
         ACsB8Y+89tuuKhaybUMdP/wInr7+Drsksb9/nPDDqN/ENAsy2hTZJnRKMVNtVg+WS6j2
         QFog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SAqovLo3;
       spf=pass (google.com: domain of 3owavxwokcxaobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3owavXwoKCXAObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QrWS+Cs++2dAjdXhUiXALu1XP7z7HG04gPZ1Qyg/Y0c=;
        b=rfoc7vDjFJibxpwflxao2KRlFAEQyv3PAjOPZoPWeBe/BcPdIsAIVnhP5IVuic+fih
         oQuU5mE1czEH+mOnyQ0flelx0nVRyq/D1WvohTzU5zjvRItHse4zGKjVADMYbHhPdzf2
         rnnOVSCc2MgD6HSUw58B5gDTpsbQpRxikKuyeSiB1uixq93NzBhuGCnddm1ETmY+uTHM
         JIw3kTkYjPo2wJoW0da0t07YkVfg0XCVgsW2X/4D7c2VCQxxSJ9UhInCN+UrD4Vfim3d
         V5lIgSCIKXUQNWRBsRNfJ+80OPgNXQheRjX6giaO1AygZi92fHlVAKilB12NTlmH0pA6
         QGgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QrWS+Cs++2dAjdXhUiXALu1XP7z7HG04gPZ1Qyg/Y0c=;
        b=ikSRhoChjHPLF5seX6R0sOaBg0SgR1o1xSCqjDzb8+zslzJP7xCX8RHRqwIndIKxRX
         kYmNnFkL9V9PEIOAfpBqjlZyh0AMP8GQ/IgkyliDwDROzkVy3drOM/8MytagZ0jQvUao
         6Uv9D0b3APkboekA6f0Hb0DEdjJNycSO3x5RSGHwc3O+qxz+iklKNEzYQIEF5iHjgEZS
         bB5j6B4y70ekAkXamp59bVkW2vpotEw0yMOtUUXm0ap5zruIgBkhT49PlI0QavRhD2L+
         JTUWUJassyvDvFSL8mizdiL7dCJgigdODU7gFGIXA3E/p0mRPLgVGc7EOLgkEBY/h2uM
         nGxA==
X-Gm-Message-State: AOAM530rBkrkxQTL85Df9zLtE6+mtkLia52+Hmhknmwg7csJizENmtiV
	haFqGER8mt/gAhZh8p44H+8=
X-Google-Smtp-Source: ABdhPJzoW2VgecTtrUFhu2qfrdy2PBbP3w5DYBJfGlOTJPUHlNdEC8RplbkfC6BONloTGdEgAkHl0A==
X-Received: by 2002:ac2:5446:: with SMTP id d6mr1866547lfn.271.1605306021510;
        Fri, 13 Nov 2020 14:20:21 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:d0e:: with SMTP id 14ls5526295lfn.0.gmail; Fri, 13 Nov
 2020 14:20:20 -0800 (PST)
X-Received: by 2002:ac2:418e:: with SMTP id z14mr1597524lfh.25.1605306020643;
        Fri, 13 Nov 2020 14:20:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605306020; cv=none;
        d=google.com; s=arc-20160816;
        b=B+ox2nsP1NtEsGFORh0HNEmU7M18NXcamzcszFDi3qI7XhSB2wsLpvzxdkANHYjG3J
         6ZVuExbVnY9JbPHVSWGGykfCmVjsUuToBK7Cka7U9hvM3JC0feSPiJC1oHENw0KDxqgl
         PyLDHyM+ZlHNx9miKNieWIjJDbO0yYqIY1UM2LD4BT0ZGxKUKUIARFcsUusbYeYIA24C
         SN/fbKZLaMsSkMsBKcaLGH6wsZnY6JPi5BKvIwee3qmWrwu573gnaGm1oVm+StrL9WFH
         e3oE4dvWmxU331pieTjyYDK8V5HwNIda3Q7cMWzRxaPk6oID93otFnYR5Oo83W7Fl185
         8L7w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=P/VONEfbusEo0xeHDJ2NdS5sIzPWe1VMLcnIssonnS8=;
        b=wqC75J/53a8E36+vX3352U3weav8ZPM0MNFrBBqrbK70JCKw0JwltIZdMbNUbpn0L3
         +7Leb6BuBjdOZWqqWd2g9K1e8Z4bPRGlgv8gbGahxFtwb01sArXjaj9ECva/izzVRyn5
         ZwXaqbF+ujJvYNL+lGjgmke0nGuadGyjeP9PaqJOWhHaVloQWFbU0sfxjBbQty3D0yK4
         pDljsocMkduGX/+Nxq6aBDR/B9HxsN8z0UxMPHNcsPOwbePgLCA3KUsMBOhoR9gHsH8e
         FZhyG3iuKQ9rq95w4WT58PhWuojYyaAs2USTh3amwbcNbiioFetThgkLDN6+gR7ho/IJ
         d0kQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SAqovLo3;
       spf=pass (google.com: domain of 3owavxwokcxaobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3owavXwoKCXAObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id m18si351107lfr.11.2020.11.13.14.20.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Nov 2020 14:20:20 -0800 (PST)
Received-SPF: pass (google.com: domain of 3owavxwokcxaobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id w6so4674334wrk.1
        for <kasan-dev@googlegroups.com>; Fri, 13 Nov 2020 14:20:20 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:adf:8382:: with SMTP id
 2mr6018992wre.227.1605306019928; Fri, 13 Nov 2020 14:20:19 -0800 (PST)
Date: Fri, 13 Nov 2020 23:19:52 +0100
In-Reply-To: <cover.1605305978.git.andreyknvl@google.com>
Message-Id: <54a24c9db9d2c5dd7e0c268f19a693077adf6fd9.1605305978.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605305978.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.299.gdc1121823c-goog
Subject: [PATCH mm v3 02/19] kasan: rename get_alloc/free_info
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SAqovLo3;       spf=pass
 (google.com: domain of 3owavxwokcxaobrfsmybjzuccuzs.qcayogob-rsjuccuzsufcidg.qca@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3owavXwoKCXAObRfSmYbjZUccUZS.QcaYOgOb-RSjUccUZSUfcidg.Qca@flex--andreyknvl.bounces.google.com;
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

Rename get_alloc_info() and get_free_info() to kasan_get_alloc_meta()
and kasan_get_free_meta() to better reflect what those do and avoid
confusion with kasan_set_free_info().

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Marco Elver <elver@google.com>
Link: https://linux-review.googlesource.com/id/Ib6e4ba61c8b12112b403d3479a9799ac8fff8de1
---
 mm/kasan/common.c         | 16 ++++++++--------
 mm/kasan/generic.c        | 12 ++++++------
 mm/kasan/hw_tags.c        |  4 ++--
 mm/kasan/kasan.h          |  8 ++++----
 mm/kasan/quarantine.c     |  4 ++--
 mm/kasan/report.c         | 12 ++++++------
 mm/kasan/report_sw_tags.c |  2 +-
 mm/kasan/sw_tags.c        |  4 ++--
 8 files changed, 31 insertions(+), 31 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index e11fac2ee30c..8197399b0a1f 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -181,14 +181,14 @@ size_t kasan_metadata_size(struct kmem_cache *cache)
 		sizeof(struct kasan_free_meta) : 0);
 }
 
-struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
-					const void *object)
+struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
+					      const void *object)
 {
 	return (void *)reset_tag(object) + cache->kasan_info.alloc_meta_offset;
 }
 
-struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
-				      const void *object)
+struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
+					    const void *object)
 {
 	BUILD_BUG_ON(sizeof(struct kasan_free_meta) > 32);
 	return (void *)reset_tag(object) + cache->kasan_info.free_meta_offset;
@@ -265,13 +265,13 @@ static u8 assign_tag(struct kmem_cache *cache, const void *object,
 void * __must_check kasan_init_slab_obj(struct kmem_cache *cache,
 						const void *object)
 {
-	struct kasan_alloc_meta *alloc_info;
+	struct kasan_alloc_meta *alloc_meta;
 
 	if (!(cache->flags & SLAB_KASAN))
 		return (void *)object;
 
-	alloc_info = get_alloc_info(cache, object);
-	__memset(alloc_info, 0, sizeof(*alloc_info));
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	__memset(alloc_meta, 0, sizeof(*alloc_meta));
 
 	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) || IS_ENABLED(CONFIG_KASAN_HW_TAGS))
 		object = set_tag(object, assign_tag(cache, object, true, false));
@@ -357,7 +357,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 		     KASAN_KMALLOC_REDZONE);
 
 	if (cache->flags & SLAB_KASAN)
-		kasan_set_track(&get_alloc_info(cache, object)->alloc_track, flags);
+		kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
 
 	return set_tag(object, tag);
 }
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index da3608187c25..9c6b77f8c4a4 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -329,7 +329,7 @@ void kasan_record_aux_stack(void *addr)
 {
 	struct page *page = kasan_addr_to_page(addr);
 	struct kmem_cache *cache;
-	struct kasan_alloc_meta *alloc_info;
+	struct kasan_alloc_meta *alloc_meta;
 	void *object;
 
 	if (is_kfence_address(addr) || !(page && PageSlab(page)))
@@ -337,13 +337,13 @@ void kasan_record_aux_stack(void *addr)
 
 	cache = page->slab_cache;
 	object = nearest_obj(cache, page, addr);
-	alloc_info = get_alloc_info(cache, object);
+	alloc_meta = kasan_get_alloc_meta(cache, object);
 
 	/*
 	 * record the last two call_rcu() call stacks.
 	 */
-	alloc_info->aux_stack[1] = alloc_info->aux_stack[0];
-	alloc_info->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
+	alloc_meta->aux_stack[1] = alloc_meta->aux_stack[0];
+	alloc_meta->aux_stack[0] = kasan_save_stack(GFP_NOWAIT);
 }
 
 void kasan_set_free_info(struct kmem_cache *cache,
@@ -351,7 +351,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
 {
 	struct kasan_free_meta *free_meta;
 
-	free_meta = get_free_info(cache, object);
+	free_meta = kasan_get_free_meta(cache, object);
 	kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
 
 	/*
@@ -365,5 +365,5 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 {
 	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_KMALLOC_FREETRACK)
 		return NULL;
-	return &get_free_info(cache, object)->free_track;
+	return &kasan_get_free_meta(cache, object)->free_track;
 }
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 3f9232464ed4..68e77363e58b 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -75,7 +75,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
 {
 	struct kasan_alloc_meta *alloc_meta;
 
-	alloc_meta = get_alloc_info(cache, object);
+	alloc_meta = kasan_get_alloc_meta(cache, object);
 	kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
 }
 
@@ -84,6 +84,6 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 {
 	struct kasan_alloc_meta *alloc_meta;
 
-	alloc_meta = get_alloc_info(cache, object);
+	alloc_meta = kasan_get_alloc_meta(cache, object);
 	return &alloc_meta->free_track[0];
 }
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 13c511e85d5f..0eab7e4cecb8 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -149,10 +149,10 @@ struct kasan_free_meta {
 #endif
 };
 
-struct kasan_alloc_meta *get_alloc_info(struct kmem_cache *cache,
-					const void *object);
-struct kasan_free_meta *get_free_info(struct kmem_cache *cache,
-					const void *object);
+struct kasan_alloc_meta *kasan_get_alloc_meta(struct kmem_cache *cache,
+						const void *object);
+struct kasan_free_meta *kasan_get_free_meta(struct kmem_cache *cache,
+						const void *object);
 
 void poison_range(const void *address, size_t size, u8 value);
 void unpoison_range(const void *address, size_t size);
diff --git a/mm/kasan/quarantine.c b/mm/kasan/quarantine.c
index a0792f0d6d0f..0da3d37e1589 100644
--- a/mm/kasan/quarantine.c
+++ b/mm/kasan/quarantine.c
@@ -166,7 +166,7 @@ void quarantine_put(struct kmem_cache *cache, void *object)
 	unsigned long flags;
 	struct qlist_head *q;
 	struct qlist_head temp = QLIST_INIT;
-	struct kasan_free_meta *info = get_free_info(cache, object);
+	struct kasan_free_meta *meta = kasan_get_free_meta(cache, object);
 
 	/*
 	 * Note: irq must be disabled until after we move the batch to the
@@ -179,7 +179,7 @@ void quarantine_put(struct kmem_cache *cache, void *object)
 	local_irq_save(flags);
 
 	q = this_cpu_ptr(&cpu_quarantine);
-	qlist_put(q, &info->quarantine_link, cache->size);
+	qlist_put(q, &meta->quarantine_link, cache->size);
 	if (unlikely(q->bytes > QUARANTINE_PERCPU_SIZE)) {
 		qlist_move_all(q, &temp);
 
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index a69c2827a125..df16bef0d810 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -164,12 +164,12 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
 static void describe_object(struct kmem_cache *cache, void *object,
 				const void *addr, u8 tag)
 {
-	struct kasan_alloc_meta *alloc_info = get_alloc_info(cache, object);
+	struct kasan_alloc_meta *alloc_meta = kasan_get_alloc_meta(cache, object);
 
 	if (cache->flags & SLAB_KASAN) {
 		struct kasan_track *free_track;
 
-		print_track(&alloc_info->alloc_track, "Allocated");
+		print_track(&alloc_meta->alloc_track, "Allocated");
 		pr_err("\n");
 		free_track = kasan_get_free_track(cache, object, tag);
 		if (free_track) {
@@ -178,14 +178,14 @@ static void describe_object(struct kmem_cache *cache, void *object,
 		}
 
 #ifdef CONFIG_KASAN_GENERIC
-		if (alloc_info->aux_stack[0]) {
+		if (alloc_meta->aux_stack[0]) {
 			pr_err("Last call_rcu():\n");
-			print_stack(alloc_info->aux_stack[0]);
+			print_stack(alloc_meta->aux_stack[0]);
 			pr_err("\n");
 		}
-		if (alloc_info->aux_stack[1]) {
+		if (alloc_meta->aux_stack[1]) {
 			pr_err("Second to last call_rcu():\n");
-			print_stack(alloc_info->aux_stack[1]);
+			print_stack(alloc_meta->aux_stack[1]);
 			pr_err("\n");
 		}
 #endif
diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
index aebc44a29e83..317100fd95b9 100644
--- a/mm/kasan/report_sw_tags.c
+++ b/mm/kasan/report_sw_tags.c
@@ -46,7 +46,7 @@ const char *get_bug_type(struct kasan_access_info *info)
 	if (page && PageSlab(page)) {
 		cache = page->slab_cache;
 		object = nearest_obj(cache, page, (void *)addr);
-		alloc_meta = get_alloc_info(cache, object);
+		alloc_meta = kasan_get_alloc_meta(cache, object);
 
 		for (i = 0; i < KASAN_NR_FREE_STACKS; i++)
 			if (alloc_meta->free_pointer_tag[i] == tag)
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index a518483f3965..6d7648cc3b98 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -174,7 +174,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
 	struct kasan_alloc_meta *alloc_meta;
 	u8 idx = 0;
 
-	alloc_meta = get_alloc_info(cache, object);
+	alloc_meta = kasan_get_alloc_meta(cache, object);
 
 #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
 	idx = alloc_meta->free_track_idx;
@@ -191,7 +191,7 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 	struct kasan_alloc_meta *alloc_meta;
 	int i = 0;
 
-	alloc_meta = get_alloc_info(cache, object);
+	alloc_meta = kasan_get_alloc_meta(cache, object);
 
 #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
 	for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
-- 
2.29.2.299.gdc1121823c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/54a24c9db9d2c5dd7e0c268f19a693077adf6fd9.1605305978.git.andreyknvl%40google.com.
