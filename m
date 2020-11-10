Return-Path: <kasan-dev+bncBDX4HWEMTEBRBMVEVT6QKGQEVVUQYQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C4C72AE320
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:20:35 +0100 (CET)
Received: by mail-wm1-x33e.google.com with SMTP id h2sf1878804wmm.0
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:20:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046834; cv=pass;
        d=google.com; s=arc-20160816;
        b=LvUDPpl5pstuF2JLRcbDV6v06Y3p1gGvKTSlBaelKTsVvTC+/PAa4vhDDqhEMg3c1B
         b0YEy5udpeE/zulsyWdqRDvYdgIF0FCsxCwdxPuSt9OHpsk3pTEJhvyDIHq1aaNTMZlF
         Aud98PevA4L5Ph8/ydrLLDyfIShpD1l4PT7yae5ogdkPUviDgUezdwG1AWAUgfDckjBQ
         +2vUSI4PFkTXz5rMpOnPzHC5Z4o9YBYvHT8nB2Wc3lOovkwdZ5dBfbOBNHep/YaVBcQl
         5RouSKX1QDP/21U5qR+9CUWr8O7FBzciuSuCaFgTMjtn9Rnive/j4C6hTJXwwVq+mcEC
         jCZw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=sfVNREG4SyGcG9DkBHMAI568eYoxU1LASFVNSQA7RVM=;
        b=txJDnIzVbnvQ/UsabszalRFpRrAyK9m8byiUfvjeXAdYjiBxtBdHVNq/di/lhU4Bl1
         fjez+ikG7MoW+sfP3RkbmGLslnwqN2cDDpTFZYOpFr9b3gGNCCnH2asbyd6YaXWRSGhV
         fqHiGwk0VCpfjkoHVnIhSAauORHbSjJFNxcqvngFQ0toIUUva9e8ZxdaWa7Ci5saMuKA
         LhVwUEwpeAA0A+/13LHA/84iFlAJCnFjQYWsXdUERjd7/MBpQFKAObad4Tp4oYHcCrlH
         myzYy26lsd6ku/PmssUTZc5A7xaUmgWsJexxP7UZa08813U9uMHCohya0qf3yA4Ij2hb
         XNLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CJ8BfCyP;
       spf=pass (google.com: domain of 3mrkrxwokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3MRKrXwoKCQYgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=sfVNREG4SyGcG9DkBHMAI568eYoxU1LASFVNSQA7RVM=;
        b=RsKxSSI4L1Iiwv3mSruarETkGZkl9+U7AVwl0vdqX3Khi/e2yImPIesexAcg+kr0fv
         NItsok76kO4H0+hEs03VbDU6fI7YvG+yzeJBo6mTEIkLstyqz4zoDZ3LWfc+KP/AAzQQ
         uQGQ8Ft9XvXXMEWa1GJTfE/WdpYHkiIJ4m3hjS+0lsUrxVRXzeBb1/QWViH1WDUqJ1+J
         VKe5TzrdTSq4rVH7bWVfSH8SSbyIBxCpbivqWoBXi9q5D6M5GT7dFjmRA3EPrpCm/Ag7
         dETssU8fz/l64C8CsfQPx9p4DFHSLd9MHhiPpUlYuLhAwAa+d8WXw7oXlLF3vyrxVN5f
         wwyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=sfVNREG4SyGcG9DkBHMAI568eYoxU1LASFVNSQA7RVM=;
        b=aHzo6ERbbeyHaCmmRY6fXTYqZ8T45t7K2el3MUK505oAg5sIqRL8vaOSkciiZyhZDe
         fhc1o4B6ROk8yhoRVEKozQvqNGJl5xvoZxKoQSDBzQneVUCmGEJNyHYBTXG3gd0Ek4xu
         bO2cG+LUCp06rC0GrrHbaaZLgKbld5R8HxFqx98hGg3s6n4czmt1az2IosdZ/Pf1bfkj
         NCQXDCfG16nemW3wdCQdcno1OSDnRZ2GtggEqWbwaEFZK8M9kOIbQxdBJxzIIp1n/0jv
         ZohLi4bAzToE7wE2ECDob9/IA/hbDQRbgCZvj4oJ5Jtk8a0y38U63yItgwnVkxX5vMMu
         vMXg==
X-Gm-Message-State: AOAM531vmkOLlpBglXtS6ZcC2ivC3MjuI5+qw+N8MbmPMg5VoWJ/avNJ
	+pIlqcGa/wioj5UcPYR/V+E=
X-Google-Smtp-Source: ABdhPJwxKDAPjx+/ie3IYT/AcRyR6pa4m9mBL8aHcs3ueywpFFItUgAhF8Mwk/yAE9tHlltUMNLupw==
X-Received: by 2002:a1c:4b0c:: with SMTP id y12mr284398wma.91.1605046834798;
        Tue, 10 Nov 2020 14:20:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:c689:: with SMTP id j9ls475277wrg.0.gmail; Tue, 10 Nov
 2020 14:20:34 -0800 (PST)
X-Received: by 2002:adf:e80b:: with SMTP id o11mr6918607wrm.409.1605046834050;
        Tue, 10 Nov 2020 14:20:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046834; cv=none;
        d=google.com; s=arc-20160816;
        b=WBLs7wDdBHKdyO6T1HajvzghqtSq+e2TX50BXPPNWGmeLaiI1RqbQc/x2SvzYbTdlS
         7oI+iocHtpTv4zhGRUeAbsSUi4pYXLqmNrqB0xrKZ7l1+mnMnLgZWsFH39l+gtsTBavH
         Yz1qV+qiYr/rrf09MgOyK+f5VrGxATuIKySJTPovJA5IJPBA0cchsqJmeZLdzW2s+5UE
         5ajqsVnb3qTtrKqTfbPK9wVdLoZM/W+58cn4cr6Hi5M6zPTG+KcIX7IAKFiy6Hp9SLi+
         fD+U2edO/0wlb/+Dacn006sd8GtgdHVSX+0fMP5sATh9UFtgO9ZOry8ITrAn61Z8hLWq
         8N9g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=JDIZOBUdSYTr2qi1CrbHHoKD73faXUnEima7jMLorCA=;
        b=vgpIPuj2G5Razv3gR0DH7l9U1xSK/dVxp1OMu9Sz77dTFVYSY0nQ15ln3jI9cYY+Xz
         3F3HWXQ4qhK9vtcVWsiEHTW7c9qms1JdpJ1Hpuh3yJURaAeKdcv/XwXUHTXRhbWTTaDy
         aWMf0ZSr/Ec24jeAIqkFe7aGGVtsYXVFmszqR/HPCvdTyj0seksziu/CXWNLWpRtR6H4
         vqUTwP4W7iLzcxvfbTOwKu0yHBlIUuiBSa//+uPxjDRO6zWuxL2a+dDF4aZ5ZDl9Q0qm
         Vnm9kCWuApYZU7zErzsKidPkw8c5QwBUeUDGuroA6H7Yb31vEA/8NbskLogrmmSr1O9C
         Tk1w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=CJ8BfCyP;
       spf=pass (google.com: domain of 3mrkrxwokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3MRKrXwoKCQYgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id r21si2901wra.4.2020.11.10.14.20.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:20:34 -0800 (PST)
Received-SPF: pass (google.com: domain of 3mrkrxwokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id x16so6166671wrg.7
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:20:34 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:bac1:: with SMTP id
 k184mr290033wmf.76.1605046833741; Tue, 10 Nov 2020 14:20:33 -0800 (PST)
Date: Tue, 10 Nov 2020 23:20:06 +0100
In-Reply-To: <cover.1605046662.git.andreyknvl@google.com>
Message-Id: <f60a0852051bbe9a20d5f9eba7567c0e9474a1c4.1605046662.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v2 02/20] kasan: rename get_alloc/free_info
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Evgenii Stepanov <eugenis@google.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, Andrew Morton <akpm@linux-foundation.org>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=CJ8BfCyP;       spf=pass
 (google.com: domain of 3mrkrxwokcqygtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3MRKrXwoKCQYgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
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
index 5712c66c11c1..8fd04415d8f4 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -175,14 +175,14 @@ size_t kasan_metadata_size(struct kmem_cache *cache)
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
@@ -259,13 +259,13 @@ static u8 assign_tag(struct kmem_cache *cache, const void *object,
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
@@ -345,7 +345,7 @@ static void *__kasan_kmalloc(struct kmem_cache *cache, const void *object,
 		KASAN_KMALLOC_REDZONE);
 
 	if (cache->flags & SLAB_KASAN)
-		kasan_set_track(&get_alloc_info(cache, object)->alloc_track, flags);
+		kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
 
 	return set_tag(object, tag);
 }
diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index adb254df1b1d..d259e4c3aefd 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -329,7 +329,7 @@ void kasan_record_aux_stack(void *addr)
 {
 	struct page *page = kasan_addr_to_page(addr);
 	struct kmem_cache *cache;
-	struct kasan_alloc_meta *alloc_info;
+	struct kasan_alloc_meta *alloc_meta;
 	void *object;
 
 	if (!(page && PageSlab(page)))
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
index 0080b78ec843..70b88dd40cd8 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -66,7 +66,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
 {
 	struct kasan_alloc_meta *alloc_meta;
 
-	alloc_meta = get_alloc_info(cache, object);
+	alloc_meta = kasan_get_alloc_meta(cache, object);
 	kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
 }
 
@@ -75,6 +75,6 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 {
 	struct kasan_alloc_meta *alloc_meta;
 
-	alloc_meta = get_alloc_info(cache, object);
+	alloc_meta = kasan_get_alloc_meta(cache, object);
 	return &alloc_meta->free_track[0];
 }
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index c2c40ec1544d..db8a7a508121 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -148,10 +148,10 @@ struct kasan_free_meta {
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
 
 void kasan_poison_memory(const void *address, size_t size, u8 value);
 
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
index ce06005d4052..0cac53a57c14 100644
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
index dfe707dd8d0d..3bffb489b144 100644
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
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f60a0852051bbe9a20d5f9eba7567c0e9474a1c4.1605046662.git.andreyknvl%40google.com.
