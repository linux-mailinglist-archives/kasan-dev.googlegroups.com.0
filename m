Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQWGTX6AKGQETW4B5OA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 5F55228E7F9
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 22:44:51 +0200 (CEST)
Received: by mail-lf1-x13e.google.com with SMTP id e29sf68938lfb.5
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Oct 2020 13:44:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1602708291; cv=pass;
        d=google.com; s=arc-20160816;
        b=va0bV7JuTTUd+zFBnwWb/u96xqGlZ6NAxsh/RmaXyC5qqSpXPcuH6NQTS/Z4jJYFmW
         JQhXMUzxmXYZT7USuyM7a5QKu1Hsl9Tzpt7/Z/0v8P2Q1OMgBeWMZd1yvtAQFrm2PVv9
         ZQ8LsKgoVCKt23eON420PprC8JIENHLykFsTwvyQM2ZqW38yL5rRZx2qtMwVoAmyJ7rk
         UnVq4Dku2gVXAUk/2N4qByqbSU4t9J5yXBATUIYsMpsT7hkUlqvlA4A0OAkMaM+JnL2G
         Psz5ZmBqoc8Hs21AwoPg8JTAsQ9oIhcJQUi/b/bEDPt3cdmhgkZwBsUWG9LfWRGc5ehk
         bvxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=7Q+1k+BPi7SClVGATIluzaH7MzmMxO/QR8Hk7whyzg4=;
        b=hk0vvDioBFNi1Kdw4Nm47Aq0mCrt7d4zjbenx9WUOuhHKYvgbk0mN/je1p+VlFE+S4
         zI8e3tn+1Hwy4VVHDc80l1aGin6mIGWIpkVXWHcEpnLklrC1EDlqGqG8kFarcYItmytj
         7t6I1LM0p2ruvPlpkBffusNOAXHj0iS3zUJDrXP7OLKbgTaqm570k6da5O+z0S3Ie79w
         queIW6XuiaKtRMJ1IpsKBRJicqnFJ4VuMp8+fA70hvmMnWuzWXdeIVn0yB6m/e5Q6HuM
         jxDr3V8+bkx6RHulGSYq2f64HfcBscWzhIKViDFHIJdHHGnRWZHryM76a0DkOWdUr8DS
         08eA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=O1sn77fI;
       spf=pass (google.com: domain of 3qwohxwokcsgerhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3QWOHXwoKCSgERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7Q+1k+BPi7SClVGATIluzaH7MzmMxO/QR8Hk7whyzg4=;
        b=tm05SIILWZxm1E3g0GId7rqEtjnQiRzFM8eAjSeRsyTW2B7C4AOCfWENZMIyNt5FLZ
         mFA/lg9bsuLo3g0wvU7s0rdaZ5S5VtbKyF5pZs2hczDpJRaOPJy9EkqvuwABSV2fBGiS
         Tec1/uWF7V9VrIKDUcLtHIQhK4L5P3wJtyUNpL1HX663+Sa3AZrO4qouk51IMOaY1LZF
         4hzEQ8p7JamqJZvFI9M8YOnsL8f9RL/ypiYVws5w4crf8Us452VRZcoB5PUyPGu/yxy+
         GD04SbomcWpfdzfjhDEfQN4mvFtqniDyLJp0MkNL74ze8sl56axe9HPlocQ9KMBSv+mz
         YJCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7Q+1k+BPi7SClVGATIluzaH7MzmMxO/QR8Hk7whyzg4=;
        b=UVXn3IafCdVMz4yY8qkghlBgdAlGKlH79e6LpUnGCOQdyPvIJZagwpK+XQXfh2SGJP
         eUinEv1mBvuU1D7+zipW1jOgZfOcXS+CHPeKtDTDs/3LLwST1ooHCTHPvcrO5SwB1cqY
         YGLEhPM6eMBnwE9A9AxTO/9Lg9lCrouxOXdXzi5f+3jaY/GjI9ZErCl2YlmkhqCty1Hy
         yTJd5+/ECtFghnjgp7pG4iKVFrFzzcyHgzwDcKrtWoif35ahicvrBn+DtvpQ8zAxy7rr
         4hVhqajuOSZAx/Zottj2p3TGgSn0tQ/WBfe2DeQfKAzsV/m1XVRG5OgagkTzsip3lk5c
         jp0w==
X-Gm-Message-State: AOAM5301IPKdyFZT69CJ1sXlBMUQtG+gOha0Dz3rTatY38HOSOHrTmd+
	hb7in0hugXEcTRy5m9qKTS0=
X-Google-Smtp-Source: ABdhPJwdI+CVX7EKR3i/YJUXbV9ywtKLSv8wr+cZyAzahKC3gam7sl8P9HR102u+4BWHxSQkEM9uaA==
X-Received: by 2002:a05:651c:1af:: with SMTP id c15mr185072ljn.446.1602708290836;
        Wed, 14 Oct 2020 13:44:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:8848:: with SMTP id z8ls150888ljj.5.gmail; Wed, 14 Oct
 2020 13:44:49 -0700 (PDT)
X-Received: by 2002:a2e:6c0e:: with SMTP id h14mr149755ljc.117.1602708289736;
        Wed, 14 Oct 2020 13:44:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1602708289; cv=none;
        d=google.com; s=arc-20160816;
        b=dN+iRVFhBe+cB+bT3vBOtYSF2z6b38UR0y1oq7EpLTA50DNO1k48+XnQFIviZtMozd
         82ioYXEZUbtetnZl74YwqPIfHJQnBoEDTSjrGK/+jNsj6u9YcUjIJguz+1NFcKKX3NRk
         qZMBTe0Fu2+LbKk8KOCa0uW5Z6LU0dqCDHz/Xle5MO4gYb694jDs2lUoze1HgY92B8Oe
         RtuYM/Z2i2VqI0vpDYXeyXsAS/+MtgfCjZ6GjCcVlm5Wbjc4EntICFGOU2nJScoyQT2x
         huAeNNL8TWKLMehM/F9HsHhBxJej0TGXgwp2tYke7GnnOJ6+hz2iyu4bwfeXstzlAxV4
         kXUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Av8tJux3BwbmeDJFmJufyBaR7iq/cL2LgtaOzffVcEM=;
        b=wCrbuLioUxOXhwSHdPFeno/TKFFQ/wt1ItR1ygj+gupeWCPW2rcqkaOQ6VQUr5DD41
         ZZhlLlt9bReq6ebKiBTl20pB3GbC+CtMrAYud8wXTSPpYVAfkmRMYd2PL+bydsQ0L+A0
         iBc20P/zbMXZLSd3FEZzunt4/uXGswlp6bgidmTy8Y8wMdCLFJxX4NyyC9zc1yTWSZu3
         QYdAYdr9Hje6ZWghDZIF788tQwk/uJIW3LGM6oiPiLQE022J/cFHahmkXKhGMlQhwryQ
         DiQ4KD4S4/iCLPCWWZrFkJkOpdu1cJyNU1G5VGqkvaHBme4/HuDDuo6j1kNpI5TvsATW
         0NRg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=O1sn77fI;
       spf=pass (google.com: domain of 3qwohxwokcsgerhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3QWOHXwoKCSgERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id l28si17124lfp.11.2020.10.14.13.44.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Oct 2020 13:44:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3qwohxwokcsgerhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id f2so397571wml.6
        for <kasan-dev@googlegroups.com>; Wed, 14 Oct 2020 13:44:49 -0700 (PDT)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a05:600c:294b:: with SMTP id
 n11mr608559wmd.85.1602708289010; Wed, 14 Oct 2020 13:44:49 -0700 (PDT)
Date: Wed, 14 Oct 2020 22:44:30 +0200
In-Reply-To: <cover.1602708025.git.andreyknvl@google.com>
Message-Id: <bb983571383d88b7a1feee5b5c5e497833c465e0.1602708025.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1602708025.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.28.0.1011.ga647a8990f-goog
Subject: [PATCH RFC 2/8] kasan: rename get_alloc/free_info
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>, 
	Evgenii Stepanov <eugenis@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Elena Petrova <lenaptr@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=O1sn77fI;       spf=pass
 (google.com: domain of 3qwohxwokcsgerhvicorzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3QWOHXwoKCSgERHVIcORZPKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--andreyknvl.bounces.google.com;
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
and kasan_get_free_meta() to better reflect what those do, and avoid
confusion with kasan_set_free_info().

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
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
index e1af3b6c53b8..de6b3f03a023 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -331,7 +331,7 @@ void kasan_record_aux_stack(void *addr)
 {
 	struct page *page = kasan_addr_to_page(addr);
 	struct kmem_cache *cache;
-	struct kasan_alloc_meta *alloc_info;
+	struct kasan_alloc_meta *alloc_meta;
 	void *object;
 
 	if (!(page && PageSlab(page)))
@@ -339,13 +339,13 @@ void kasan_record_aux_stack(void *addr)
 
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
@@ -353,7 +353,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
 {
 	struct kasan_free_meta *free_meta;
 
-	free_meta = get_free_info(cache, object);
+	free_meta = kasan_get_free_meta(cache, object);
 	kasan_set_track(&free_meta->free_track, GFP_NOWAIT);
 
 	/*
@@ -367,5 +367,5 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 {
 	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_KMALLOC_FREETRACK)
 		return NULL;
-	return &get_free_info(cache, object)->free_track;
+	return &kasan_get_free_meta(cache, object)->free_track;
 }
diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 7f0568df2a93..2a38885014e3 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -56,7 +56,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
 {
 	struct kasan_alloc_meta *alloc_meta;
 
-	alloc_meta = get_alloc_info(cache, object);
+	alloc_meta = kasan_get_alloc_meta(cache, object);
 	kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
 }
 
@@ -65,6 +65,6 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 {
 	struct kasan_alloc_meta *alloc_meta;
 
-	alloc_meta = get_alloc_info(cache, object);
+	alloc_meta = kasan_get_alloc_meta(cache, object);
 	return &alloc_meta->free_track[0];
 }
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index a3bf60ceb5e1..e5b8367a07f2 100644
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
index f8817d5685a7..dee5350b459c 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -162,12 +162,12 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
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
@@ -176,14 +176,14 @@ static void describe_object(struct kmem_cache *cache, void *object,
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
index ccc35a311179..c10863a45775 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -172,7 +172,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
 	struct kasan_alloc_meta *alloc_meta;
 	u8 idx = 0;
 
-	alloc_meta = get_alloc_info(cache, object);
+	alloc_meta = kasan_get_alloc_meta(cache, object);
 
 #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
 	idx = alloc_meta->free_track_idx;
@@ -189,7 +189,7 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 	struct kasan_alloc_meta *alloc_meta;
 	int i = 0;
 
-	alloc_meta = get_alloc_info(cache, object);
+	alloc_meta = kasan_get_alloc_meta(cache, object);
 
 #ifdef CONFIG_KASAN_SW_TAGS_IDENTIFY
 	for (i = 0; i < KASAN_NR_FREE_STACKS; i++) {
-- 
2.28.0.1011.ga647a8990f-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bb983571383d88b7a1feee5b5c5e497833c465e0.1602708025.git.andreyknvl%40google.com.
