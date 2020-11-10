Return-Path: <kasan-dev+bncBDX4HWEMTEBRBT5EVT6QKGQE5K6P62Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x637.google.com (mail-ej1-x637.google.com [IPv6:2a00:1450:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 9CB192AE335
	for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 23:21:03 +0100 (CET)
Received: by mail-ej1-x637.google.com with SMTP id yc22sf27025ejb.20
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Nov 2020 14:21:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605046863; cv=pass;
        d=google.com; s=arc-20160816;
        b=CbQADv+uw9ruAQUQAE74Vg7PvMArj4Xfgize26dBdSWHmgvqNtrsR4e48nIHhc1GdA
         kVH7bFZGjzlmNWv45p1/0rDLOsAijwzqTZDH0/vlYdFIeojuluV9fGpmdrvNdu1ySU2t
         qVG/Wg8sd5N11PVKDGNbzN9/LhoqaI507llYj9LliyrUJdlYy2mPbgaR5EBmEMK73Rs8
         AIu5z+1MoMJqr2KYXp2D+qOHj/d948sEUB7DSP8Up9Y+3XatWhciitneUEPrHGUqrgUN
         /fpUE0st4axGoJiE/7mKpHZIXEjUwes+hyJQAopIKVOLYOkW9IH5qV9FbDjE18mVUNmd
         Vi+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=ebAEJM2raNwovosTcoBqiA4NyNIit3Vq4gEYdc+i9YE=;
        b=MI9ljaJdw+yEuQKiKf+Gld6OYlPoJur/sE6AI3q646ybCeXsxENowl3kj1RKqHF4Zk
         JwqKqnW85wZmitLVGe/py6sS5/KZiC8w/47qyzIvi1YWBxzE8jtVQiGADLMCH3WFIh2s
         QU4SoLotoIZS34ajS1fJjE12ZwDuEwMscRUdfUw+ITgkYIgCLn01Zgv5ayyqwPsgRYoG
         1+uziXUTDVqRXbtLo9Vyz6Ehgm2xnjIMO2a8faUs3voYuW9MjPgbEqXo8wclJj73TDXU
         xt37NYGVLL2/4EE88Bpr19G3lwQga7lOE/RfYRxO+jwE+NNmvVzmEbUtqbKg4W3r7b+m
         KQYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nWOy4NUD;
       spf=pass (google.com: domain of 3thkrxwokcsm9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3ThKrXwoKCSM9MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=ebAEJM2raNwovosTcoBqiA4NyNIit3Vq4gEYdc+i9YE=;
        b=s18I2LT6944zEvkg5WiDgQJ/5SYEyAlF+c48yVv4EuzKc3BuVjylRmUOh2jOZ9sO47
         2OeHB91AqC4RRcqtb6Hcmq1OqzAnL/B+M3+3FyiNqYH5EfCpZCLbd+7YrqTJrCVlbPqu
         NZFa4fT5YeqeyKZROM+v0Vv6UcRgc8U6ZR/rFtlFQ54YMg2f3hsNPjt3BnTCfvVhyGIq
         yH7mDw9OjLaxIn7V3uE70Wmg6BBWBhabzwt99Dq8OHUiwMi06lGqZzQgTYKD4ybS/NPQ
         hxoO3CqRh0HiTLYM+VboFPSXOqz5FplOiC23QIfV7zI5ioDKO+WmjfGtPTERMIas1CKn
         n7sw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ebAEJM2raNwovosTcoBqiA4NyNIit3Vq4gEYdc+i9YE=;
        b=HfZO7wZ1LcfHS7P64ISqdc2FDu1pZH2/Hm42Tq1aQQD2nNGn8/MoGyBFaQ9KOb0KqK
         AnNxmSWBeeQ2lQUUkDVQ+sw8Q4xEJICPM7jjM3oEHZJzQtoqIk5Em0bK3cvop8jMndiz
         KUTh9EjZ22nvbsdT6SZP+PkaNx9eIy8UhBZPczwCBgbYndLqWPv8PZBy71mtO6TIibj9
         KTw9qGpFk0ehL1UyA2hdESldZB5lR/l1yT5KSUo28rivD9KjAPDOTjFFRYGws0IDHJMU
         Y1AlycrNitcVJi2r5DNUKzjMNrnLxrx9NWRhqMgOol3+u8lKJvD323reQmIsprnWpwNH
         S99A==
X-Gm-Message-State: AOAM531oQ8+tIUyDhT3vgBz1RMFvGa1J/5+6u3ujpJrzmon0cQcvOBhh
	hZ40ez2Pgb2PsAC3hPAJNbY=
X-Google-Smtp-Source: ABdhPJw1G94gxU1I+BDWBPFda7WCQUvD8+8xaO3CTWcRFhIuM/22DxXSg0iMJBwF6RZI9Q7DmEnR7g==
X-Received: by 2002:a17:906:3c17:: with SMTP id h23mr15303850ejg.374.1605046863407;
        Tue, 10 Nov 2020 14:21:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:c050:: with SMTP id bm16ls6875208ejb.6.gmail; Tue,
 10 Nov 2020 14:21:02 -0800 (PST)
X-Received: by 2002:a17:906:85c1:: with SMTP id i1mr22821668ejy.157.1605046862528;
        Tue, 10 Nov 2020 14:21:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605046862; cv=none;
        d=google.com; s=arc-20160816;
        b=DyIrD3fxHYfdQSjZdUI6CgFzhjIHoLwVGGSxChPfLGc4enRNwU6WEK57k2/Mgcmv3Y
         7izBVEEZROH1AWg4vRdstN80TAixnL5lNpVNXZymeOATwf/QTkkMoVlLFvvIJXVoUHU1
         54S6+HkEW3ns0mvokBVRjoLIcEdsirXpZRIVwFzC9Ea/81hKP576Ba8UozG9BoEGOiHU
         6JwXd+j/xe+B39vGFjeVPtiiTWRZh0QzzuckmtK+BDDLyjHhtR9jM8uhkgzZmpgckuIw
         Wta6zyjQfn3f7YzkMIPKkcjAxg8jvdlouiFxjFaj5Z6NigELcYbxAR2Vqb5FzwSMbFHD
         ajiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=GOGJv8k49mZ7izGKRKf2lz4nE5+QAATrVFhHt9hU4vk=;
        b=pCvOHG+pj/E8zljMG5lpkPf+iJS6zyCFAYKXP+ttpEQS/2z3y0F4QtCqtd4UtxN0D2
         sEy6iXG8oHggvVxXyEE/Ho18YcihCqZR2Nd5eIenfcHmU4XaN3t78VPST32CfXAxuuIb
         Hh1xav7WRY26Sa3+VoL/6+PsOABENYMt/uY/cKZIeJXdqtdGv7yVZVNGVhFI78fdwq2n
         LYviHcb6RQppRDMj0Ek5vffqHKUnzCa8loLhySKRV+DT9KODfrqM6hbykNCcH50Doe+b
         ujv6NvwZQS0VQ4hdtLO/XiKg1m8l2Nahv4v0n+7Eb+x87HK7e/bN4oOkAd2rwBEg5HIj
         toRA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=nWOy4NUD;
       spf=pass (google.com: domain of 3thkrxwokcsm9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3ThKrXwoKCSM9MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id v7si9302edj.5.2020.11.10.14.21.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 10 Nov 2020 14:21:02 -0800 (PST)
Received-SPF: pass (google.com: domain of 3thkrxwokcsm9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 14so1386127wmg.1
        for <kasan-dev@googlegroups.com>; Tue, 10 Nov 2020 14:21:02 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a7b:cbd7:: with SMTP id
 n23mr302280wmi.142.1605046862286; Tue, 10 Nov 2020 14:21:02 -0800 (PST)
Date: Tue, 10 Nov 2020 23:20:18 +0100
In-Reply-To: <cover.1605046662.git.andreyknvl@google.com>
Message-Id: <ee33aa1d9c57c3f2b2c700e8f2c6c24db8703612.1605046662.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1605046662.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.222.g5d2a92d10f8-goog
Subject: [PATCH v2 14/20] kasan, mm: rename kasan_poison_kfree
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
 header.i=@google.com header.s=20161025 header.b=nWOy4NUD;       spf=pass
 (google.com: domain of 3thkrxwokcsm9mcqdxjmukfnnfkd.bnlj9r9m-cdufnnfkdfqntor.bnl@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3ThKrXwoKCSM9MCQDXJMUKFNNFKD.BNLJ9R9M-CDUFNNFKDFQNTOR.BNL@flex--andreyknvl.bounces.google.com;
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

Rename kasan_poison_kfree() to kasan_slab_free_mempool() as it better
reflects what this annotation does.

No functional changes.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Link: https://linux-review.googlesource.com/id/I5026f87364e556b506ef1baee725144bb04b8810
---
 include/linux/kasan.h | 16 ++++++++--------
 mm/kasan/common.c     | 16 ++++++++--------
 mm/mempool.c          |  2 +-
 3 files changed, 17 insertions(+), 17 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 779f8e703982..534ab3e2935a 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -177,6 +177,13 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object, unsigned
 	return false;
 }
 
+void __kasan_slab_free_mempool(void *ptr, unsigned long ip);
+static inline void kasan_slab_free_mempool(void *ptr, unsigned long ip)
+{
+	if (kasan_enabled())
+		__kasan_slab_free_mempool(ptr, ip);
+}
+
 void * __must_check __kasan_slab_alloc(struct kmem_cache *s,
 				       void *object, gfp_t flags);
 static inline void * __must_check kasan_slab_alloc(struct kmem_cache *s,
@@ -217,13 +224,6 @@ static inline void * __must_check kasan_krealloc(const void *object,
 	return (void *)object;
 }
 
-void __kasan_poison_kfree(void *ptr, unsigned long ip);
-static inline void kasan_poison_kfree(void *ptr, unsigned long ip)
-{
-	if (kasan_enabled())
-		__kasan_poison_kfree(ptr, ip);
-}
-
 void __kasan_kfree_large(void *ptr, unsigned long ip);
 static inline void kasan_kfree_large(void *ptr, unsigned long ip)
 {
@@ -263,6 +263,7 @@ static inline bool kasan_slab_free(struct kmem_cache *s, void *object,
 {
 	return false;
 }
+static inline void kasan_slab_free_mempool(void *ptr, unsigned long ip) {}
 static inline void *kasan_slab_alloc(struct kmem_cache *s, void *object,
 				   gfp_t flags)
 {
@@ -282,7 +283,6 @@ static inline void *kasan_krealloc(const void *object, size_t new_size,
 {
 	return (void *)object;
 }
-static inline void kasan_poison_kfree(void *ptr, unsigned long ip) {}
 static inline void kasan_kfree_large(void *ptr, unsigned long ip) {}
 
 #endif /* CONFIG_KASAN */
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 819403548f2e..60793f8695a8 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -336,6 +336,14 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object, unsigned long ip)
 	return ____kasan_slab_free(cache, object, ip, true);
 }
 
+void __kasan_slab_free_mempool(void *ptr, unsigned long ip)
+{
+	struct page *page;
+
+	page = virt_to_head_page(ptr);
+	____kasan_slab_free(page->slab_cache, ptr, ip, false);
+}
+
 static void set_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags)
 {
 	kasan_set_track(&kasan_get_alloc_meta(cache, object)->alloc_track, flags);
@@ -427,14 +435,6 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 						flags, true);
 }
 
-void __kasan_poison_kfree(void *ptr, unsigned long ip)
-{
-	struct page *page;
-
-	page = virt_to_head_page(ptr);
-	____kasan_slab_free(page->slab_cache, ptr, ip, false);
-}
-
 void __kasan_kfree_large(void *ptr, unsigned long ip)
 {
 	if (ptr != page_address(virt_to_head_page(ptr)))
diff --git a/mm/mempool.c b/mm/mempool.c
index f473cdddaff0..b1f39fa75ade 100644
--- a/mm/mempool.c
+++ b/mm/mempool.c
@@ -104,7 +104,7 @@ static inline void poison_element(mempool_t *pool, void *element)
 static __always_inline void kasan_poison_element(mempool_t *pool, void *element)
 {
 	if (pool->alloc == mempool_alloc_slab || pool->alloc == mempool_kmalloc)
-		kasan_poison_kfree(element, _RET_IP_);
+		kasan_slab_free_mempool(element, _RET_IP_);
 	else if (pool->alloc == mempool_alloc_pages)
 		kasan_free_pages(element, (unsigned long)pool->pool_data);
 }
-- 
2.29.2.222.g5d2a92d10f8-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/ee33aa1d9c57c3f2b2c700e8f2c6c24db8703612.1605046662.git.andreyknvl%40google.com.
