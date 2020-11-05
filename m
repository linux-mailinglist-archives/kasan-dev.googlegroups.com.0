Return-Path: <kasan-dev+bncBDX4HWEMTEBRBIMCRX6QKGQEJ3QFS6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63d.google.com (mail-pl1-x63d.google.com [IPv6:2607:f8b0:4864:20::63d])
	by mail.lfdr.de (Postfix) with ESMTPS id C64AD2A736B
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Nov 2020 01:02:42 +0100 (CET)
Received: by mail-pl1-x63d.google.com with SMTP id g2sf61906plg.1
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Nov 2020 16:02:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1604534561; cv=pass;
        d=google.com; s=arc-20160816;
        b=YXqxdjZZ//60A0IHK0jxGl12zY2259lpJ3qMFODtSyG3lhRBgVSrm9dC7c8TeJwWgP
         pzB9VYlZ+A26qS9Vqfw3nyPwEMVe5YgsQxmTnqqqtMUTdccTbCT4sUyGYBnwA8fO8Dkg
         TeCKS2Jk/0nSKCamH0BAtSBuYxPweg12zCrK4kRBy9xIpsg/bXAF5JymQUP9saxJpSX2
         6JBLoBIn1sjt2sIOJExJOL+njhtBlNbRdefvAQXWjzzzKa6MVzekGldHMrCWH5pwz38k
         5P/DtodCazMeE6oIW2p9UivhgFnjZFQtH2AuGOXWTFZiNZS1rCCz44H10VegxeQSRi/Z
         4meQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=QWPpFJ4NmHTIwI5/IbtD9trxBjrVU7mDwqDvdBemMsk=;
        b=k5Sq/BRMQ1ZK1N7OIEEHbW9uDUaaoEsI1TbHF4hGfOMTvDDMvrRgYLZxjB+Mg5Eej/
         NkO++pYl07QsgzeJHt6LupkP2eKbr7qFQBqhI82+Df78rZSMW1mS/ntcabpNPywbMx8z
         8uUCSGKsA+RvzINToUa81wBHreBhy8dOS2e9V31YyTkAbpP78RfmektJ07IZQKMmjztl
         xUZPw1NO49fyJLT3DE1YTDfCcTvVYjmOyhSTZxsCPY+11n7JaRD5yXs6onRe2H+XHqXw
         wkU1lY4W0svx1X3QBbRPr48IrsSCJHv/t73MCdTDDtw9AQHwbOFVJBl22sN2kMC7dw1u
         r0Lg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QP+KU7EF;
       spf=pass (google.com: domain of 3iegjxwokctmpcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3IEGjXwoKCTMPcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QWPpFJ4NmHTIwI5/IbtD9trxBjrVU7mDwqDvdBemMsk=;
        b=flsit6M7NBSPyS+X9AeWYQ1/8cg33+ckvLsptpB3640ybbLB2JwP3gLW7Z/gEycQ86
         SNRLvSKMWIYex0OROufrJbBcxGORAGWtJTnHklj0dn1+mqALHU0g401RIw1HDlgo+KOP
         7DgzJzNAZjv/gWpBj9zWhvYTiBftWiouhU45G+/+KeiAlN/4tLMGz77E2n8etaCmb183
         1MqjhV/ZXvHat/ep20vdOuPPHyziW2TWh7kn18sMJzOVpiL8W6ICgOg70sLDW0wbd4AF
         jMYrHgPOA3JL+vcr9ijIESGaquzXdc2b8B7JwCiq9lAOOf+JFDdeCvA4NSv7pIRBY7o+
         SWlg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QWPpFJ4NmHTIwI5/IbtD9trxBjrVU7mDwqDvdBemMsk=;
        b=IKMMet5OLJue7/bu6K/Mlgdrzgbb97kh/cppjzcrVXPpZhEyGlzkLjaPFz4D+j2In6
         m5Ml7rFVqDtK52u3frKf3mrosuj+v6yIonEADYrVU/XfxEfZSXgP4gvjqLkqqC8/KBPf
         szbnA2P4QS5h15ayURH96lolZyOCTVQK5jGGrvERwjK0eGrGPBPV4nJKqjxncWtIZbCT
         bZ/NkubDX74MrsWjFiaeQG7YpqVkXjvz4M/mK2lgE2H1j9Uu9C4jTqvqjywBM5wg8dfF
         OTPOen15V702ZF8/1PbAA1pC5pc6rGgmNTziyfXE3RHIlfX3exVtAHXR3c1/e3EI8+pP
         Ja+g==
X-Gm-Message-State: AOAM531XiA9Fp5gbyrjPfjM3shYErnW931kf5dNNOqENtW08j9ZnBEXB
	mAHyAhg1cftVjUrHUM5aeCA=
X-Google-Smtp-Source: ABdhPJy8yK1dFOcnKKWhCbTKctIVRcOZPasKlNANA3Q+hXJaWBtHHaHbpPciQoQYc7PshnzDbYks8A==
X-Received: by 2002:a65:4483:: with SMTP id l3mr427879pgq.96.1604534561564;
        Wed, 04 Nov 2020 16:02:41 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:aa08:: with SMTP id k8ls14851pjq.0.gmail; Wed, 04
 Nov 2020 16:02:41 -0800 (PST)
X-Received: by 2002:a17:902:b70f:b029:d6:5bcb:1b24 with SMTP id d15-20020a170902b70fb02900d65bcb1b24mr406912pls.82.1604534561014;
        Wed, 04 Nov 2020 16:02:41 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1604534561; cv=none;
        d=google.com; s=arc-20160816;
        b=IfadRY6VQt2rHRHOzFmaz+j5Zb9Nb+50cTv/R6jPhc6Dlv5A0g4iTvKp0WWeAo6S5/
         6rU85hBExIhnhkilTnYEYbPR5D0VYy4NH4GSz2VP6h36u9HxH5jQMWKRtsZjXyD8PDit
         zIuCmCMqbJH01aOmftSaO6hj5sYsH7sFjT+ZIxNrBJ4X0jpNBEX4GV58uMaJRdbFss4+
         Aabm3LV45nhAeb4GcUQ75sqn6JKDJpth20F7HeAEiZGteOztDwr1S2UasLV9gDQSDRII
         eEPrCfM/hA7DuPp2te7T2QF3cT0M0k7VxwRR7Owpj3mN8ABeWykAljxKqFx26W34C+3E
         VNFg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=XrlC+aEcWbd3aE57QC+9E5FwHOZXpbQu57tR6JwJ5+c=;
        b=ZwnnAYVxFB6+46vAdFVZrfnm1qJpQ32jRnHLlcm5mO6z/1ga5N/lL8G8Yz2bjEMSKa
         EDgCIqDBy8SnRSeuDyR7BARK/zajC2LeCNTtWF0KQqQmoWQhJYTgfFXWjfnMqbeQB2pg
         wd1le1xXphByC41OAirNkPD2IxdAfg3tLRKUl6HObjUR9E2s8khdVYiXU5MNxbkarVvJ
         Fk1KNeFKyXQzRRLQI4frndp+sN3ObTZnsml20N8P1/D/eBFFPs2MG1YsbAAreXHxRAmV
         dRO/NcKGEYUfYpK9m5Njz8AVzdiwKKQC381iwFHiAwCSYgqE6eOw4Vx7KQJ7T/CgTKoi
         VISA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QP+KU7EF;
       spf=pass (google.com: domain of 3iegjxwokctmpcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3IEGjXwoKCTMPcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id 38si247736pgq.3.2020.11.04.16.02.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Nov 2020 16:02:41 -0800 (PST)
Received-SPF: pass (google.com: domain of 3iegjxwokctmpcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id t70so35645qka.11
        for <kasan-dev@googlegroups.com>; Wed, 04 Nov 2020 16:02:40 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:ecc8:: with SMTP id
 o8mr293863qvq.54.1604534560168; Wed, 04 Nov 2020 16:02:40 -0800 (PST)
Date: Thu,  5 Nov 2020 01:02:12 +0100
In-Reply-To: <cover.1604534322.git.andreyknvl@google.com>
Message-Id: <7fb01c82767f6ec2ef804ec4689b7a9620b5bb4d.1604534322.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1604534322.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.1.341.ge80a0c044ae-goog
Subject: [PATCH 02/20] kasan: rename get_alloc/free_info
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will.deacon@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Evgenii Stepanov <eugenis@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=QP+KU7EF;       spf=pass
 (google.com: domain of 3iegjxwokctmpcsgtnzckavddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3IEGjXwoKCTMPcSgTnZckaVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--andreyknvl.bounces.google.com;
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
index 25ae7b43db87..d858aeb7387f 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -62,7 +62,7 @@ void kasan_set_free_info(struct kmem_cache *cache,
 {
 	struct kasan_alloc_meta *alloc_meta;
 
-	alloc_meta = get_alloc_info(cache, object);
+	alloc_meta = kasan_get_alloc_meta(cache, object);
 	kasan_set_track(&alloc_meta->free_track[0], GFP_NOWAIT);
 }
 
@@ -71,6 +71,6 @@ struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
 {
 	struct kasan_alloc_meta *alloc_meta;
 
-	alloc_meta = get_alloc_info(cache, object);
+	alloc_meta = kasan_get_alloc_meta(cache, object);
 	return &alloc_meta->free_track[0];
 }
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 994be9979ffd..5513b4685007 100644
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
2.29.1.341.ge80a0c044ae-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7fb01c82767f6ec2ef804ec4689b7a9620b5bb4d.1604534322.git.andreyknvl%40google.com.
