Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQ5Q6D6QKGQEFJBI2JQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id EDC1F2C156B
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 21:15:00 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id 192sf7073527pfy.15
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Nov 2020 12:15:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1606162499; cv=pass;
        d=google.com; s=arc-20160816;
        b=ruC44sHTVGoXD1Q3kt0i51A5LoALeTL3qGAjjGvBzYY29C11Xxbnn5wXtiEsD5CKnc
         eRmvEezeNWtJtM1mAJl2LjTm3Bv6Uy8WDBg/P6Q1YoNrn/292NZMyrP4i+w6+5kf/TEb
         8uhsgoULMKptE+960YRGjf+Xp1vizLcy6q2ysd4tZdh8Czw9xnKMGx3bD+3OOpFFaN1C
         1hFVR0iaXQKWrttHqKjdhdg2m/2uH0V17cCxa38cjHmNsLsrRIh+yJNYqHMa55uel4kB
         2Slmsn/cVuCnHb/OXqYam/DVh+hbOrkvZVtf64Kcd++AeM5Fxjb4l3taKH8GXEuYTYTM
         Jn9Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=PcOLfKkRIqAxAewWBD8kZPuRV0yRSfzUC0nFixT4xaY=;
        b=mtcTXd8bgt3FVjpltrEyjXTXyNlwoMnHhDa1COkuefF/wZIAkck7C/jb3I6YSZSsxW
         OG1MQriARiU3xO5lJrBw+K/MyFZ7VuDsHeUFmq1/B9r5jmkXCgVyc4U6YjXIRMh1cv0m
         QuubQckHpI4RMsZMLDpjPDkJfZNR7nKL47WA1UTpLQ7riJkCvyHiPh+DFxGSSKzlqpwW
         kn4wiNdbX8djgz48BOOg1Jvij13Da/FigA+P06pxbGlaU2qHVIB1TZfEcPF6uBPk3y7S
         qveNtPOF8VC0Shwx/iFt/ifoGqVYaaC9ufHWGKB7nNAHapKxDpOgprFD9dheRQyWgCoj
         bN8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fk9aLtCh;
       spf=pass (google.com: domain of 3qhi8xwokcwcfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Qhi8XwoKCWcFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PcOLfKkRIqAxAewWBD8kZPuRV0yRSfzUC0nFixT4xaY=;
        b=ng0YdLEV9jK4v7mLnmyrQmuQ0kQFM9Lw/7apmfqtD3m5KyhmuuJjfLokckzPoj8aco
         3CNkLzugl91zW3Cb+PJgz/I7x0PhHP5LxjHaQMB1CLmIeYqRVUUF7n07RI0BqnKxOnKZ
         ibNXGh26mGP4pv7zUU1Q0ihfSEXo3e3oVNSDqJMFJmXQSiMhEPsjrPXt5BQNbXqk6u1B
         YH8Wy+Rve20pXjwS3U8yHLEXapQvrG/2tMYvnUirAnOz0jYL83S6wKB3siCoQAMeEEPx
         pvQXJkdgMmoqB3ci5aDEyVEtvuhbbKG1RaR93hVcjloYRBiyEgstFPgNu7c9h5FHOFLw
         gfbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PcOLfKkRIqAxAewWBD8kZPuRV0yRSfzUC0nFixT4xaY=;
        b=d+zosnUk1OiAYQxty+IpIu69pFY4t5JP68QVep04V8QK9e1qZw7KGT48/ICJLdzpbg
         ZxaSZEDk7vt3/EequDsu6nB5eYe6/92Wj1t6k7IH8cwcc3eZSysbL8io3uPBoF95qDB4
         cpWpQKCFWvNvEv+phOTd7qKPpZnezmi7vm7/C/lWzEqpnFNm30BohMGkvd8XSIYw2gZA
         BdPx2feje3IP05Oq45t3L65NZ4qqivlplUYmjN2R0p+B2jErS2a3vzd1YA3eWYcQuJYM
         SDJTVAm8BnzURiuXD/6vX3N0S8iZyafclZNji0+ySopgk7cziYrzXrSvjVWY18OwuOqP
         cPtA==
X-Gm-Message-State: AOAM5328ozX7kTH2w0ysX3xbsD+Lp4bb7pYdM1DL9Dipi5nbiPPUEMIe
	m+59Wjo+UspMDuuBoSRskHY=
X-Google-Smtp-Source: ABdhPJyobhJ1reTVtZPHsdhstWj4A90PcY3uFTG1dESbDqo1pLBcJCt+6WX77E0u3641u4VrpthMAg==
X-Received: by 2002:a62:248:0:b029:18c:992f:e407 with SMTP id 69-20020a6202480000b029018c992fe407mr933023pfc.37.1606162499687;
        Mon, 23 Nov 2020 12:14:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:be18:: with SMTP id a24ls211550pjs.3.canary-gmail;
 Mon, 23 Nov 2020 12:14:59 -0800 (PST)
X-Received: by 2002:a17:90a:65c9:: with SMTP id i9mr679318pjs.125.1606162499135;
        Mon, 23 Nov 2020 12:14:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1606162499; cv=none;
        d=google.com; s=arc-20160816;
        b=iTEidorl0d+PLHQcw839ZfouufB/w/pqFOwqHM6SZnXWKJcJWJKM8yyetSm6GiS5Cb
         9uIBlYx/CezQFmVXedySw5oOnjtNzfoh7nqEAWmLAd+xw89Z6BrhhXERl1fGIEZOr8B7
         KR+UYLZoCrV8UEvwi5OaVS62TCS7sMHn1BVx9J2isTkPEUef9pNj1yiid2erzCsCJClo
         H9r4J7G7/9b0k4rsOCBpsdhzaaheTlJksN1b4svAiRheaIoNVr0Z9//EOZ1aMNGmk71m
         TfMsEq7RxhkOuv7Ymh2y1V7X5pbMY243hbl8XfM1goGMhbHnmo2XRtzN79PyA/9mGQi/
         3Okw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Q1jnDs8w1xeJeKoumjoM2fj7KFzVMx2xpTSCdfWMzaI=;
        b=Yr4A9dVMMuoNDpnJa+/SFenvyMfFhQS+ZSgHDs/gXd/dNM8vm1rdKjnfkYg1Yr5ld2
         n3aVlAx4wGlVEyaZLr+SpjtvjlCImWWq9g+FfANcE1iW2t22eToHIoDq1Mu96jE38cET
         LIRJRPNovhX1esUbrEC3QaZQAqDKWMii2H1cRDNP8AY18qWhS96yTLjIcQZlFTndADPP
         7D9yXE2T4V+G5PlEFC7D0OzKqbQMOOTvlI0YDHBENy1kIou6Vey3aL2+930GEp/Gb+iU
         NCHUn8Sm0wKIKKuHfHVZBCgD29QRFvvPKjfCEzq2FXvg1a8o22OsTwfD9WaVdOtVt/yS
         HpLQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=fk9aLtCh;
       spf=pass (google.com: domain of 3qhi8xwokcwcfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Qhi8XwoKCWcFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id f14si663639pfe.3.2020.11.23.12.14.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 23 Nov 2020 12:14:59 -0800 (PST)
Received-SPF: pass (google.com: domain of 3qhi8xwokcwcfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id i39so14498584qtb.1
        for <kasan-dev@googlegroups.com>; Mon, 23 Nov 2020 12:14:59 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:f981:: with SMTP id
 t1mr1155145qvn.60.1606162498261; Mon, 23 Nov 2020 12:14:58 -0800 (PST)
Date: Mon, 23 Nov 2020 21:14:32 +0100
In-Reply-To: <cover.1606162397.git.andreyknvl@google.com>
Message-Id: <27b7c036b754af15a2839e945f6d8bfce32b4c2f.1606162397.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1606162397.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.454.gaff20da3a2-goog
Subject: [PATCH mm v4 02/19] kasan: rename get_alloc/free_info
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
 header.i=@google.com header.s=20161025 header.b=fk9aLtCh;       spf=pass
 (google.com: domain of 3qhi8xwokcwcfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3Qhi8XwoKCWcFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
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
2.29.2.454.gaff20da3a2-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/27b7c036b754af15a2839e945f6d8bfce32b4c2f.1606162397.git.andreyknvl%40google.com.
