Return-Path: <kasan-dev+bncBAABB7VSRCWAMGQEKI4RL7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23d.google.com (mail-lj1-x23d.google.com [IPv6:2a00:1450:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id B020F81938C
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:30:23 +0100 (CET)
Received: by mail-lj1-x23d.google.com with SMTP id 38308e7fff4ca-2cc5ddc6e0dsf30821841fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:30:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703025023; cv=pass;
        d=google.com; s=arc-20160816;
        b=C0rXEPgbqS+CPeOX8bya5sEe8G6RjkSS4Q80QHyRFEAdkow0Au8V1EzPX1+7IC5Vgc
         uBj9Zxr/xpejzzaFnJjCf8mcGlVjEH+hNhzrY9TEQEy8FWWiGPCxGKVFFvyjNGBo8NB0
         9jybZiF13HvnYzsrwtbuJo3Db1YQwYg9maW8PpNvPsgxEhs8ZHLM4avQQAFtD7a/nio5
         fKitI4HoPUIblIYs3/xG43BDp4nZEZCVeGTiK2HtwS+yTC5kGc/mcfieINOVuLjqeLhd
         SZFShpynkD939GVdqLzS4qw3OYwjDBECDGg9WMg2UXvPI/CqfYjR27h53aAABO03umOq
         cg2A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=q/38UZSbRgnXxz5GA9cQ1YFENL7aKMMJD/wo+A6blHQ=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=iR3oLbpXMbu4QQkWp2gKMXmAhqWlQecVpcTkbor8NKHkEgyarFkpdj1eD1H2RjIjBI
         Uzt4yX3oKq0GJCvjYJSPaUrhKZDYCCLH0b77L1ZN9xQ9eEAebGLSvXit2OWY1STdf/SQ
         AbsHCRYBXCskcDMHel3e31nbhWSPddQZrYjHmVJIBSQhbQZi9QCvKpE6KYsqfWpzc8hH
         TN0z9Y3fj5GAZm6bY0EnaP370Up2UpdCW+JMl8jLCTGxgPE1t2MrLPCL00aSuA2nELaK
         F7qcX8FUpJzAPp9m7Nr1O941m5Zo+0/1VxzXzdgenJGan8nnaPhTwYXEFVu+lEjHFlct
         7rvg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ctrg2ZB1;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.180 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703025023; x=1703629823; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=q/38UZSbRgnXxz5GA9cQ1YFENL7aKMMJD/wo+A6blHQ=;
        b=iZby0XhKNsz0Ty+FOAz6b7n/myicaWIlQvzrNedMyMDSCcvzwP3e0g6TZ7MfigW8Qw
         Q8ecyyBVmGeFUSuqvYwhms2V3oELSlFh2ZYpnCer8q/YLZM++2NjV5wMZPaeVlDIqhYm
         ft5cifG8GXvvUo83ZqLqWqkdqnrfc3KqZaAkaVpqhTy8U0tJWiwIGwALgT6MeA60Dspr
         qExplyCaZTh5fVHqPV0PZxE6/ZtH4Y3wI89AfUXLAGEGX9fNbktXwsRD7/NaZsTqb1Ac
         Y4PxxbWGlP6E3IpajaOou+qHPgK+96GqsSc4saXaG7YvbIyJEJKVrC4DCw295MlBpYXE
         FFyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703025023; x=1703629823;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=q/38UZSbRgnXxz5GA9cQ1YFENL7aKMMJD/wo+A6blHQ=;
        b=RKMcMATN1tuHzbAL+mosK0hTMBHJfAMiVQQyhTmryGFDdLFPQtgHuwVUVGwHU1WbFr
         5W/qqAqlw2paSu4cYtg2CaVNeBG5b2MwLFATNWVPtgLMjS8da7BMVN7V6C4HwIU2CvvH
         7u9rV4XGZSGlYhhqpD0rdqoxieY89B2CaBCNUj5fBCkREaNS5pB5qQegiH5ZQKZNbB3A
         VoDfgA38JENEv/fcExHFPMrtC2ond/5WWAZWWcMxAtIkgPu4ex40ROz/uXtucTQUo1K1
         6MsI+RRQ+diNTJR7qjvqYsVeSIXf21jvj5NY0tKtfovlq2IOKy4PYFsIXs9f4XvRJzcF
         2F6Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Yy7Rsc5R4Su7lrQnLykKj/P/mLGAqyLhSTPo3Fp91BlX9ibGluG
	oDqbEUnW4ABdi84PbfFQ9Js=
X-Google-Smtp-Source: AGHT+IHe3+KjIFeLC6ibyTzwSPuTleQp8kGWaOJt+Lm6b74ybnhEhx0VQtRfduK4hMXP4Qfvts/q8Q==
X-Received: by 2002:a2e:be9c:0:b0:2cc:641f:9a35 with SMTP id a28-20020a2ebe9c000000b002cc641f9a35mr2746775ljr.86.1703025022965;
        Tue, 19 Dec 2023 14:30:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:26c9:b0:551:46b6:345e with SMTP id
 x9-20020a05640226c900b0055146b6345els288658edd.1.-pod-prod-04-eu; Tue, 19 Dec
 2023 14:30:21 -0800 (PST)
X-Received: by 2002:a17:906:344e:b0:a23:4951:9962 with SMTP id d14-20020a170906344e00b00a2349519962mr2313576ejb.115.1703025021206;
        Tue, 19 Dec 2023 14:30:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703025021; cv=none;
        d=google.com; s=arc-20160816;
        b=xPEC4/nJ3nFJdSNr9UOznLzn31GiEIJgNiXNNA1lc09QFf1vgqNd2oiiDAfNTrnXCS
         jC7i5S5oP4mMG5DMnxxgI86fPDgbYhgrVqJ95Ys7umgym0k7YpB7N19NNBfiSznVxKG3
         BfLfSycGPRFd43TtZ4Ix5tWRU/t7ASeyVR0RDpe3pzFxlbP883du5cOgcOamBJ3pE6ZK
         8hKM0OVx1U+h8CMkzigRitkYIIVOFM+QtaBeJu9K7aqPiovtY5xLY9pl4KjgZUTri9Uk
         AihaMRL4nNXIpj1ADdhDQqLkyokEX7QVLyGbuA9JzNSuFVCJB5DoaFk2xYjePBgr4Sxq
         TXFw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=TOZdtH5KljVO+QBwvb475Ri4NSt7i5y2rX8Y2gdn2wY=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=bNpZt84Q+DTNNqY33Tom70TykTWY7KINmMUdKU1Sy/hUaJbhZdNU3XGM8OhSCOw3AY
         gL+jU3jdoAU8ZRaovMvdmDrt11wWLMFnf6pZV5ZSK4P5ZDcx/eRJpKvoJ0Jiuv2mhsf7
         yAljD0UuB2ch5eSVv3CrK8VztUUhPYYfoPlruhJW4IDPTfqxXEJ8GdjHfL9xyc4ClBfQ
         bkO3wRck6XlGSOqzEHLwW8Nt8/+bcknHIa7dyd7WUKnTnAH5J+/9sZKs2OEb4DV/BWBI
         I020xSRt1tsdUr0bGzh775pnPzksD6Hxv4Pl/XWKtHlUlCTTlpQQ9+mPJ7f4SpXycQg8
         QEug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=Ctrg2ZB1;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.180 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-180.mta0.migadu.com (out-180.mta0.migadu.com. [91.218.175.180])
        by gmr-mx.google.com with ESMTPS id dt10-20020a170907728a00b00a2355945814si283172ejc.2.2023.12.19.14.30.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:30:21 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.180 as permitted sender) client-ip=91.218.175.180;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Breno Leitao <leitao@debian.org>,
	Alexander Lobakin <alobakin@pm.me>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm 10/21] kasan: clean up and rename ____kasan_kmalloc
Date: Tue, 19 Dec 2023 23:28:54 +0100
Message-Id: <5881232ad357ec0d59a5b1aefd9e0673a386399a.1703024586.git.andreyknvl@google.com>
In-Reply-To: <cover.1703024586.git.andreyknvl@google.com>
References: <cover.1703024586.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=Ctrg2ZB1;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.218.175.180
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Content-Type: text/plain; charset="UTF-8"
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

From: Andrey Konovalov <andreyknvl@google.com>

Introduce a new poison_kmalloc_redzone helper function that poisons
the redzone for kmalloc object.

Drop the confusingly named ____kasan_kmalloc function and instead use
poison_kmalloc_redzone along with the other required parts of
____kasan_kmalloc in the callers' code.

This is a preparatory change for the following patches in this series.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/common.c | 42 ++++++++++++++++++++++--------------------
 1 file changed, 22 insertions(+), 20 deletions(-)

diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index 59146886e57d..1217b260abc3 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -312,26 +312,12 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 	return tagged_object;
 }
 
-static inline void *____kasan_kmalloc(struct kmem_cache *cache,
+static inline void poison_kmalloc_redzone(struct kmem_cache *cache,
 				const void *object, size_t size, gfp_t flags)
 {
 	unsigned long redzone_start;
 	unsigned long redzone_end;
 
-	if (gfpflags_allow_blocking(flags))
-		kasan_quarantine_reduce();
-
-	if (unlikely(object == NULL))
-		return NULL;
-
-	if (is_kfence_address(kasan_reset_tag(object)))
-		return (void *)object;
-
-	/*
-	 * The object has already been unpoisoned by kasan_slab_alloc() for
-	 * kmalloc() or by kasan_krealloc() for krealloc().
-	 */
-
 	/*
 	 * The redzone has byte-level precision for the generic mode.
 	 * Partially poison the last object granule to cover the unaligned
@@ -355,14 +341,25 @@ static inline void *____kasan_kmalloc(struct kmem_cache *cache,
 	if (kasan_stack_collection_enabled() && is_kmalloc_cache(cache))
 		kasan_save_alloc_info(cache, (void *)object, flags);
 
-	/* Keep the tag that was set by kasan_slab_alloc(). */
-	return (void *)object;
 }
 
 void * __must_check __kasan_kmalloc(struct kmem_cache *cache, const void *object,
 					size_t size, gfp_t flags)
 {
-	return ____kasan_kmalloc(cache, object, size, flags);
+	if (gfpflags_allow_blocking(flags))
+		kasan_quarantine_reduce();
+
+	if (unlikely(object == NULL))
+		return NULL;
+
+	if (is_kfence_address(kasan_reset_tag(object)))
+		return (void *)object;
+
+	/* The object has already been unpoisoned by kasan_slab_alloc(). */
+	poison_kmalloc_redzone(cache, object, size, flags);
+
+	/* Keep the tag that was set by kasan_slab_alloc(). */
+	return (void *)object;
 }
 EXPORT_SYMBOL(__kasan_kmalloc);
 
@@ -408,6 +405,9 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 	if (unlikely(object == ZERO_SIZE_PTR))
 		return (void *)object;
 
+	if (is_kfence_address(kasan_reset_tag(object)))
+		return (void *)object;
+
 	/*
 	 * Unpoison the object's data.
 	 * Part of it might already have been unpoisoned, but it's unknown
@@ -420,8 +420,10 @@ void * __must_check __kasan_krealloc(const void *object, size_t size, gfp_t flag
 	/* Piggy-back on kmalloc() instrumentation to poison the redzone. */
 	if (unlikely(!slab))
 		return __kasan_kmalloc_large(object, size, flags);
-	else
-		return ____kasan_kmalloc(slab->slab_cache, object, size, flags);
+	else {
+		poison_kmalloc_redzone(slab->slab_cache, object, size, flags);
+		return (void *)object;
+	}
 }
 
 bool __kasan_mempool_poison_pages(struct page *page, unsigned int order,
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5881232ad357ec0d59a5b1aefd9e0673a386399a.1703024586.git.andreyknvl%40google.com.
