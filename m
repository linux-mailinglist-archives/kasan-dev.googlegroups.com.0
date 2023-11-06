Return-Path: <kasan-dev+bncBAABBPMRUWVAMGQE7ANZKGI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 0F36F7E2DD7
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Nov 2023 21:12:47 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2c50ef18b04sf51572501fa.1
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Nov 2023 12:12:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1699301566; cv=pass;
        d=google.com; s=arc-20160816;
        b=VKBCapXJP0PBQMP2lOuOi1VARYZVJe8DtHtfob/Bkw2JVfPi4RGZh2DSGFUODLBTXF
         LIrFTFXXDM7ncWh6Zl8AHOgLmQwWU1SygY2wG4kb1VOxmuD/Z/FfiobSn4f1lu392KGU
         ffqoSThwQAdshffdrShrdot2IQWFqRQInfVdl+t+pTXrNWE8NL1H1yvH5KeJM+5w4hgW
         G4lD0o8S2ia9xzHRIFzUamrDCVvQ6bvO1JohdwdjJivF0ecJ+GIca7JBXpYiBs9ZPMYH
         0rCssat7OywcQfkXJxbFKuNu0eU2kzK9l3kTV42SFwsJxa2Zpu7S5P4IZi55pim0xMAI
         5kQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+6zd4QjuDC8NZ7ycLEjkkcJHHZffrWz4/aV6V60PpbE=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=qW0Q7rvWYkrVnXXBdSjDTY5qmuXorS1tLdvSjQ5nF+Zf9TGrkkEKnv+1QEEosqA1ut
         G3Wcf9c1ZaMxaJzS+z+Y8Ave2Cf8d0CpdxOfZaeVT706gRUBQUtKGnXxdkfxe2/I6CYW
         n20+BFa4mq66aLCILjspYty3ycgVsVEcssn5lm/jHBJeif7QXjNxAMNwpjbSrylHKdT8
         MdF2KeeYe+w6jnRvG2KLcB9JAP7DBvn+2mr07fi+PLf79kQZ6wKwK2lOrJ21tVIYhvHb
         sdq1BAFfOYHUG1SiXTzHyS62y0lKIPcEOig2ma9Jiy7Ow2ZyPX6ss/ZC/NjDbt+ce31j
         4DvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pwv3dkzf;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ab as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699301566; x=1699906366; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+6zd4QjuDC8NZ7ycLEjkkcJHHZffrWz4/aV6V60PpbE=;
        b=OvTE3f9UVwX/LCoMjtZ6D2L0HIFzNH98pFm+lUkunb15+Z/5nOdFrPIXnidtIqlAXi
         KK/5OJ3EAULtk9SPzNy0PtSI4H/O2lWzqbieWdLY5zVuM+tw8cSuslsR+lUEXzMcvXQj
         ZGLmrV+KL4ToFMlRYGSAWpNa05+6iGBRTT43pYl38sjRlgbvtpqcFd6ek4blOqNAayZS
         jHV1hbKW/OHkT7i3qUZfIh/DQrT+8YgsQn4F1jbdL02B1v+Yez7gX//pdwpFI/C1yKtG
         +1u3uXdT2FS49j0KVzT/j/c61bb5FxeAkMPGdmppiWpIW8mZ9rb85HfnNaOQRozuZrKB
         J+oQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699301566; x=1699906366;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+6zd4QjuDC8NZ7ycLEjkkcJHHZffrWz4/aV6V60PpbE=;
        b=krKnRDJNYoUHN1XZai/P02KYwR8KwB2+OJi1p5hJHJPe2V568gSDv25oo6Fx5PUz69
         7kkBEtdKwQDWVxw0Y7fh3mABhtQNHx36fhywOGS6EC7FamJLiVpZGCkzpYRR3DYaf5l+
         dg7ocPHKywyLoEFIYDM4fs+amKPyH2Y82jPnUHjcHDSsAaqBeJnp9g9Psa3ASmB8tkzb
         SAAehpIauDZ77Mgtsq1PmLZIT1It1m+/gVxqsEovYmvWnQZ5Ys6FR2BCSeCZ0ptxvYex
         ydcX2dMOFqAMQXagwPiyg6OxEZYrbLnQbUJCgNShvCpohSQyrKbrBon5OvS+EM9ImyGC
         PAPw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyuXcILRQb6dS8s0e8MwAqsFuELIjHET4un7DVEdSjO9GBtQpdo
	raua5i+pYTQD72LhBBivI+M=
X-Google-Smtp-Source: AGHT+IGaR17cBStSa5CQt3gjKOvll8HNyUB+0HyTA4GPcmhv+2IxGw9QyLC4sZD6a1X1wyaC+s1J4g==
X-Received: by 2002:a2e:b4bc:0:b0:2c5:fb9:49b6 with SMTP id q28-20020a2eb4bc000000b002c50fb949b6mr20646510ljm.10.1699301565762;
        Mon, 06 Nov 2023 12:12:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:bc11:0:b0:2bf:c704:bca1 with SMTP id b17-20020a2ebc11000000b002bfc704bca1ls500910ljf.0.-pod-prod-04-eu;
 Mon, 06 Nov 2023 12:12:44 -0800 (PST)
X-Received: by 2002:a05:6512:2244:b0:500:9a45:62f with SMTP id i4-20020a056512224400b005009a45062fmr30068473lfu.8.1699301564066;
        Mon, 06 Nov 2023 12:12:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1699301564; cv=none;
        d=google.com; s=arc-20160816;
        b=lKd1wGUyf4XHsCtGdOb70nQEbewuVWu3zZnHataEQ69czKcs5I2sm5ov2hYzguV8MY
         EJF9FDeehiK8TmEF8aE48LRTsDKog5LqmyvBLvvVtSvu9ThOEv7joK9/q907irXOrxox
         YQ8HLzjD6XsJuyNkoZecfLbx62PZWExTv416yQGv+cEO8VadvNetZH89QmM5xTF7mcJ1
         DGMLIfq+aCxJMYOuw4m7IqX9tDQQ1I961mB9fdNFqZ/ZUyxoIzduzfFBDyRShqE7vqHY
         GILEkomaWfUTGb59zvQw+0t5pOjtzlUaGxbKi+oGYrJ7klLr6vM7loj61R2DAH7AAS5f
         mTQQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pzcd7T6SaBRo5t2Dalks3vRx+ahOG8KGm+CRn7Qcn4c=;
        fh=n5KN85tQTomq0Sa/nFFC9xbnc77mxkBzF8HoolO/QOw=;
        b=d37G0ana/qWuzW8EOPxNBH5wt+pad398B6NNEDHQPgvuDqys7rQeG4QMpvidDc5UkE
         a+UURnqgupxR+TpMS3fZftXEr4K7DBZk+TMtGrRhp5wbRWNaeQafmeAlwy0w/wWgz7rq
         wjBMsTeecIwE3YDcp8I9EVGXMV2Ent4aWdFNF08SxRO+rQpdNSIr3XBnhXyNxVpGqn5z
         2ohyCnyJCMxLDE6aEZR5a4NlGVIaiR6RAvK5IJzm/4RwZwWiNT7xqKwrLoMUb0mKEXHx
         E3Musb/PXTaXsEraBf1kW5z/mpPBEV4gwWLUw8nxDn0LykuVvb5qp6EL1dHrVDza3I4i
         8onA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=pwv3dkzf;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ab as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-171.mta1.migadu.com (out-171.mta1.migadu.com. [2001:41d0:203:375::ab])
        by gmr-mx.google.com with ESMTPS id a1-20020adfe5c1000000b0031aef8a5defsi32725wrn.1.2023.11.06.12.12.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 06 Nov 2023 12:12:44 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::ab as permitted sender) client-ip=2001:41d0:203:375::ab;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH RFC 12/20] kasan: save alloc stack traces for mempool
Date: Mon,  6 Nov 2023 21:10:21 +0100
Message-Id: <325b1285d95f7bb6d2865750aa0088ab4cb5e0c3.1699297309.git.andreyknvl@google.com>
In-Reply-To: <cover.1699297309.git.andreyknvl@google.com>
References: <cover.1699297309.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=pwv3dkzf;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::ab as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Update kasan_mempool_unpoison_object to properly poison the redzone and
save alloc strack traces for kmalloc and slab pools.

As a part of this change, split out and use a unpoison_slab_object helper
function from __kasan_slab_alloc.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/linux/kasan.h |  7 +++---
 mm/kasan/common.c     | 50 ++++++++++++++++++++++++++++++++++---------
 2 files changed, 44 insertions(+), 13 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index e636a00e26ba..7392c5d89b92 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -303,9 +303,10 @@ void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned long ip);
  * mempool).
  *
  * This function unpoisons a slab allocation that was previously poisoned via
- * kasan_mempool_poison_object() without initializing its memory. For the
- * tag-based modes, this function does not assign a new tag to the allocation
- * and instead restores the original tags based on the pointer value.
+ * kasan_mempool_poison_object() and saves an alloc stack trace for it without
+ * initializing the allocation's memory. For the tag-based modes, this function
+ * does not assign a new tag to the allocation and instead restores the
+ * original tags based on the pointer value.
  *
  * This function operates on all slab allocations including large kmalloc
  * allocations (the ones returned by kmalloc_large() or by kmalloc() with the
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index b50e4fbaf238..65850d37fd27 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -267,6 +267,20 @@ void __kasan_kfree_large(void *ptr, unsigned long ip)
 	/* The object will be poisoned by kasan_poison_pages(). */
 }
 
+void unpoison_slab_object(struct kmem_cache *cache, void *object, gfp_t flags,
+			  bool init)
+{
+	/*
+	 * Unpoison the whole object. For kmalloc() allocations,
+	 * poison_kmalloc_redzone() will do precise poisoning.
+	 */
+	kasan_unpoison(object, cache->object_size, init);
+
+	/* Save alloc info (if possible) for non-kmalloc() allocations. */
+	if (kasan_stack_collection_enabled() && !is_kmalloc_cache(cache))
+		kasan_save_alloc_info(cache, object, flags);
+}
+
 void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 					void *object, gfp_t flags, bool init)
 {
@@ -289,15 +303,8 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
 	tag = assign_tag(cache, object, false);
 	tagged_object = set_tag(object, tag);
 
-	/*
-	 * Unpoison the whole object.
-	 * For kmalloc() allocations, kasan_kmalloc() will do precise poisoning.
-	 */
-	kasan_unpoison(tagged_object, cache->object_size, init);
-
-	/* Save alloc info (if possible) for non-kmalloc() allocations. */
-	if (kasan_stack_collection_enabled() && !is_kmalloc_cache(cache))
-		kasan_save_alloc_info(cache, tagged_object, flags);
+	/* Unpoison the object and save alloc info for non-kmalloc() allocations. */
+	unpoison_slab_object(cache, tagged_object, flags, init);
 
 	return tagged_object;
 }
@@ -472,7 +479,30 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 
 void __kasan_mempool_unpoison_object(void *ptr, size_t size, unsigned long ip)
 {
-	kasan_unpoison(ptr, size, false);
+	struct slab *slab;
+	gfp_t flags = 0; /* Might be executing under a lock. */
+
+	if (is_kfence_address(kasan_reset_tag(ptr)))
+		return;
+
+	slab = virt_to_slab(ptr);
+
+	/*
+	 * This function can be called for large kmalloc allocation that get
+	 * their memory from page_alloc.
+	 */
+	if (unlikely(!slab)) {
+		kasan_unpoison(ptr, size, false);
+		poison_kmalloc_large_redzone(ptr, size, flags);
+		return;
+	}
+
+	/* Unpoison the object and save alloc info for non-kmalloc() allocations. */
+	unpoison_slab_object(slab->slab_cache, ptr, size, flags);
+
+	/* Poison the redzone and save alloc info for kmalloc() allocations. */
+	if (is_kmalloc_cache(slab->slab_cache))
+		poison_kmalloc_redzone(slab->slab_cache, ptr, size, flags);
 }
 
 bool __kasan_check_byte(const void *address, unsigned long ip)
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/325b1285d95f7bb6d2865750aa0088ab4cb5e0c3.1699297309.git.andreyknvl%40google.com.
