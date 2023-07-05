Return-Path: <kasan-dev+bncBAABBHOLSWSQMGQESRQNE6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 544C3748457
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Jul 2023 14:44:15 +0200 (CEST)
Received: by mail-lj1-x239.google.com with SMTP id 38308e7fff4ca-2b6fdbe2efdsf8071131fa.3
        for <lists+kasan-dev@lfdr.de>; Wed, 05 Jul 2023 05:44:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1688561054; cv=pass;
        d=google.com; s=arc-20160816;
        b=c+birmKwpLlFWaAKorTpGhgClEWq/WCbvHBUUBVr1JU9ngfAUPSCkU6coiS1u/bPFE
         iNI43t0rF00/4VyxSz1EmUk6TPuXoV53F2TC8AfRN8DvEScTzrldPmuw7UJBk//Osnn4
         uQhmKazaiO0MQor8BaGjXJ6VHo03mNUkNVxYsVwiTdg85mztoEIb9rlvFWt1TMlfw6U0
         wGiarhf/aGwW/TJI66NPjMNvVBvtwq6dfE0VX8h9Ge7O268ObOEF1MAjvSs7JD0Xg95J
         8s2wq5F5sSGxjnkNCt2vmJbDM8wkvOLbJBuXoG+FBHtqOXG+pkwErHNwwIxdUcohC8Tt
         QzCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=Rbg2HnWMvemQ+/eQrjRZgh0K1oVMKKPA8TLN/+VheKg=;
        fh=xT/TyM1Q24WPLrvck7c/7hBNuM75zgT2kRItA7gjdiQ=;
        b=teZETE3Gl35/pZwJxZsiHJ37QXZVVNDnh/4WW6Bw8Hyq/YpM4TpCPvjT/orZQmOTb5
         Ae0O5aMYi3hT9YoE9HkOwXaOE4W6x3pJ1B5666YwKCzS4rTq8xnExw9x0b4GrzZfW0M9
         yXGOCdvZnQB5in3sxSF4y5S/Q0F2BuHoqubDKtoB1aPtKCC6HtHb1qbSjRx0GlHv1Vm9
         mI9M2MnvRO5WN2M3hyE+epXrSBWgwOu49j6UhBvKUuknV9I5Po7ouHlUtcRQoL07WzJY
         Y9xPszt2BZTqLaelrFyvwcpKi2Wrv0ABD41D+4vKzsGxUc1fNiQulyNuOYT7cogeEXh3
         qg2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=L8cZm9Lx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1688561054; x=1691153054;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Rbg2HnWMvemQ+/eQrjRZgh0K1oVMKKPA8TLN/+VheKg=;
        b=HuFSAdyPSKpSfZLshmBMhSg0b5G5/WQhUEPcT4J8EPYy2hsGqJUBDPIb2SLu26kMlN
         is9M7J7gYdIjIwrOTUfHw34+0Z3JFhlo6gEFNkC+ACgxSnAMsjDEC2r0/1AB75ggdQ1C
         GQ3iyNMXzU/OVVyjkq6rsykzkbRMeo85cyjmf3AipR/mWbDBoxBBQKjU+WXqN0qSZwc5
         2CZr0ZVV7aUCsydDFlEnco1m1WkasvWXSzZmOthcu01NHS18SNooGrICS88PlegmlVCf
         aVyC+uM6o3JhhLo4R8xSxbhcQ895g6MQ4eHGs6CdKP//6J7DRLEm65Ard4elhI4EpMmh
         67Ng==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1688561054; x=1691153054;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Rbg2HnWMvemQ+/eQrjRZgh0K1oVMKKPA8TLN/+VheKg=;
        b=SDTcTsS5RSinqfHeU+lMwMbFVD8S3oIzn28zfqVm/XnpUrAnBxrICbb2u9iDAkrX/g
         BX3SbUsJkvNDXfE9YINduDG99KaEkdDOwgWS1ZxSzxZv9oR4cymQrNt3AZHI2SlCOXH6
         +oQDW3FPM20RPyk0WXVuZUemw5+3FUN4OzRmZgl12Tht4ow7lOBefPZFmKQjqTquBnre
         owCFKPdr5Wb29EYhPkWqb+Y33HqnkGhfOkQRXiXnLnJfEuJETHNNAd+F1ypFFi37lA6t
         fHGdTU0Ix0hlWxqHgmpiNMHgjy6Y3Ev1ypWIz3mqBGfk9oX5me7ywrKwMenyfoogQg1f
         w/Qg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ABy/qLaREzqTKKVwzzp9LPfehZoX66I34w3cR4W7t1fDbufQcBQYG9Mn
	BNxd7YOabfWgWNXmYPBiq7M=
X-Google-Smtp-Source: APBJJlE9uGD4JoW2VvY9ZX7kQPjGdzZ2e52aQAOTd55eMI0qFN7+Av17Qi0ZDOXjLuovM9qa7DOG0g==
X-Received: by 2002:a2e:8188:0:b0:2b6:cca1:975f with SMTP id e8-20020a2e8188000000b002b6cca1975fmr10734464ljg.13.1688561054029;
        Wed, 05 Jul 2023 05:44:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:9ac1:0:b0:2b6:bf6a:f7a3 with SMTP id p1-20020a2e9ac1000000b002b6bf6af7a3ls3555116ljj.0.-pod-prod-06-eu;
 Wed, 05 Jul 2023 05:44:12 -0700 (PDT)
X-Received: by 2002:a05:6512:1094:b0:4f9:5a61:195c with SMTP id j20-20020a056512109400b004f95a61195cmr11929709lfg.13.1688561052515;
        Wed, 05 Jul 2023 05:44:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1688561052; cv=none;
        d=google.com; s=arc-20160816;
        b=lZ0+sYEllDrhBLXk9EZ5J0m7gEAQwF+aluO/NK9WO8S8VysKNeJuQP/vgM6JjUiz1D
         r+8cA7EA4EOcIGPmQUddr0D3/7ac9ruBblsEX90JtggZ0k5lQlgsAe8cGbnB1Jqe1/F9
         MvJGT/KNZnXlM3+YW6D6r69dhf3AA/dEo26Jkj1C/7T+Nldk4J3NXQrhgEFlr7L+DipX
         7qaCHjJuj96jXtSqt0zTGJDcn0SEaQS1GwFm7f1xLsrt2xYYWUrETS2KHU82EiWJie0p
         jgU7tIZxMAmdqHYido7com77Wn7AmQQVNDpfJl2nAuavODjRk32d7BfaYNfQK5kj2Jt8
         rvqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=OvYom9X/S7wayVeQUgTcDXl5jN2F2BPuKd+7kG4C4mU=;
        fh=Z7U9iMdsC69cB1H0ASX4Oy4U3mNnZLPnMIDPEgDFekk=;
        b=W4dhrAjlWJq3DDNotElXexzj618asxJL8NDBw9MkIP09TuBwFj6Q/YMlOz/ePdhY61
         W0iiwofEfCSx9nEyw43GLslBPFDZPfMGvHxH/JO79HgL/SR+wPlHzYycvKUcnxcL4s5X
         5e6LxtuJyS9lhEoKqoZWR67EwNMPmuzK7Gy2X9UOACIPCbRWmclxvcTm5h2I5V4JGGWZ
         EPvf4zUaYRAjdXDMv2vaJP9h+QUPCm56s5j7V7ww5VhW0WmdhmUErmXEtIQ4JxrW1vgz
         oqjm0VjMbSGoK6DkiHDGlPHJeHbyh3HXWBRAQmVibZPGSvv7ewwaBwfxd8+pJyKk5VKj
         8BkA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=L8cZm9Lx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.9 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-9.mta1.migadu.com (out-9.mta1.migadu.com. [95.215.58.9])
        by gmr-mx.google.com with ESMTPS id n22-20020a0565120ad600b004f9c8e62211si1766809lfu.11.2023.07.05.05.44.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 Jul 2023 05:44:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.9 as permitted sender) client-ip=95.215.58.9;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Mark Rutland <mark.rutland@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>,
	Feng Tang <feng.tang@intel.com>,
	stable@vger.kernel.org,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Vlastimil Babka <vbabka@suse.cz>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH] kasan, slub: fix HW_TAGS zeroing with slub_debug
Date: Wed,  5 Jul 2023 14:44:02 +0200
Message-Id: <678ac92ab790dba9198f9ca14f405651b97c8502.1688561016.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=L8cZm9Lx;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 95.215.58.9 as
 permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

Commit 946fa0dbf2d8 ("mm/slub: extend redzone check to extra allocated
kmalloc space than requested") added precise kmalloc redzone poisoning
to the slub_debug functionality.

However, this commit didn't account for HW_TAGS KASAN fully initializing
the object via its built-in memory initialization feature. Even though
HW_TAGS KASAN memory initialization contains special memory initialization
handling for when slub_debug is enabled, it does not account for in-object
slub_debug redzones. As a result, HW_TAGS KASAN can overwrite these
redzones and cause false-positive slub_debug reports.

To fix the issue, avoid HW_TAGS KASAN memory initialization when slub_debug
is enabled altogether. Implement this by moving the __slub_debug_enabled
check to slab_post_alloc_hook. Common slab code seems like a more
appropriate place for a slub_debug check anyway.

Fixes: 946fa0dbf2d8 ("mm/slub: extend redzone check to extra allocated kmalloc space than requested")
Cc: <stable@vger.kernel.org>
Reported-by: Mark Rutland <mark.rutland@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/kasan.h | 12 ------------
 mm/slab.h        | 16 ++++++++++++++--
 2 files changed, 14 insertions(+), 14 deletions(-)

diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index b799f11e45dc..2e973b36fe07 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -466,18 +466,6 @@ static inline void kasan_unpoison(const void *addr, size_t size, bool init)
 
 	if (WARN_ON((unsigned long)addr & KASAN_GRANULE_MASK))
 		return;
-	/*
-	 * Explicitly initialize the memory with the precise object size to
-	 * avoid overwriting the slab redzone. This disables initialization in
-	 * the arch code and may thus lead to performance penalty. This penalty
-	 * does not affect production builds, as slab redzones are not enabled
-	 * there.
-	 */
-	if (__slub_debug_enabled() &&
-	    init && ((unsigned long)size & KASAN_GRANULE_MASK)) {
-		init = false;
-		memzero_explicit((void *)addr, size);
-	}
 	size = round_up(size, KASAN_GRANULE_SIZE);
 
 	hw_set_mem_tag_range((void *)addr, size, tag, init);
diff --git a/mm/slab.h b/mm/slab.h
index 6a5633b25eb5..9c0e09d0f81f 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -723,6 +723,7 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
 					unsigned int orig_size)
 {
 	unsigned int zero_size = s->object_size;
+	bool kasan_init = init;
 	size_t i;
 
 	flags &= gfp_allowed_mask;
@@ -739,6 +740,17 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
 	    (s->flags & SLAB_KMALLOC))
 		zero_size = orig_size;
 
+	/*
+	 * When slub_debug is enabled, avoid memory initialization integrated
+	 * into KASAN and instead zero out the memory via the memset below with
+	 * the proper size. Otherwise, KASAN might overwrite SLUB redzones and
+	 * cause false-positive reports. This does not lead to a performance
+	 * penalty on production builds, as slub_debug is not intended to be
+	 * enabled there.
+	 */
+	if (__slub_debug_enabled())
+		kasan_init = false;
+
 	/*
 	 * As memory initialization might be integrated into KASAN,
 	 * kasan_slab_alloc and initialization memset must be
@@ -747,8 +759,8 @@ static inline void slab_post_alloc_hook(struct kmem_cache *s,
 	 * As p[i] might get tagged, memset and kmemleak hook come after KASAN.
 	 */
 	for (i = 0; i < size; i++) {
-		p[i] = kasan_slab_alloc(s, p[i], flags, init);
-		if (p[i] && init && !kasan_has_integrated_init())
+		p[i] = kasan_slab_alloc(s, p[i], flags, kasan_init);
+		if (p[i] && init && (!kasan_init || !kasan_has_integrated_init()))
 			memset(p[i], 0, zero_size);
 		kmemleak_alloc_recursive(p[i], s->object_size, 1,
 					 s->flags, flags);
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/678ac92ab790dba9198f9ca14f405651b97c8502.1688561016.git.andreyknvl%40google.com.
