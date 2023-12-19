Return-Path: <kasan-dev+bncBAABBPNTRCWAMGQE7WDDBTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id C3253819393
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 23:31:26 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-2cc8060792bsf9349451fa.0
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Dec 2023 14:31:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1703025086; cv=pass;
        d=google.com; s=arc-20160816;
        b=PRrs5NgS4iWYiEefmB/FKeLzdGwcOqXUVhZJkqRYxWT9Una8Hl1KG5ytaOCLo9c8wh
         VppZMLLoSZoRDePy2IoGmcW2OFKVIQjO0oiXkS0dTmfDABN+epiXsAxT7DM1yf40vv8F
         qS0x8bLaNgpWMhNvp1aVOtyeo+bJHV9viEq6dJP9eLx7wi3TzM/JuRai48JnAOLNA0dY
         epu4tUL3quIvdTWH1rtD40HXn78pvK498a9wnHmNGFrMpl9V8mQAzZLRFu4r/PclR+XG
         RSicSJyjIVQJ3i0g5OsvP9r5ArLagOvnoey/JIBbNRqf4S30oscoZ/DBXFdycsMHQvtB
         4KHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=6rzdjWmWMZpTLe2+Hiac2GqpBr2LfiSG8XmyG5I5XuM=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=osgrATX0pon9UlSZDPrDe74VBnYOObJG6aaMi+L60SBZGQzWZYdAymXJfTFUtcTwVi
         JJ6MBINrYau0pGnbfnRjVCVRCaQynvtbOCg7Yc9R7Bfh3DaTx7m8aSZ8zkSOXPlM0Iqj
         kazulr98nvZ70XTye3mk5oCTAYROjg41LupQAwjk+7GsntDVIMeGibMlYLi3xjTXSTiu
         Hg503jJ5E7mgDo8acphEMpHKWllLz2RXvv07FlMKczJpGOw2a7rqBrU1e1Gci4+2CWpA
         yUoYifdpUVjY16ILXuEJlCBx3+62WEQAWrzQefynvte/m2CiFMIxUhUxu+NV6akTKzOk
         xSfg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=r2ZaOIS6;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::af as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1703025086; x=1703629886; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=6rzdjWmWMZpTLe2+Hiac2GqpBr2LfiSG8XmyG5I5XuM=;
        b=o6JSF/cvRJY7gbNRLJtwpq5tef2Ml/kUGQRolmOH8vnvz6SFo9yEmboLwlgfmmLFrZ
         zv+heN3ND7DtQp9nCJy9cBtYnl1lCzrTc8t8jL6ISWvWAP+aMYS/750PSU6Fu9Jo19AU
         a+y7hSBNwLtrNU1rq/Rq7L4KQxr+S9BJC3W6ivfA9lOLgjD44NJfp3jUcrlA/5U8dE/Q
         VXvzrjOMetvJN+tKl4bTcvf8nULf0HP4VVdCY5aOPxTc7Fi38jpDwgdU424fHoEDUFHu
         3djuXkKMbOCHUZbhiOCyfzxBDHvNYTGVAIQBzPDDCir/b7GDSCGWWVc0shrQO7RI7Mvt
         7qTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1703025086; x=1703629886;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6rzdjWmWMZpTLe2+Hiac2GqpBr2LfiSG8XmyG5I5XuM=;
        b=tOoXSzhXJg7qoz6MIzHqFcfoq6aMZLvc7y+PsNi1CnOOhChxUiaordwogOrLPyrQNm
         gHkJFfrwsYlZzEaRFZA17PcaymoyZ/J5aa4VkY4NI0nV66fvFeOL/VhtKDabTUZ0+zkS
         +bwzlb4ZxSA+4z4JkGL5SDP8P3GIbJPhyiA+aU9V/YH54N23EcwIXYsTTLucb+XV1+tN
         W2JOxKDaFJpOokSpAUtnV8pwKhS358/3t/S2b7gS8Q2zyrkjepBBrBCZ1oO8cQR618LO
         +7fLgVA6OJcQY71XNIcjCwej+i644fTOUzofCU+6X60LSS6MLxH+W6Vt3ppurmKiSL6T
         koMA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YyOG/Gn/s2BsU+3tLD1rU/KmA07fXr59F03RnDC9nOWh/7zxhBd
	0/sNruvWHZbv9X+UZS3Q86k=
X-Google-Smtp-Source: AGHT+IGYryxjEr3QZb59gALEveofZkMIcRTGQBOMtqnMYwBKRZ3Xzb9rVqeRFD1by33VDVgJ/r83Lg==
X-Received: by 2002:a05:6512:3e21:b0:50b:e005:88ab with SMTP id i33-20020a0565123e2100b0050be00588abmr10627834lfv.64.1703025085581;
        Tue, 19 Dec 2023 14:31:25 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:cfd9:0:b0:553:2a33:7d33 with SMTP id r25-20020aa7cfd9000000b005532a337d33ls1171753edy.0.-pod-prod-01-eu;
 Tue, 19 Dec 2023 14:31:24 -0800 (PST)
X-Received: by 2002:a05:6402:2805:b0:54c:4837:75a1 with SMTP id h5-20020a056402280500b0054c483775a1mr11628528ede.77.1703025083856;
        Tue, 19 Dec 2023 14:31:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1703025083; cv=none;
        d=google.com; s=arc-20160816;
        b=C0LB1UAKOlD3palbnrWxC1HC6YchdqN+24FKj80umaRA6x0XxnA/NOZduoAlbnaylx
         G+Ec16BToyujF0ERhzKm9I/+HsJPFoTOL4TQLC2Val9BGQBB6OUmhSPVqGij3gozo4In
         nk7Q6oVp1vngZYteSX0sL8Z2n8bxRJwash93ZYvfnAhPmw55eGSvfmUOIh5/skAdIhtz
         dWL3t7d938EGnk6fuJTmPwiXWAQCowzUoTNVwYRQl+yd1vEHzfwYe6k5ETcWtoy3rNTV
         LYiYfaF4IJDwbRhtKpSt330TOB0R54w804q/Y5gWijNJSx/EiJBCeu1R4AeFvUcmY6JN
         JOTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=g+O4MJvijsH/fxNfhEtO0ZT1bhv1NQvjMHnoD8zQplM=;
        fh=AIzsiqkKUtrB7QnM+XRgAblgvDINIC5pDvD0mg8EzrU=;
        b=eoRf7zxgVa6C/rZTeHDvY6U9htVLcoa5d5wMB00NJwl3q/Cr1yOlLJsUmQ8DbWLJwO
         WBl/h+z72qekTV0NNL7rT23yWs+dwZCdgS7amNHqAy3b2+TbRYfh7UjAG141131dgKRt
         3eI15emykY2tEj+KfSZQvgSgqAJVDnXljwmyPAAgLk2OFStwt/L2FQRUXH+y4w4LvD/P
         lkapIueMuS3KwzwrokrWqhT3dE1Y2lDYSW8eDQUVWZ/MQ7TkO7UoEkoEviIHyWwrYOWU
         pyApok7AU4qhVPdsB9DfS2Q3ta3T2s+zwtU+IIYphcKVXgLscYEa2PRHD0xVEXMjpqBb
         z6aQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=r2ZaOIS6;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::af as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-175.mta0.migadu.com (out-175.mta0.migadu.com. [2001:41d0:1004:224b::af])
        by gmr-mx.google.com with ESMTPS id y1-20020a50e601000000b00552180ac40fsi444609edm.0.2023.12.19.14.31.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 19 Dec 2023 14:31:23 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:1004:224b::af as permitted sender) client-ip=2001:41d0:1004:224b::af;
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
Subject: [PATCH mm 12/21] kasan: save alloc stack traces for mempool
Date: Tue, 19 Dec 2023 23:28:56 +0100
Message-Id: <05ad235da8347cfe14d496d01b2aaf074b4f607c.1703024586.git.andreyknvl@google.com>
In-Reply-To: <cover.1703024586.git.andreyknvl@google.com>
References: <cover.1703024586.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=r2ZaOIS6;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:1004:224b::af as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
index 962805bf5f62..b8e7416f83af 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -277,6 +277,20 @@ void __kasan_kfree_large(void *ptr, unsigned long ip)
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
@@ -299,15 +313,8 @@ void * __must_check __kasan_slab_alloc(struct kmem_cache *cache,
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
@@ -482,7 +489,30 @@ bool __kasan_mempool_poison_object(void *ptr, unsigned long ip)
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/05ad235da8347cfe14d496d01b2aaf074b4f607c.1703024586.git.andreyknvl%40google.com.
