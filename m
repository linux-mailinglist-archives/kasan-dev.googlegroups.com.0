Return-Path: <kasan-dev+bncBAABB4WJ3GMAMGQEN3LKO4I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 6E3A35ADA93
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Sep 2022 23:06:59 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id j19-20020a05600c1c1300b003ab73e4c45dsf5540693wms.0
        for <lists+kasan-dev@lfdr.de>; Mon, 05 Sep 2022 14:06:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1662412019; cv=pass;
        d=google.com; s=arc-20160816;
        b=S/fSYOP89ERg18f8XWQXxk2ypqp5JCEFoOVCnC53EKvdNGwk2RldHd7RhjFv8Lsqo8
         mGgiqU5+nqenLqyu0hUhxaWO7+agq2TCewwbk80p3xuEgFi8MIl1q+74LM7hkicHGGIh
         1N4YlwJM3d4bilyW7QOp4K1IsSGx5DsConRMBWGsvisnHBjxUEYElqOVDpe5Q64LO/D5
         8QrHrgYCoWXmF42nwuZeVDKB58lxmbsvGt7+TDyBxhonNCPryVzK+iQJ67u3D3fwi1PO
         AjPze4wS9NXNBL2eWKR+hfu/qQx4DO9b/j8TdE3q1AFpq4CJH5DpDCaRDkd7JMZ1XtIU
         hpTg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=1KzDDK8XMMnQZUKCjuIUDuGPMJFw1HB59+Syl379xPw=;
        b=mUrQV9VBgC7X5cayXCzGtlhyPl9HuE8F+GW63dLRRiey+TrBW67RKKbndmCgDTMj5K
         /RKCt8JRihAJ8MsI8nMxrJRoK0sVYA0jTB2iQG/ykvSN1TjWZrtLXJb4maiw6H6WSfmX
         ty0Upb0UNV4tdMIxSo1npjxowkCIUiYkvtCsLsMUP1Og4AX/hPCYLBtwinzIkc1ZqvX0
         9pNUlssav9X1l0myGod1z1Lgs5SD+QIVn1oRo92HhMZIdtnf1keeNiEQu2OuJZRb1fqv
         Bv6uPCRu2eiYFt5QBbBFlWoXDvYqvU7SJsWAW3FTIhGlcvbOdxsbTV3JOYYK3C/nsVXs
         fGNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=c7RNoemt;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date;
        bh=1KzDDK8XMMnQZUKCjuIUDuGPMJFw1HB59+Syl379xPw=;
        b=MRTej+Ed42j2xS4YBsDS5hC4sp0FyvzN8gvbRdwyM7NLdSamRyt8xCvh8K/4CksGqR
         /k7gk9yUOj+dmZnnr8Z2HGFgLfZC66E7nQUUTjKCBalu28/EPB6yvXAf/Irak+Ly5JD9
         pgPbKev4XuarXzbNHJTBYE94clkfcs94ym1pr09bUK2KYD77RbsmCZsOg2ETtkm6aSzd
         FxayUQylmvjNFAaQj9pLdj3NYPPGm4GObVr/nlVKW8z77/NtUAfEe+1UCKotKql4gEsc
         odHW2HuxWM0T1XFZFCskB+Ce50s4h/CmK3W6CpBUhusbpUywIE5S3EvWHub2M8PgYWaW
         +how==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date;
        bh=1KzDDK8XMMnQZUKCjuIUDuGPMJFw1HB59+Syl379xPw=;
        b=CMOhzqBV7UJxdZoauT147VZyEhLpfCoG2p3hSpplAi9kvIka9N5u128OzKOZO+im+f
         jhdQIR6mFreMwqyScJzaWNCgRv+KYGYh09tNx31FMSl/x0HdRZJ5IHKsoeTvKAsYtmDK
         ARVrkKH6MJwfbA1+okEigsqYpm3GBqmfWdgEXLm5zUUuXMozIlyT3Fq1xoc8RRm963Yk
         7A19ZGSC/V591dX4puiOWiztSNGItO7g/CU6dAnWHh4T7wWNaVVWuenc6rsEEAQcOxF6
         o+5axgPRgHB6VSPENjsbsBRGFUC8+U2/Ahrkd7eVN7/3HKbg00dy//zMUyw0Sff21o57
         KrxA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACgBeo1nm53KF4b/fFi24c7HIb5o1+JzeMR290+OpCBLCMwZ6dqxW6Gi
	iNz+UuT653QVjqxLJzbpWwg=
X-Google-Smtp-Source: AA6agR7HeTGpez939dsdFiZXBal4bQuuQUp4yMGWiBhxbbNpNzK7ykiz0061z8/FcMNXDIJYFt2mxQ==
X-Received: by 2002:a5d:5551:0:b0:228:d70a:102e with SMTP id g17-20020a5d5551000000b00228d70a102emr335392wrw.446.1662412019137;
        Mon, 05 Sep 2022 14:06:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:d22e:0:b0:225:26dd:8b59 with SMTP id k14-20020adfd22e000000b0022526dd8b59ls193844wrh.3.-pod-prod-gmail;
 Mon, 05 Sep 2022 14:06:58 -0700 (PDT)
X-Received: by 2002:adf:f54a:0:b0:228:951a:2949 with SMTP id j10-20020adff54a000000b00228951a2949mr3331170wrp.240.1662412018569;
        Mon, 05 Sep 2022 14:06:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1662412018; cv=none;
        d=google.com; s=arc-20160816;
        b=XN+a+RBqipfzwk193mlPjCP8f71MfEVtPQAATYWLlBnFS0TgG+Vc1ho0zeMQomp3pT
         RuiRkm3Gj7RTPmK6hl5HzP7B7Ak+xwXBCuw86RRp2CxVLcLPwWco/9DMlCi6kRvxiURd
         5kC7QaeAXlMdNLvZ3ggJcyINwltTOrHllqs7ScZReOABOCN6E1NLRNx093nGoXF3El4/
         NIojK35c2tRjxupESr3oqklaV9NxwVFkXtYiPZASALD5fFvcJQayyyXM3XfRIYV77fCW
         3klFrOxAPYTRKN4t5TPbe7sL+hBoknbIoheDSqpcNDUiikn8kwEltJ3W0xWkdC1frbKQ
         +Gfg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=1P0OL5eJBC/VWyzrUzzXy/PpMlaQ+HYTExB/Z4qpTio=;
        b=FEG2jhKAEhSZoBnn3ofUtgiRTl+0Yluqpb4WCs+aGeuOAjeGd92uL5qnKZCvCIUpZL
         6lWTEeAcb9NyRYH9M3R6kvww/ZuHEYz+IVy3WnypP2YXoNHC9poqosIOIRKujS1hWLcj
         T12eRz8RQDhQ0RCoG67w4wKqNQiD1PVaC9rIdyhWErL53Zm1AkFbvImB40CnFh6BMeDl
         mKxe3p/AaYdMrgKA4ZsQozbqeX+6hh6Puqm98suWfQR38349IQq+G0b4zY9qbWfJMsdB
         3xjwyok6wUYyvM4sAi1+llxO2Yyd66DwniRnWIwYcYdTuvLA6r/CdMdKy0QhAx1S+8z9
         7ldQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=c7RNoemt;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id r3-20020a1c2b03000000b003a972d2d4a4si528861wmr.1.2022.09.05.14.06.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 05 Sep 2022 14:06:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) client-ip=2001:41d0:2:267::;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Florian Mayer <fmayer@google.com>,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 07/34] kasan: introduce kasan_get_alloc_track
Date: Mon,  5 Sep 2022 23:05:22 +0200
Message-Id: <0c365a35f4a833fff46f9d42c3212b32f7166556.1662411799.git.andreyknvl@google.com>
In-Reply-To: <cover.1662411799.git.andreyknvl@google.com>
References: <cover.1662411799.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=c7RNoemt;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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

Add a kasan_get_alloc_track() helper that fetches alloc_track for a slab
object and use this helper in the common reporting code.

For now, the implementations of this helper are the same for the Generic
and tag-based modes, but they will diverge later in the series.

This change hides references to alloc_meta from the common reporting code.
This is desired as only the Generic mode will be using per-object metadata
after this series.

Reviewed-by: Marco Elver <elver@google.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 mm/kasan/generic.c | 14 +++++++++++++-
 mm/kasan/kasan.h   |  4 +++-
 mm/kasan/report.c  |  8 ++++----
 mm/kasan/tags.c    | 14 +++++++++++++-
 4 files changed, 33 insertions(+), 7 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 98c451a3b01f..f212b9ae57b5 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -381,8 +381,20 @@ void kasan_save_free_info(struct kmem_cache *cache,
 	*(u8 *)kasan_mem_to_shadow(object) = KASAN_SLAB_FREETRACK;
 }
 
+struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
+						void *object)
+{
+	struct kasan_alloc_meta *alloc_meta;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (!alloc_meta)
+		return NULL;
+
+	return &alloc_meta->alloc_track;
+}
+
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-				void *object, u8 tag)
+						void *object, u8 tag)
 {
 	if (*(u8 *)kasan_mem_to_shadow(object) != KASAN_SLAB_FREETRACK)
 		return NULL;
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 30ff341b6d35..b65a51349c51 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -283,8 +283,10 @@ depot_stack_handle_t kasan_save_stack(gfp_t flags, bool can_alloc);
 void kasan_set_track(struct kasan_track *track, gfp_t flags);
 void kasan_save_alloc_info(struct kmem_cache *cache, void *object, gfp_t flags);
 void kasan_save_free_info(struct kmem_cache *cache, void *object, u8 tag);
+struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
+						void *object);
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-				void *object, u8 tag);
+						void *object, u8 tag);
 
 #if defined(CONFIG_KASAN_GENERIC) && \
 	(defined(CONFIG_SLAB) || defined(CONFIG_SLUB))
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index cd9f5c7fc6db..5d225d7d9c4c 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -255,12 +255,12 @@ static void describe_object_addr(struct kmem_cache *cache, void *object,
 static void describe_object_stacks(struct kmem_cache *cache, void *object,
 					const void *addr, u8 tag)
 {
-	struct kasan_alloc_meta *alloc_meta;
+	struct kasan_track *alloc_track;
 	struct kasan_track *free_track;
 
-	alloc_meta = kasan_get_alloc_meta(cache, object);
-	if (alloc_meta) {
-		print_track(&alloc_meta->alloc_track, "Allocated");
+	alloc_track = kasan_get_alloc_track(cache, object);
+	if (alloc_track) {
+		print_track(alloc_track, "Allocated");
 		pr_err("\n");
 	}
 
diff --git a/mm/kasan/tags.c b/mm/kasan/tags.c
index e0e5de8ce834..7b1fc8e7c99c 100644
--- a/mm/kasan/tags.c
+++ b/mm/kasan/tags.c
@@ -38,8 +38,20 @@ void kasan_save_free_info(struct kmem_cache *cache,
 	kasan_set_track(&alloc_meta->free_track, GFP_NOWAIT);
 }
 
+struct kasan_track *kasan_get_alloc_track(struct kmem_cache *cache,
+						void *object)
+{
+	struct kasan_alloc_meta *alloc_meta;
+
+	alloc_meta = kasan_get_alloc_meta(cache, object);
+	if (!alloc_meta)
+		return NULL;
+
+	return &alloc_meta->alloc_track;
+}
+
 struct kasan_track *kasan_get_free_track(struct kmem_cache *cache,
-				void *object, u8 tag)
+						void *object, u8 tag)
 {
 	struct kasan_alloc_meta *alloc_meta;
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0c365a35f4a833fff46f9d42c3212b32f7166556.1662411799.git.andreyknvl%40google.com.
