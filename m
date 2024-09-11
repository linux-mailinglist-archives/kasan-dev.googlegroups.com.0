Return-Path: <kasan-dev+bncBDN7L7O25EIBBIXZQS3QMGQEFRL32CY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 20D79974A89
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Sep 2024 08:45:59 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-e179dcb42b7sf2337135276.1
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Sep 2024 23:45:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726037155; cv=pass;
        d=google.com; s=arc-20240605;
        b=AnFosV6WdsHEOeOL2mpbU74VWfZKNd3x/31Y/C+W0Gc50IVVALWUj94puf2dK7tPOJ
         5Zgz9diD+rmfU9I5JgaEkrStuWuCw/KEg2PF3PoCfsI+C/uVpi82neVvJdu/6qVmmYHV
         Usnerpi/UM2BnySva1U7qTBxW1w0N+XyHR/AfBS9nhiHEOimKVi01xa0vLWGsx/lPyoX
         WUVPtYnncdBNay1u84xCk2nHuZ7pOUpg0X79y2v/2zbV64THGtB2ChPlMvMjnVYGHVo2
         oCO+h/p7WDqnmeYKmkdf+XMXAil2cJqZzWqGYpbMj0UlqiwdnVCPmKgrx3z0+SqK3aW5
         RlHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=SMM/mQ4Tg4fd60/WTYg9yzKaKrvsNRLDzFwyScAKlXU=;
        fh=qcUlww5v+jBwndS922rG+2xZXej3/eslO8Bq/jTgP2U=;
        b=KNT1XU135S7B4iNCshy7r/k+ueAq+YG6fFHU0PIVHRlVt+54xmshbg/5x/pZKsYmke
         Nm7FBY0np2Lkkom6Mm9YaQcx1BJoGvQcL0/TbcsnvtZ4Z2NVlxAhPRw1giTbfHyR8yGa
         DK+o7fB0hBoQBuBPn7OhyOnnkPCXEm6Ieio9FbuyXxkB58GBYln5S39RIxOTapSeGXOl
         Su9/qE902Xf4fVk8Vi262GpaUpVn5/a6IuKh2g/NZ3a5CgER57CShkd4iwopS/yH2VDD
         coGbscVplpJpDMWm0XsBsLOUvpnAFnEnjfPT3V1EMYVB4lSDKKV0p1bqspAcYYI/z3Ty
         fhcg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=fSlUj7mq;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.12 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726037155; x=1726641955; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=SMM/mQ4Tg4fd60/WTYg9yzKaKrvsNRLDzFwyScAKlXU=;
        b=wAPmbc1f9p39hH8NNJiM6n7G/72qo8gICeQh55wI/WraaPyGdlbZzqaD4DqfmVavhV
         1kd2eleC2whfDx4xl/V+bbc0AkWer0J8jpYLFacLHLlXCl9HjFzjp3xRgHZSaP+3n0PR
         /qgtIuWmRbv3Wi3IuHBD50Od4UOca71ZFrfwFWteq2owFS7wSwbAgLF3seRcigCvE6MK
         fYAHpmRcZE7FvlpB9Yzn9FC7Af3qnFUCBYvGaSAvOT8VAO2nq+KP+R/3O5uxjB+OsFQL
         T1WgMisCeMjXMUESNbXtg8w3dmEumTOxh7QdU4om1sg2g4bPJ/GwuDHfjN+GY8pg+kaE
         7GJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726037155; x=1726641955;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SMM/mQ4Tg4fd60/WTYg9yzKaKrvsNRLDzFwyScAKlXU=;
        b=T7vWrBG7QZ7PW7HTTl/GQ85c4yBC3BIyIqKoBfrV64/9mIMxWW41VYriicl3dclQ6f
         aigDkd1psCCWV1X5XbNSRxeknkbbSQamFagPtyuBOatFg3XlblYi+59NE0BzVmSnXVEq
         w7z0an4Lz6ZkJPB9ie74XCiMVso+bW5OUBRCPcoDuDY2sNyC+NRnm91FNGuq3iwFvRkk
         Bze6QIUnoNUYod0GII1m1qfMoUGJZ00p29kfWazLVrG8WQq9c6KS570HFMlLgzqROmOE
         oLBEcLbmKw0GKQekRL4IxQ5BSfyWuMkbcx36g4NfvxW8X6RoHXqU9yvZw9qEHH1DXwqM
         wleg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXrfsnUIGhAEeZdW/RDarXWEhu+NCnOjwETad5zONpqtIjIPzuHbwYzo12gFkAfbWbHF2u0Ow==@lfdr.de
X-Gm-Message-State: AOJu0YwJ3ct7hIDHx4IzuT83A6KGdVa6yap08heqeUkr2CDQWo2heJo4
	y2wqIOX7UVuP4gxXTnT+FGAotnKV5kWHOrcfFzxzp/JscXsZUU8W
X-Google-Smtp-Source: AGHT+IG6xX4hdR1I5Gm+/0ADUPqLUqjoRBtUuldAJRAaVKW/QHD50+bhztBEQEzmNUlgPmjbLtXu/Q==
X-Received: by 2002:a05:6902:2e0d:b0:e13:c5da:1e79 with SMTP id 3f1490d57ef6-e1d349dc683mr8030998276.7.1726037155166;
        Tue, 10 Sep 2024 23:45:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1026:b0:e14:d13e:ee39 with SMTP id
 3f1490d57ef6-e1d7a3ea067ls41282276.2.-pod-prod-02-us; Tue, 10 Sep 2024
 23:45:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWbh6OlOavLPF/Siz3YIIFujgswyhkdg1F59oqCfuQNQwIBtOgFZlKseTEYmK+U1w3HUoh+z3cQeCg=@googlegroups.com
X-Received: by 2002:a05:6902:2845:b0:e16:4909:c8f8 with SMTP id 3f1490d57ef6-e1d8c53b0dbmr1713064276.49.1726037154391;
        Tue, 10 Sep 2024 23:45:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726037154; cv=none;
        d=google.com; s=arc-20240605;
        b=LAjyxPwEIt7R9xiwy0kxdyJDX5tKwufr9RM+LW9PGp/AsKIj64YoqkboskKTnygDR9
         H57MsZjso3CMvWN5IaXAcvMrkT5Km3GXgcBGoWSd0YgMxVnP/DAYSDh8ZPozG/TXDfB3
         CZ9j7KRV9YB7u6v2qRfXqAa1jvOo3vKbLQcsKIsfq3rkWZXc/7VYjqcKRyHK1KA7IJLx
         lnccovztA/Iu8uaTvI0ymRebvuKrUJ9YIQe1NsvCvYSokdG6mB9PLJyXkgqV30DXWElN
         o4XhLMudM5fPnHGw6An5dUNXZ8RcNUwUADbN2HEol/tc5vI4leaad2izNPLl8pAMHQGG
         TLmg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=wZNuj6wBkLP0SnWxYyCLS6aj5zno8YqWIFsVBbPmmqg=;
        fh=Xs830Dl/dg7cBD7Cjxi4zgG6B28PocXmmZIfDH/IGEM=;
        b=dJP2zaNwgQYvVWO0Q3L8FNMlaqhIzCFcfaTmKeBjnUDlj6RIwCr0kf4UEwP0YIse0l
         A6/agv7OScbW0lUYZX+z8YGy0XBfWL3oXr4vBkT/JJ5hji7h3RKjP/oUoCA+TgKh6PKU
         MHHV4bo+oNXVMI6trvWECGlmpE1w0d9lk8a6dUvNm5d/UGDJ6RAn79jirbWDJ+2TlouY
         u61Y5MSMoLKezNGCJEgD3UFpCc5pUuOBhZjsbXgZG3rmyNG5zRKPdxJk2T7jzXCwNty0
         8qVo3u/PPQJuKoF8F2kZRBENNUtQXms1O/mAGInqrTDlgi0y6h7SZn2QHAN2c69Ta4AV
         K22A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=fSlUj7mq;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.12 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.12])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e1d7bbb4424si168943276.3.2024.09.10.23.45.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 10 Sep 2024 23:45:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 198.175.65.12 as permitted sender) client-ip=198.175.65.12;
X-CSE-ConnectionGUID: 1djenPZgQ+uZD+OuB80psg==
X-CSE-MsgGUID: D8kum2RoSLyG4a79RVFksA==
X-IronPort-AV: E=McAfee;i="6700,10204,11191"; a="36172983"
X-IronPort-AV: E=Sophos;i="6.10,219,1719903600"; 
   d="scan'208";a="36172983"
Received: from orviesa007.jf.intel.com ([10.64.159.147])
  by orvoesa104.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 10 Sep 2024 23:45:52 -0700
X-CSE-ConnectionGUID: wcILiiZ3QmaqfhSIVIcfHw==
X-CSE-MsgGUID: fx8JhJANRZCRTz/LvKdSHg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,219,1719903600"; 
   d="scan'208";a="67771485"
Received: from feng-clx.sh.intel.com ([10.239.159.50])
  by orviesa007.jf.intel.com with ESMTP; 10 Sep 2024 23:45:41 -0700
From: Feng Tang <feng.tang@intel.com>
To: Vlastimil Babka <vbabka@suse.cz>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Lameter <cl@linux.com>,
	Pekka Enberg <penberg@kernel.org>,
	David Rientjes <rientjes@google.com>,
	Joonsoo Kim <iamjoonsoo.kim@lge.com>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Marco Elver <elver@google.com>,
	Shuah Khan <skhan@linuxfoundation.org>,
	David Gow <davidgow@google.com>,
	Danilo Krummrich <dakr@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>
Cc: linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH v2 1/5] mm/kasan: Don't store metadata inside kmalloc object when slub_debug_orig_size is on
Date: Wed, 11 Sep 2024 14:45:31 +0800
Message-Id: <20240911064535.557650-2-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20240911064535.557650-1-feng.tang@intel.com>
References: <20240911064535.557650-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=fSlUj7mq;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 198.175.65.12 as
 permitted sender) smtp.mailfrom=feng.tang@intel.com;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=intel.com
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

For a kmalloc object, when both kasan and slub redzone sanity check
are enabled, they could both manipulate its data space like storing
kasan free meta data and setting up kmalloc redzone, and may affect
accuracy of that object's 'orig_size'.

As an accurate 'orig_size' will be needed by some function like
krealloc() soon, save kasan's free meta data in slub's metadata area
instead of inside object when 'orig_size' is enabled.

This will make it easier to maintain/understand the code. Size wise,
when these two options are both enabled, the slub meta data space is
already huge, and this just slightly increase the overall size.

Signed-off-by: Feng Tang <feng.tang@intel.com>
Acked-by: Andrey Konovalov <andreyknvl@gmail.com>
---
 mm/kasan/generic.c |  7 +++++--
 mm/slab.h          |  6 ++++++
 mm/slub.c          | 17 -----------------
 3 files changed, 11 insertions(+), 19 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 6310a180278b..8b9e348113b1 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -392,9 +392,12 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 	 * 1. Object is SLAB_TYPESAFE_BY_RCU, which means that it can
 	 *    be touched after it was freed, or
 	 * 2. Object has a constructor, which means it's expected to
-	 *    retain its content until the next allocation.
+	 *    retain its content until the next allocation, or
+	 * 3. It is from a kmalloc cache which enables the debug option
+	 *    to store original size.
 	 */
-	if ((cache->flags & SLAB_TYPESAFE_BY_RCU) || cache->ctor) {
+	if ((cache->flags & SLAB_TYPESAFE_BY_RCU) || cache->ctor ||
+	     slub_debug_orig_size(cache)) {
 		cache->kasan_info.free_meta_offset = *size;
 		*size += sizeof(struct kasan_free_meta);
 		goto free_meta_added;
diff --git a/mm/slab.h b/mm/slab.h
index f22fb760b286..f72a8849b988 100644
--- a/mm/slab.h
+++ b/mm/slab.h
@@ -689,6 +689,12 @@ void __kmem_obj_info(struct kmem_obj_info *kpp, void *object, struct slab *slab)
 void __check_heap_object(const void *ptr, unsigned long n,
 			 const struct slab *slab, bool to_user);
 
+static inline bool slub_debug_orig_size(struct kmem_cache *s)
+{
+	return (kmem_cache_debug_flags(s, SLAB_STORE_USER) &&
+			(s->flags & SLAB_KMALLOC));
+}
+
 #ifdef CONFIG_SLUB_DEBUG
 void skip_orig_size_check(struct kmem_cache *s, const void *object);
 #endif
diff --git a/mm/slub.c b/mm/slub.c
index 21f71cb6cc06..87c95f170f13 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -230,12 +230,6 @@ static inline bool kmem_cache_debug(struct kmem_cache *s)
 	return kmem_cache_debug_flags(s, SLAB_DEBUG_FLAGS);
 }
 
-static inline bool slub_debug_orig_size(struct kmem_cache *s)
-{
-	return (kmem_cache_debug_flags(s, SLAB_STORE_USER) &&
-			(s->flags & SLAB_KMALLOC));
-}
-
 void *fixup_red_left(struct kmem_cache *s, void *p)
 {
 	if (kmem_cache_debug_flags(s, SLAB_RED_ZONE))
@@ -760,21 +754,10 @@ static inline void set_orig_size(struct kmem_cache *s,
 				void *object, unsigned int orig_size)
 {
 	void *p = kasan_reset_tag(object);
-	unsigned int kasan_meta_size;
 
 	if (!slub_debug_orig_size(s))
 		return;
 
-	/*
-	 * KASAN can save its free meta data inside of the object at offset 0.
-	 * If this meta data size is larger than 'orig_size', it will overlap
-	 * the data redzone in [orig_size+1, object_size]. Thus, we adjust
-	 * 'orig_size' to be as at least as big as KASAN's meta data.
-	 */
-	kasan_meta_size = kasan_metadata_size(s, true);
-	if (kasan_meta_size > orig_size)
-		orig_size = kasan_meta_size;
-
 	p += get_info_end(s);
 	p += sizeof(struct track) * 2;
 
-- 
2.34.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240911064535.557650-2-feng.tang%40intel.com.
