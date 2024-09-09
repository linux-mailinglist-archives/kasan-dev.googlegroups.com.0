Return-Path: <kasan-dev+bncBDN7L7O25EIBBIE77G3AMGQEG5JJZ7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 07C9E970B32
	for <lists+kasan-dev@lfdr.de>; Mon,  9 Sep 2024 03:30:10 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-457d84fd0d7sf119569051cf.0
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Sep 2024 18:30:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725845408; cv=pass;
        d=google.com; s=arc-20240605;
        b=keswvHzC/mAHR+QHTN6j2LxYq1VeEYXt/+FRGQF9uWo8VrYC1f2H0cGhEBbQpnsh+4
         /ZKixbcIHDwuvToSnj2yj1IxjzurCiN5aTTTzbn/ld461KES7iJN4tHPDiOpcH444O4X
         BSH7FHE7KBMeYUkMuzmgumEmaH8wgLNFF15gsWcoFO7JYftFNs5R4UVzflI4aA2ZUF9y
         a7qQHpkI3DPZdGZDJAA3NbWnyCdJkH1k6vDD5S8DXKi3W2ugCe4iznzksLNWobZZxg/2
         1X1Fk3+RVxir+BqWwLtX+a9iB43dBLan4aP74PtHOA/su6S20sObqMLHMrYavIY5DMAt
         MyKg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=xIMWjuDGduwZRE/SBKVGDx20t4ZwCp8Lkkug6qZ4fWo=;
        fh=6mtP+7/ceKedb869KaqC4bdUniqCJzQlDzAHXT1p454=;
        b=JkQyspqqazlCkaQh5ERuPYybqcCptlSJSsqYr57M0s1msNF9Aqgm5/jxZLncZkIWsb
         H85uAVX/lrdWgTo43M9CHT8BeISGPl7PbCwRYSHeEkmR4UQqYBOMsN7scf7E8LeaD38L
         PYnIIy2QThGHE7hk2iojcwE00WOPcvNLsJ4arPXZd8HbtxAv3IybgevO4OI0AhS9ir+O
         HU9x1AqOQiEv2vdf+Ui45aCEHG1o2vA/CK9wfKv6r8/uC7J3pwRm4vTynv2uKI3BtFyc
         UnFpY+Ack1tzWApy/bGAy/DeY/sAyhFluJn2Fud8UZKUeKTiH+yolqDURnotHpj7GVTX
         DIUw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=T2sx01ob;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725845408; x=1726450208; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xIMWjuDGduwZRE/SBKVGDx20t4ZwCp8Lkkug6qZ4fWo=;
        b=mJ7rlAZqAvrsmd2GtM4hqCwnUd3sqtbh/zJlgCwsBCoFW80O+9g2D8vnvLI25iUIP2
         X6QxlnPXuJ4RzbOoraUCZs7GJMp7n6H/y+QYt+3CWXUweoY9G2jQs3ZSXaXTtLXXACXx
         uCzaPy3Va4spQSat9Y8jdw0K0/5y/RgtIFee1Z6ngPB46kMjArUl7RGUkwCilHVkSNvd
         yvZfiP7RUurgUHsUqaWF5TWcmC+6LaZzKA5yitPnmH5uWz8+mCqqmoN81PxR09+dkoFY
         SGn14EkZPvEveuz34URD3UJBcBtBYqq24PzZQ9M9WVd6UnuzZGLx8dxzAxlfS5BUtUEE
         6nnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725845408; x=1726450208;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=xIMWjuDGduwZRE/SBKVGDx20t4ZwCp8Lkkug6qZ4fWo=;
        b=LQqSTA1rVocibenQlAlntaUR+DIzL8wFTrLvW1HMXvw5t7MVlcCojEh9zM/S/JNggE
         QQEhappSgj4ZjqHwTHYQXM1pSt2pd079Lix9UhhlQ6nGCEJPhneIIoX7apxmkfpu9cHT
         mnqJwWmrexIo7/7+eyQi7ggWKU0yVAfUflYn3NYrJJbaVYG+Xe+31aayQEHG9SGjo5XD
         z3R6hzhmRU6rqzfMFfgS0zgKKyW+t30bsp47te/qGQZP/B7Gvcd8WqDAkyzYmzQ1siFI
         V1YrZuSdasT0Xf2AqNMOGESY/f59D8+7HW4P9ECLuStAIpwuLIMi+tOhMH406zsdHLe5
         XZ0g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVJm+VxV8bfIc2PELnTsF8apZ+032Y/psYPE4oJMLwu9NGWNoodvY5nXjW9yZPJv51uTYlydA==@lfdr.de
X-Gm-Message-State: AOJu0YwGlz80B//6AtFaYeQINfOXxbuDEsbHkd9ikvmYJ+rIIFryBEeK
	xhumpMBlUFP1pI2wRZ8T29wdNczGqq5SrMiaUicUkjeApGBSc8yZ
X-Google-Smtp-Source: AGHT+IFdAu8jkdiR5TskhKpLapavFsDb1QHR9tI89qINlGtj00TjNPzrPDbhy726nKliNToh/n4WGg==
X-Received: by 2002:a05:622a:4e96:b0:458:27cb:a5e4 with SMTP id d75a77b69052e-45827cba81fmr79699611cf.1.1725845408511;
        Sun, 08 Sep 2024 18:30:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5d49:0:b0:444:f3d0:bcbf with SMTP id d75a77b69052e-458355d7914ls1704871cf.0.-pod-prod-00-us;
 Sun, 08 Sep 2024 18:30:08 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU3vrwLJrqYhNJwmke7JmNEN3L9KPtVf295efM1DdoKC6niXK4TEixlfdouAeNlVxNYiSlghPyPaKA=@googlegroups.com
X-Received: by 2002:a05:620a:4687:b0:79c:ad5:cd7d with SMTP id af79cd13be357-7a996e1930amr1634791185a.23.1725845408012;
        Sun, 08 Sep 2024 18:30:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725845407; cv=none;
        d=google.com; s=arc-20240605;
        b=gKw3N2M2bEq+4Nuwnms1xLW5vqXakvCo5DrvArlArHNIIs5ZcKHACQMlNEiGsWxmny
         P9/72MBDYgmICha1KrEVfcKUM9P5ArzFxuKNDTLf43+OnTgq6dWALbY+WD/p3G3vGU7W
         lb9vRSZyX+beHtwqSj80TKFZsHhlrPAsdBSe+8an9TSQM4JsvOQi3PBizgFxX4fkh9SY
         5ZUJNXKbfdZyjlAHhghuVXzr0QpOMJlfvQbweHri2gvuHMs7XMB1zCnTSL90cn3JMbf+
         SipSUeaRrjhRj6L3tdyKe2oOn5E5LJHZDujr0P23kejicxDB1ofr/jzK/YJp/DF/aZZt
         8cpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=praePlo9gXwYoSdDC3+quBDxNg2mp+3vLJVC4CIDpoM=;
        fh=DOrQZqwZ3gYiN8TxsTSOKms3YTEHds3R/56bZbzlpuk=;
        b=caQQsWCshxnV0dfJD1VODSuk+DaOl/Yh4HhtuzQ7N+7gkVod5nubbFGhhQHeN94Ya4
         OFo9c2UCQ9+MrH6YQGUzUuCLk78m5eLQdTFOqTO4kymrcjZhJXqaovdas/HldOkAdZf9
         /x8CYyJ9B6JTKVfwMkztsL8RPZHquRy/dzdljGX6VR8WdjocbKE4lCqOVbACuU2QYRVE
         rIBSCkX0Y6XnTgR6WzV5Cqn8UdvZu9wDxiBseys3U7J5w6mHKxPGdJCH/E5vHt7NibpO
         ywGg2yQry0IC7YGjxUoo/T3pJgaSjsRLOPpt+KdFj1r6pWLvi8Yn+4o7OcBEJ6t5RPmM
         oThA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=T2sx01ob;
       spf=pass (google.com: domain of feng.tang@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=feng.tang@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7a9a7a07571si13098485a.4.2024.09.08.18.30.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Sun, 08 Sep 2024 18:30:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of feng.tang@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: Mjsoh1Q8TnyEZeqiUx5svQ==
X-CSE-MsgGUID: SGchhfQsRq6fQA07jzUEnQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11189"; a="28258100"
X-IronPort-AV: E=Sophos;i="6.10,213,1719903600"; 
   d="scan'208";a="28258100"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 08 Sep 2024 18:30:07 -0700
X-CSE-ConnectionGUID: UowcQFlWTN6ZxGnlayNrVA==
X-CSE-MsgGUID: NSxbVtALS32RTELxfc1T0A==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.10,213,1719903600"; 
   d="scan'208";a="66486438"
Received: from feng-clx.sh.intel.com ([10.239.159.50])
  by orviesa009.jf.intel.com with ESMTP; 08 Sep 2024 18:30:03 -0700
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
	Danilo Krummrich <dakr@kernel.org>
Cc: linux-mm@kvack.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Feng Tang <feng.tang@intel.com>
Subject: [PATCH 1/5] mm/kasan: Don't store metadata inside kmalloc object when slub_debug_orig_size is on
Date: Mon,  9 Sep 2024 09:29:54 +0800
Message-Id: <20240909012958.913438-2-feng.tang@intel.com>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20240909012958.913438-1-feng.tang@intel.com>
References: <20240909012958.913438-1-feng.tang@intel.com>
MIME-Version: 1.0
X-Original-Sender: feng.tang@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=T2sx01ob;       spf=pass
 (google.com: domain of feng.tang@intel.com designates 198.175.65.15 as
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
---
 mm/kasan/generic.c |  5 ++++-
 mm/slab.h          |  6 ++++++
 mm/slub.c          | 17 -----------------
 3 files changed, 10 insertions(+), 18 deletions(-)

diff --git a/mm/kasan/generic.c b/mm/kasan/generic.c
index 6310a180278b..cad376199d47 100644
--- a/mm/kasan/generic.c
+++ b/mm/kasan/generic.c
@@ -393,8 +393,11 @@ void kasan_cache_create(struct kmem_cache *cache, unsigned int *size,
 	 *    be touched after it was freed, or
 	 * 2. Object has a constructor, which means it's expected to
 	 *    retain its content until the next allocation.
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
index 90f95bda4571..7a0e9b34ba2a 100644
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
index 23761533329d..996a72fa6f62 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240909012958.913438-2-feng.tang%40intel.com.
