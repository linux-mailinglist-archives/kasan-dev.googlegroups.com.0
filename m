Return-Path: <kasan-dev+bncBAABBO5UY7EQMGQENRY3T5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x240.google.com (mail-lj1-x240.google.com [IPv6:2a00:1450:4864:20::240])
	by mail.lfdr.de (Postfix) with ESMTPS id 3DF3BCA508F
	for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 20:00:13 +0100 (CET)
Received: by mail-lj1-x240.google.com with SMTP id 38308e7fff4ca-37a4e2bbbc0sf6050761fa.0
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Dec 2025 11:00:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1764874812; cv=pass;
        d=google.com; s=arc-20240605;
        b=juqARuk3cNum6IUZnQHFc3BRMisRQj4LaFu3xH0gKC6SFzyGmVmp0NbhFoVwjLQbE1
         wWWP5RiAymD/2hQ8NdwrwkyH/NyDPCZBzGR7tbFa7G6XXPDRj4PFndgi8a3BOvIjYa+v
         GUE5rahv/KSWntb4Z3DeOKUu9Bsf9vS6hg/2bG9hbTVYtnZMo/K5QfVTBS59VkYnHO6I
         UgMs1alxUvUS4uNXucMReJlvhBJF3/u1Aw6BnMhs/qo767eUUROXdRMQA6bvfmmq5Lkw
         FrNnajRybM8MLglxjTyM3vWo4A3DGHok0vpSa++UkmhMcYkvbd9B7kLtlL9k3JJfCvDx
         CKQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=geu5kO7x8WIkBn+tLgkTVYikfY6EBDDwwlE8RlL14h4=;
        fh=mtKfYC59xdZJf+zhTy0Xr6REWVDTCQoFx8PkP41eQfw=;
        b=UX5c/IEOrwPUF6ptTY+yeN0LAcJvxG6OhV7vXPerzL3hzg+Gu/M2pjIMWZCFTKHqfr
         hLNl9wDgumV7NV4v5H33WVk9OZVpUQjW9aZ/mUuKKcrUnEVMm4kspBy+smvg5CBERiuN
         MJxwQeRlc40Dald+oD7QbihmxQOyE2p3mdHyWUY/Ax5RjsouAcLWasRgs8zY4rjxHipe
         U+SzShmkJ1ScCW9vUQSyiQsSRvcEeS9UNoiI9qiyffZBzILpzfga1zYxApzAc28In+lG
         /aSVWO5NU6oho3YEPwodZIlvHZWEtnJ/MP9V7FBHAoWeE3/L+EyUNCn53kUyFylb0jSg
         3EFg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=rtyWO8Mh;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.119 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1764874812; x=1765479612; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=geu5kO7x8WIkBn+tLgkTVYikfY6EBDDwwlE8RlL14h4=;
        b=BA6TOQ5dPVY8UgNObfZi5diYi2ZaWABlP7YKiav9W9ynjJWzYduCU5PFpQTXDilyGx
         WJ4XmZQNgIG6S5tgjsaFVRkkV16wb6741YKG61loFNJjXIgHeNXBnM/cYNVc8TbGq+Gi
         zFj3M9Zxt5VUvsgcGJXkTMTuAA6tYyv/Bn81zKgEQGdsbF+hTCcfqlCwTT5RKwF8YNAk
         gxpCKsU8bSHSzPR2Z9WEJq/iZpG8VeuNWqqi3u9F2fx+cDY3KDXeZnyDIBFoo9sgGR3Z
         lvTp9+RobD4zqhigr2xAJm2FEJnFs6GgM2J9RUtopiNilGF7n08D5DyBG7SJDIQ6R/t2
         KFVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1764874812; x=1765479612;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=geu5kO7x8WIkBn+tLgkTVYikfY6EBDDwwlE8RlL14h4=;
        b=T9wM1nI78cCq98Xbc0ocW/rzAqS7tXmGoS0tqHnTjlASJpaw0d6+pL2ya5mHmktfIN
         O1JXWu4WTVlD/2+IzcEW42nzr9GEjE8N3RKEuPw5abRWS0izzuzTvlOG+Su5VGdkcg4N
         jvbWcUzGE+wze54LmssOPwkGuUk01uqJDesP+NDH9zcbH5isQrTEpQ3kjGVJQ3WxS6AW
         2yD3Ridkgu5Tn6m5+IQbnqJTupTCXcsAPZLVIArj5SMBeCEk/GuOtmjYXOhw+XdzSoY+
         ZWGV3nZ/7rCgmzNmvdLVtG3AmlzE8vA9u632lsEoBAxRNVQ/e7KN4oSCkE5dyvay1GW6
         ovzA==
X-Forwarded-Encrypted: i=2; AJvYcCWs9LuBwjh5+15howLbSMhGoupPWCS1sy+zl9jTJXiXyb9GZoEyiW0+jTUCSZOlbojLnFd4Vg==@lfdr.de
X-Gm-Message-State: AOJu0YxuIVlZFM4TblLTYj0en8bnvSosLhvS5HetzFHrkNjDQytdeP1N
	aaXYZ7Mc9MiD7ve4NAyx98kg4l7O/rFzFpHKGQUT5NyYeRy2RGHH22Ly
X-Google-Smtp-Source: AGHT+IHsjeSGzKuNQt59iwVMtEmpeVGK3uyKWgtL29EXSoxTlLo+H5QP85r9snLLPvnSdvGG3yBaDQ==
X-Received: by 2002:a05:651c:41:b0:375:db6e:fac9 with SMTP id 38308e7fff4ca-37e63905eb7mr17428441fa.31.1764874812228;
        Thu, 04 Dec 2025 11:00:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+YJIXtRvryVVOXhC7EW+MRVTG5vjOVYfAaItFHefzlQ1w=="
Received: by 2002:a2e:94ce:0:b0:37b:97f4:2753 with SMTP id 38308e7fff4ca-37e6ebbe4c2ls1773511fa.1.-pod-prod-05-eu;
 Thu, 04 Dec 2025 11:00:10 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXmdLRXE2Ec9JMtv0djjS8x7WSLbzvtVKae9v225KJW2tS+2KKXnSDJhg9CB9etS7mxNZsZlh+EAUs=@googlegroups.com
X-Received: by 2002:a2e:740a:0:b0:37d:1fa0:92bc with SMTP id 38308e7fff4ca-37e63904703mr19946871fa.29.1764874810126;
        Thu, 04 Dec 2025 11:00:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1764874810; cv=none;
        d=google.com; s=arc-20240605;
        b=XUDLcUtq4mxryOtSeWIbqd3UPtR8aDI9efRvOvZpWA63KiNEqxtnR1ltjwM+tt2E1z
         sD78YmcZ3HuyhHFG/XLbwH1c0sFf1n/6hsTI1b2L0qdPFYq9zBFpxQtkHRGV4Pb0tFAx
         mcnIwfT7Uf84LddpgJO5dXNO8B/qj5IwKtOa394UeRoi4Ag9MiLy28rymaZqpk9swKr/
         30bnU6JLTUk0iMarrqJutdtaYJPlCjII/9eTAAnen6cEopMSP6D7AwkwZ867vIPKe9uc
         NrXcSBcKokokXMKK0A47vhlWqxYjf9u4UFhhJGEc3VCswDc3KZ6ZTtyUMtSDJ4nKu1Ym
         DJ0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=IkyiGHAPhFI7mnPUmSkIC1C5JfoL+QfGKczkbPsXbcs=;
        fh=UmbmKvvrgM3XQnY5Fwi2JBp+IjfoSUavXPja7kaGluU=;
        b=WBAOofhrNVTwEdg5gm9sxVQ7xFtYVoP0VO4eg/qo5Jeop6zoe4vzs0jJ21+zqU8blP
         Nl+wg+3x46GodMokJEaq4+9SO8LYFc3YJkfXnwPrHi2RUX3pNHWag+Zl5AQJaKRkl2PZ
         C85La8eDtPySyYc9OFmdz4QCbvb76JmoPOUKwNXnRowYT4wbZGHlfA409roreGzEqGNW
         009qn3DibLmd0h57NUa1lgpQ4ChSGCHt9fQ5DZtx3ed+/2bM3p6ya+4ueuvYVSgVEsT/
         dxABdGPjdmzYLb+xsiemwzzcsy51wTcOMi1FH62W7DBeVDGlhynkJgPLJLPKalB/OXeI
         2irg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=rtyWO8Mh;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.119 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-106119.protonmail.ch (mail-106119.protonmail.ch. [79.135.106.119])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37e6fe49e2asi392831fa.1.2025.12.04.11.00.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Dec 2025 11:00:10 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.119 as permitted sender) client-ip=79.135.106.119;
Date: Thu, 04 Dec 2025 19:00:04 +0000
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Uladzislau Rezki <urezki@gmail.com>, Marco Elver <elver@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, jiayuan.chen@linux.dev, stable@vger.kernel.org, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: [PATCH v3 2/3] kasan: Refactor pcpu kasan vmalloc unpoison
Message-ID: <eb61d93b907e262eefcaa130261a08bcb6c5ce51.1764874575.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1764874575.git.m.wieczorretman@pm.me>
References: <cover.1764874575.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 258475af37f58ec18af8ccf0e0fabf0466575111
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=rtyWO8Mh;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.119 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>

A KASAN tag mismatch, possibly causing a kernel panic, can be observed
on systems with a tag-based KASAN enabled and with multiple NUMA nodes.
It was reported on arm64 and reproduced on x86. It can be explained in
the following points:

	1. There can be more than one virtual memory chunk.
	2. Chunk's base address has a tag.
	3. The base address points at the first chunk and thus inherits
	   the tag of the first chunk.
	4. The subsequent chunks will be accessed with the tag from the
	   first chunk.
	5. Thus, the subsequent chunks need to have their tag set to
	   match that of the first chunk.

Refactor code by reusing __kasan_unpoison_vmalloc in a new helper in
preparation for the actual fix.

Changelog v1 (after splitting of from the KASAN series):
- Rewrite first paragraph of the patch message to point at the user
  impact of the issue.
- Move helper to common.c so it can be compiled in all KASAN modes.

Fixes: 1d96320f8d53 ("kasan, vmalloc: add vmalloc tagging for SW_TAGS")
Cc: <stable@vger.kernel.org> # 6.1+
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v3:
- Redo the patch after applying Andrey's comments to align the code more
  with what's already in include/linux/kasan.h

Changelog v2:
- Redo the whole patch so it's an actual refactor.

 include/linux/kasan.h | 15 +++++++++++++++
 mm/kasan/common.c     | 17 +++++++++++++++++
 mm/vmalloc.c          |  4 +---
 3 files changed, 33 insertions(+), 3 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 6d7972bb390c..cde493cb7702 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -615,6 +615,16 @@ static __always_inline void kasan_poison_vmalloc(const void *start,
 		__kasan_poison_vmalloc(start, size);
 }
 
+void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
+				 kasan_vmalloc_flags_t flags);
+static __always_inline void
+kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
+			  kasan_vmalloc_flags_t flags)
+{
+	if (kasan_enabled())
+		__kasan_unpoison_vmap_areas(vms, nr_vms, flags);
+}
+
 #else /* CONFIG_KASAN_VMALLOC */
 
 static inline void kasan_populate_early_vm_area_shadow(void *start,
@@ -639,6 +649,11 @@ static inline void *kasan_unpoison_vmalloc(const void *start,
 static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
 { }
 
+static __always_inline void
+kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
+			  kasan_vmalloc_flags_t flags)
+{ }
+
 #endif /* CONFIG_KASAN_VMALLOC */
 
 #if (defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)) && \
diff --git a/mm/kasan/common.c b/mm/kasan/common.c
index d4c14359feaf..1ed6289d471a 100644
--- a/mm/kasan/common.c
+++ b/mm/kasan/common.c
@@ -28,6 +28,7 @@
 #include <linux/string.h>
 #include <linux/types.h>
 #include <linux/bug.h>
+#include <linux/vmalloc.h>
 
 #include "kasan.h"
 #include "../slab.h"
@@ -582,3 +583,19 @@ bool __kasan_check_byte(const void *address, unsigned long ip)
 	}
 	return true;
 }
+
+#ifdef CONFIG_KASAN_VMALLOC
+void __kasan_unpoison_vmap_areas(struct vm_struct **vms, int nr_vms,
+				 kasan_vmalloc_flags_t flags)
+{
+	unsigned long size;
+	void *addr;
+	int area;
+
+	for (area = 0 ; area < nr_vms ; area++) {
+		size = vms[area]->size;
+		addr = vms[area]->addr;
+		vms[area]->addr = __kasan_unpoison_vmalloc(addr, size, flags);
+	}
+}
+#endif
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 22a73a087135..33e705ccafba 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -4872,9 +4872,7 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	 * With hardware tag-based KASAN, marking is skipped for
 	 * non-VM_ALLOC mappings, see __kasan_unpoison_vmalloc().
 	 */
-	for (area = 0; area < nr_vms; area++)
-		vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
-				vms[area]->size, KASAN_VMALLOC_PROT_NORMAL);
+	kasan_unpoison_vmap_areas(vms, nr_vms, KASAN_VMALLOC_PROT_NORMAL);
 
 	kfree(vas);
 	return vms;
-- 
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/eb61d93b907e262eefcaa130261a08bcb6c5ce51.1764874575.git.m.wieczorretman%40pm.me.
