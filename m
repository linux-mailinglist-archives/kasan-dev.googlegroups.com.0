Return-Path: <kasan-dev+bncBAABBI4C36GQMGQEHDUGUXA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id CDFB14736E7
	for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 22:54:43 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id m1-20020ac24281000000b004162863a2fcsf8015816lfh.14
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Dec 2021 13:54:43 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639432483; cv=pass;
        d=google.com; s=arc-20160816;
        b=gGQyP0g4s5O+1hIxpE9S7/6QW9hTuQB4aom+z/ouCop/7nZmx4y00lo9DqNuDeIWpZ
         LIQYf1NsnVBCGWVJcTa/IKX/VeYhQc5S/wycFpe/vAt2pOVkFWQ0AIxo9QMy3HYj4h8E
         hVMZhakCZR9L2C1emDF2I0XX+W9/LZldPJkIt/DEq9gRlavf0TyHW1swjbU8t1taBMfh
         DE8lj8nnugOaJPUDiHV108JNepjqWbGXor8CV+AWI4uEB+ij6mTOmAttLbIYQHoy6QvW
         EobiItQfRoegFQPpN7T1lXwiFsavbhKJjT32+VDiL7PvAzmRn1kwhx2zge+Iiaf5fd0X
         /LEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=z4xpXVWeqH+AWkcs8H7YIIOfbwNXXXZXURXUtal++Qo=;
        b=c0Yk8+hJgBn26oWN1gmAXuLRzrwv5srrJ3jARqIvzbrmtqyehHruwxHBqbvlm20zMG
         lXYTaLyS1lajN3MGxSwz3ghVYqxcSxCChyPihutR1M00VsPe024EdU9M3f3H3xK5uTDl
         JpBnL85R1bM6juPCsj1sfNBcf6/CTCYiSmy84wX2uO7d+BOmW9nHPHX+vpfYmj3EuWWh
         oHPLOLmcatUhw4/vG0o6+Gx+XF2sGLXMJ68p+q1UuYYio1UvxBHWNfv1DvcFU+Z0w03b
         0MHPLQhL/ScFKLBOf2uFVv6HpaljCRkRV2kd8MzmsjOIz95bbA40WF++op+sdPnQ1ovc
         7nFw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VG3LRepx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z4xpXVWeqH+AWkcs8H7YIIOfbwNXXXZXURXUtal++Qo=;
        b=ZsX3qbcCPGmzx85dgj1ZvH0TUVh0+jSYQu97tgBO/f2HpBfIfzMeyeVnoi8mWhlWTL
         fRqq4gf0u5fR1griA0W4en7U+6WtR9w/Ydq8uY0siRnt4G02eRXrHJUM+rff/I/f1t2Z
         YkPFHq3/iY8ivtChJe7mfBXl/BLAl9ZKy2uTxDFUO2nltOxizh0sdQvQose5gLvfpq+I
         OeQ3YJzyeVaOiuwJYa9o3pRZ7k36m2AppwHeiLCujAKiNK+L3fmMHBKtyLNsgALe/za8
         t605gFWhSJ1Q0aY53625CMDSiAABlSfAzp19YRroBlWVG1RmoQ9QIj4yRG6tX5fdUELn
         wPrA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z4xpXVWeqH+AWkcs8H7YIIOfbwNXXXZXURXUtal++Qo=;
        b=LBp6ilwamReqHx7Iv66h9iktPTmgVmphP6QR02P2b3SWsucsMH9js5reH4loCr0Lp0
         EfxOkNBl4QBZE6pCx7gjTAPF+QXMRh88lyylpmR2qHNDfmXW3h0Aq4LDSpbFgoid7V+A
         5TZLnkRQ/OmUkPemSRYu22thR0Rzek8LdVmx5jpLmGDX1RYUdsObEeUsAhOnwhgSy5zr
         OgEgzRBCOW3ix7BHKcLflnya1MFFannl6HXhsqUl1fGDAfi7hObEiC/GMwu/w/TdlVYf
         WTMjxggbbyUjpS3brErC6XG4gwSQoN3gK+CZZUajJeU8ekIkDTRo5rNuaJi/GKCJBJtb
         FTDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532VfLD/n0UF0FNL982RTuwe6RVO785p0eO9j5eJL5MZLDqqoe7f
	px6hvnlAIMdkzlDg/UgqYNE=
X-Google-Smtp-Source: ABdhPJyPSCcdn+4+F7ujq+Ji0nf7KMfnBURxxK0yXy6ml3JI53kkd1VhCP1A4AemhDwafvRruz5VGA==
X-Received: by 2002:ac2:4c47:: with SMTP id o7mr970641lfk.558.1639432483405;
        Mon, 13 Dec 2021 13:54:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:1320:: with SMTP id x32ls1551490lfu.2.gmail; Mon,
 13 Dec 2021 13:54:42 -0800 (PST)
X-Received: by 2002:a05:6512:3d16:: with SMTP id d22mr875933lfv.523.1639432482681;
        Mon, 13 Dec 2021 13:54:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639432482; cv=none;
        d=google.com; s=arc-20160816;
        b=YyFge/1Ebwl0ZxzRyjhAUfet+1EN6R7bOjCYJVLYH4n6tgVfTXQc/yfc11skjRMEvo
         d6QxwqYyiHrOZ5dyPmhnye51en4xsgs1NOMSohsQr1qe+qUE2pneUSN73GHmpA15wexQ
         VWoba27opVtvQBxj/hsZlj0ceb1I/cL6t51s6qitPeLFUvWi0EiU7b9Y9fRzjx/A1Uvw
         SSS5is2iiRhj6lBr9cYMTSuceYYWCcWjDqS6f5o7gQuUVujhhrwZJX1nT1FQXn+VPByS
         VykZO9cfIgFoYpFkTw3v4N03SVf0HsFqZ1vHS0xeCQmB/hFtB+hMhuK0WcAwELr7ZH+s
         BZZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=LUWURXaK88rRLkisc1UEaimaL7WyvD1Il6BZVcMwikE=;
        b=cgRI11coW3Mty3KpDQ34XFR7bOmDBQ81NZfOz/pGBKqGr35+SNY118uTFrnk6qRjSM
         I4cpVO0pqBkfJPsOFVxEFY3mY71gg3aW1zxC3BnA9LzhvfKfDSa2mDfNGWboY1dc7RKS
         N3yfyvvPZFttq3wkHqu0+RyguqJy9pzh8POLAEhJCeDwedAhyWw6jeG5ghNC1iKisd7d
         pqYWE8vWN9GvwHbzn/swenFU3LhQhjx69r7prXkWAiNYCDBiiAQCKm2vZTUlCONExu8Y
         JkJPMEqMKStUFNLkRE2K1u23mv83jIvpTFS4YjeHfzwmBlXwd0zedbcEpI6qyqjnj0p5
         fGpA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=VG3LRepx;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [94.23.1.103])
        by gmr-mx.google.com with ESMTPS id e18si670448lji.3.2021.12.13.13.54.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 13 Dec 2021 13:54:42 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as permitted sender) client-ip=94.23.1.103;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH mm v3 24/38] kasan, vmalloc: add vmalloc tagging for SW_TAGS
Date: Mon, 13 Dec 2021 22:54:20 +0100
Message-Id: <190297aa8e648b25a6015cd9e15a477b720282ba.1639432170.git.andreyknvl@google.com>
In-Reply-To: <cover.1639432170.git.andreyknvl@google.com>
References: <cover.1639432170.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: andrey.konovalov@linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=VG3LRepx;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 94.23.1.103 as
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

Add vmalloc tagging support to SW_TAGS KASAN.

- __kasan_unpoison_vmalloc() now assigns a random pointer tag, poisons
  the virtual mapping accordingly, and embeds the tag into the returned
  pointer.

- __get_vm_area_node() (used by vmalloc() and vmap()) and
  pcpu_get_vm_areas() save the tagged pointer into vm_struct->addr
  (note: not into vmap_area->addr). This requires putting
  kasan_unpoison_vmalloc() after setup_vmalloc_vm[_locked]();
  otherwise the latter will overwrite the tagged pointer.
  The tagged pointer then is naturally propagateed to vmalloc()
  and vmap().

- vm_map_ram() returns the tagged pointer directly.

Enabling KASAN_VMALLOC with SW_TAGS is not yet allowed.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Changes v2->v3:
- Drop accidentally added kasan_unpoison_vmalloc() argument for when
  KASAN is off.
- Drop __must_check for kasan_unpoison_vmalloc(), as its result is
  sometimes intentionally ignored.
- Move allowing enabling KASAN_VMALLOC with SW_TAGS into a separate
  patch.
- Update patch description.

Changes v1->v2:
- Allow enabling KASAN_VMALLOC with SW_TAGS in this patch.
---
 include/linux/kasan.h | 16 ++++++++++------
 mm/kasan/shadow.c     |  6 ++++--
 mm/vmalloc.c          | 14 ++++++++------
 3 files changed, 22 insertions(+), 14 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index da320069e7cf..92c5dfa29a35 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -424,12 +424,13 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 			   unsigned long free_region_start,
 			   unsigned long free_region_end);
 
-void __kasan_unpoison_vmalloc(const void *start, unsigned long size);
-static __always_inline void kasan_unpoison_vmalloc(const void *start,
-						   unsigned long size)
+void *__kasan_unpoison_vmalloc(const void *start, unsigned long size);
+static __always_inline void *kasan_unpoison_vmalloc(const void *start,
+						    unsigned long size)
 {
 	if (kasan_enabled())
-		__kasan_unpoison_vmalloc(start, size);
+		return __kasan_unpoison_vmalloc(start, size);
+	return (void *)start;
 }
 
 void __kasan_poison_vmalloc(const void *start, unsigned long size);
@@ -454,8 +455,11 @@ static inline void kasan_release_vmalloc(unsigned long start,
 					 unsigned long free_region_start,
 					 unsigned long free_region_end) { }
 
-static inline void kasan_unpoison_vmalloc(const void *start, unsigned long size)
-{ }
+static inline void *kasan_unpoison_vmalloc(const void *start,
+					   unsigned long size)
+{
+	return (void *)start;
+}
 static inline void kasan_poison_vmalloc(const void *start, unsigned long size)
 { }
 
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 39d0b32ebf70..5a866f6663fc 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -475,12 +475,14 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 	}
 }
 
-void __kasan_unpoison_vmalloc(const void *start, unsigned long size)
+void *__kasan_unpoison_vmalloc(const void *start, unsigned long size)
 {
 	if (!is_vmalloc_or_module_addr(start))
-		return;
+		return (void *)start;
 
+	start = set_tag(start, kasan_random_tag());
 	kasan_unpoison(start, size, false);
+	return (void *)start;
 }
 
 /*
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 42406c53e2a5..837ed355bfc6 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2208,7 +2208,7 @@ void *vm_map_ram(struct page **pages, unsigned int count, int node)
 		mem = (void *)addr;
 	}
 
-	kasan_unpoison_vmalloc(mem, size);
+	mem = kasan_unpoison_vmalloc(mem, size);
 
 	if (vmap_pages_range(addr, addr + size, PAGE_KERNEL,
 				pages, PAGE_SHIFT) < 0) {
@@ -2441,10 +2441,10 @@ static struct vm_struct *__get_vm_area_node(unsigned long size,
 		return NULL;
 	}
 
-	kasan_unpoison_vmalloc((void *)va->va_start, requested_size);
-
 	setup_vmalloc_vm(area, va, flags, caller);
 
+	area->addr = kasan_unpoison_vmalloc(area->addr, requested_size);
+
 	return area;
 }
 
@@ -3785,9 +3785,6 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	for (area = 0; area < nr_vms; area++) {
 		if (kasan_populate_vmalloc(vas[area]->va_start, sizes[area]))
 			goto err_free_shadow;
-
-		kasan_unpoison_vmalloc((void *)vas[area]->va_start,
-				       sizes[area]);
 	}
 
 	/* insert all vm's */
@@ -3800,6 +3797,11 @@ struct vm_struct **pcpu_get_vm_areas(const unsigned long *offsets,
 	}
 	spin_unlock(&vmap_area_lock);
 
+	/* mark allocated areas as accessible */
+	for (area = 0; area < nr_vms; area++)
+		vms[area]->addr = kasan_unpoison_vmalloc(vms[area]->addr,
+							 vms[area]->size);
+
 	kfree(vas);
 	return vms;
 
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/190297aa8e648b25a6015cd9e15a477b720282ba.1639432170.git.andreyknvl%40google.com.
