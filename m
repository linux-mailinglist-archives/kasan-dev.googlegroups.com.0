Return-Path: <kasan-dev+bncBCCMH5WKTMGRBQH736QQMGQEOTJXE2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 483196E0E33
	for <lists+kasan-dev@lfdr.de>; Thu, 13 Apr 2023 15:12:33 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id hg16-20020a05600c539000b003f09d1918aasf2739599wmb.4
        for <lists+kasan-dev@lfdr.de>; Thu, 13 Apr 2023 06:12:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1681391553; cv=pass;
        d=google.com; s=arc-20160816;
        b=MU8v9O6aApMKsBnv3t5onEC2Qi3sHv6uLWYGshJTNsbOIQmm2CMBE0TfiypV+cdKd0
         rVyAlWWnLU1qFzftHw3mlBRHm0I74PAi8Ud+0fdbKDIGFrjvcDT2rv8VwFYJPOz21Jif
         fynmSw9ljDI7Iql8R4/NpQkfqRy8QM6i5w6QlVnbBHRV92UbKo+HHmYo6kGaHecVEC6t
         q/jkR0JzRKU8aVEorLxRjeI2UAQk6VUqSEkPOeMQkNZTmxOccjnk4FfEWPmSbKGbtxXw
         QBxytDV7PxfmVxgyLNBc7lVyyQjTnnYjvaB1dctF8XjXRZAScG4LEZJVBjwlb8zWzBWg
         JS3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=MYb+wXVoKNe374+QYWmLGzZ6mcvPdeXVsPlKZEZGPVk=;
        b=TbtcaYSgM0RGIOEtQVnQYQrRUIvEuVztl2XxghxGbq7DwP/+GXQiSia/XuU9eSBgLh
         oGGhGCEC4H+RvzA3PrugxZePWkk5Vk71vTJegvsY1NOEGRrjhJTEnzJejiaJoR4fD0tr
         CMeyJ1Ojfll47TkHbchb5v90pmVg1aREwpd/Dm6elmVsHok/VYSxSdpJKM/bimxoGJzD
         V1UClShxKpmcSMbZDfUTFSSvOPh+usvsa1lYpXYSF6r+nTJDYPVIPsL3UE6hTHEO9o8O
         uLsRQ80mKf4kGSyh2Q1kTm9yeC/BQNoAebFGCtnBbPcBrcaLmbeziLMxJrS6QP7UhRpk
         VMdg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=UWMmjgu4;
       spf=pass (google.com: domain of 3v_83zaykccysxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3v_83ZAYKCcYsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1681391553; x=1683983553;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=MYb+wXVoKNe374+QYWmLGzZ6mcvPdeXVsPlKZEZGPVk=;
        b=IVOpWbOMWzeJhkyV5LAtF67/wPUYF9vtZTZXbNW3VBwhOGJhvjH/xuZlEK0oILKhMO
         OQOzq6rKsCbkdCx/Viw1QVbKhlE2dqnthFPAD8f86Edwwyk/zeCWtamg03UUyVSWDDAu
         25ezVRYRO4innn3SPuSJ3XXAEpuL6ZXPbfgBvX9JOXSRQvksKPVBLEzhUIYJpsndJmZl
         YbmgbC4dUjxQo5fB1G/5ahuGtsNg1kv5JqfkaeJqc+0eIDo1kuDdgyJM61TjQyzCDAW5
         yaT6xUVS+mvzszul/4zynqU/4nYMqVr3MXl0v5wRsVNSKO/QeNqvED26S/E5XkxB9pS6
         G/eg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1681391553; x=1683983553;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MYb+wXVoKNe374+QYWmLGzZ6mcvPdeXVsPlKZEZGPVk=;
        b=gRzVeS0KyROOumiqcaR6IlILBZiJxlQRFgDNzPeC8eI6lofoGKzm520rxjGclnoWxq
         1TVBeLigNhpeKmGILVKFOuEceoS1EJFqh9FUWToCftNnKCGwCq6UAppjG9Nqy1e+SeMF
         1LnRG3GhPhgUQc8fQKbR47U8twahVzzWSAMV+btpYx/8kxV9CYEz36KJ3QqPEkk2Pz/F
         8+HgKDy3F9nUv8j7MjNaTjiPbp9IQuY8L60Pqd52IYYEsJ6qLJpcSet38LaHQoyceaGk
         tq59QPmNzeBfTRjq7bPKNK9JsT0d3mCx17wguSm14FeE3GB/eMRW7g+3pydp9vz7jWtF
         CuPQ==
X-Gm-Message-State: AAQBX9dpGkTTTS6WER5J9Z+vGq5F7DFZHRVXs2E8WyUCgY4I5HCPdnZV
	dZYGcBd8OLr4D2nijURc7dE=
X-Google-Smtp-Source: AKy350bvUoZ/tJugREN+KbABIA299C7ShIX564YGMiWKPDDapb9vIl3tBzVCCf1w8ZbJD+Rm+dHblA==
X-Received: by 2002:a5d:518d:0:b0:2ef:b6e1:7a4 with SMTP id k13-20020a5d518d000000b002efb6e107a4mr394989wrv.11.1681391552683;
        Thu, 13 Apr 2023 06:12:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:1c8b:b0:3f0:9f47:35a7 with SMTP id
 k11-20020a05600c1c8b00b003f09f4735a7ls2390686wms.2.-pod-canary-gmail; Thu, 13
 Apr 2023 06:12:31 -0700 (PDT)
X-Received: by 2002:a05:600c:2283:b0:3ea:e582:48dd with SMTP id 3-20020a05600c228300b003eae58248ddmr1840423wmf.34.1681391551480;
        Thu, 13 Apr 2023 06:12:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1681391551; cv=none;
        d=google.com; s=arc-20160816;
        b=mH9ySpNj/Z6iyYc5vBlK830tPUnYaVp1zWesUgl/+CaNp4XxfmJpD+xBOzhVU0MKoU
         uNobI1Zgq/IpqD2r29/n97DWaWwPGrv0sM71ExN7TDyjJG2S+fS1jlsZbaiAd1DPW6GK
         bSp6T+EJLvs/GDJRw4BeW5GE1Z5LP+Xyt9o4YcviL/BoD6UI6NEQEhfU5seZaMzbBjKR
         dLlUN7Jc2TcYgpTm78GmKqvT+YN22sS3oeX27ZxC01dLaR2+Dv25AXRLOg1QZfeCqxk8
         3sqbusw/AYsgFjKebcL6exroWmLc3t1F73kZODu9G+wQnJEpI8WGXuPH7XSqCXvhHezX
         eeRQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=akRe6e4LluVT6nSisjA8EFH4R71lf+zwEBXmk0EhBro=;
        b=u7nj3FIMch0zG8HqH+9+mwmp3D509peH7Ft9S5fakusPJtN5c2Al3acFnnWNVfx9vk
         KMHX9j6UThlEMyn2SZznEOvjR3JX9EPUlviMA4a3CXrt4ammak4X4EZ046/EVMpV4aIf
         uC+mcK+NNcDvcIG8srNTOHVcGU8fMxj3//D+tIlbPGcUwtrIwmZ4oJ6eYY+ipTTC8n3/
         8vtS9aARRMr2uPwaoDCPBpDNDhzv/Xb8uoXwsPRTduCKZA0+UUk0ZRfU6h3XHsBL4hYd
         fP4ok7w0eboewTx2KSZnes2JyJgx+PpRx+yFYiHLIkvnOt523Nm/dKpMoOe/dHlurke0
         8ndQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=UWMmjgu4;
       spf=pass (google.com: domain of 3v_83zaykccysxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3v_83ZAYKCcYsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x34a.google.com (mail-wm1-x34a.google.com. [2a00:1450:4864:20::34a])
        by gmr-mx.google.com with ESMTPS id p1-20020a05600c1d8100b003ee1c61e7d9si400117wms.3.2023.04.13.06.12.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 Apr 2023 06:12:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3v_83zaykccysxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com designates 2a00:1450:4864:20::34a as permitted sender) client-ip=2a00:1450:4864:20::34a;
Received: by mail-wm1-x34a.google.com with SMTP id n11-20020a05600c3b8b00b003f04739b77aso17528513wms.9
        for <kasan-dev@googlegroups.com>; Thu, 13 Apr 2023 06:12:31 -0700 (PDT)
X-Received: from glider.muc.corp.google.com ([2a00:79e0:9c:201:eb2b:4d7d:1d7f:9316])
 (user=glider job=sendgmr) by 2002:a5d:4a42:0:b0:2f2:7854:f419 with SMTP id
 v2-20020a5d4a42000000b002f27854f419mr325850wrs.13.1681391551064; Thu, 13 Apr
 2023 06:12:31 -0700 (PDT)
Date: Thu, 13 Apr 2023 15:12:21 +0200
In-Reply-To: <20230413131223.4135168-1-glider@google.com>
Mime-Version: 1.0
References: <20230413131223.4135168-1-glider@google.com>
X-Mailer: git-send-email 2.40.0.577.gac1e443424-goog
Message-ID: <20230413131223.4135168-2-glider@google.com>
Subject: [PATCH v2 2/4] mm: kmsan: handle alloc failures in kmsan_ioremap_page_range()
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
To: glider@google.com
Cc: urezki@gmail.com, hch@infradead.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, akpm@linux-foundation.org, elver@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, 
	Dipanjan Das <mail.dipanjan.das@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=UWMmjgu4;       spf=pass
 (google.com: domain of 3v_83zaykccysxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com
 designates 2a00:1450:4864:20::34a as permitted sender) smtp.mailfrom=3v_83ZAYKCcYsxupq3s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--glider.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

Similarly to kmsan_vmap_pages_range_noflush(),
kmsan_ioremap_page_range() must also properly handle allocation/mapping
failures. In the case of such, it must clean up the already created
metadata mappings and return an error code, so that the error can be
propagated to ioremap_page_range(). Without doing so, KMSAN may silently
fail to bring the metadata for the page range into a consistent state,
which will result in user-visible crashes when trying to access them.

Reported-by: Dipanjan Das <mail.dipanjan.das@gmail.com>
Link: https://lore.kernel.org/linux-mm/CANX2M5ZRrRA64k0hOif02TjmY9kbbO2aCBPyq79es34RXZ=cAw@mail.gmail.com/
Fixes: b073d7f8aee4 ("mm: kmsan: maintain KMSAN metadata for page operations")
Signed-off-by: Alexander Potapenko <glider@google.com>

---
v2:
 -- updated patch description as requested by Andrew Morton
 -- check the return value of __vmap_pages_range_noflush(), as suggested by Dipanjan Das
 -- return 0 from the inline version of kmsan_ioremap_page_range()
    (spotted by kernel test robot <lkp@intel.com>)
---
 include/linux/kmsan.h | 19 ++++++++-------
 mm/kmsan/hooks.c      | 55 ++++++++++++++++++++++++++++++++++++-------
 mm/vmalloc.c          |  4 ++--
 3 files changed, 59 insertions(+), 19 deletions(-)

diff --git a/include/linux/kmsan.h b/include/linux/kmsan.h
index c7ff3aefc5a13..30b17647ce3c7 100644
--- a/include/linux/kmsan.h
+++ b/include/linux/kmsan.h
@@ -160,11 +160,12 @@ void kmsan_vunmap_range_noflush(unsigned long start, unsigned long end);
  * @page_shift:	page_shift argument passed to vmap_range_noflush().
  *
  * KMSAN creates new metadata pages for the physical pages mapped into the
- * virtual memory.
+ * virtual memory. Returns 0 on success, callers must check for non-zero return
+ * value.
  */
-void kmsan_ioremap_page_range(unsigned long addr, unsigned long end,
-			      phys_addr_t phys_addr, pgprot_t prot,
-			      unsigned int page_shift);
+int kmsan_ioremap_page_range(unsigned long addr, unsigned long end,
+			     phys_addr_t phys_addr, pgprot_t prot,
+			     unsigned int page_shift);
 
 /**
  * kmsan_iounmap_page_range() - Notify KMSAN about a iounmap_page_range() call.
@@ -296,12 +297,12 @@ static inline void kmsan_vunmap_range_noflush(unsigned long start,
 {
 }
 
-static inline void kmsan_ioremap_page_range(unsigned long start,
-					    unsigned long end,
-					    phys_addr_t phys_addr,
-					    pgprot_t prot,
-					    unsigned int page_shift)
+static inline int kmsan_ioremap_page_range(unsigned long start,
+					   unsigned long end,
+					   phys_addr_t phys_addr, pgprot_t prot,
+					   unsigned int page_shift)
 {
+	return 0;
 }
 
 static inline void kmsan_iounmap_page_range(unsigned long start,
diff --git a/mm/kmsan/hooks.c b/mm/kmsan/hooks.c
index 3807502766a3e..ec0da72e65aa0 100644
--- a/mm/kmsan/hooks.c
+++ b/mm/kmsan/hooks.c
@@ -148,35 +148,74 @@ void kmsan_vunmap_range_noflush(unsigned long start, unsigned long end)
  * into the virtual memory. If those physical pages already had shadow/origin,
  * those are ignored.
  */
-void kmsan_ioremap_page_range(unsigned long start, unsigned long end,
-			      phys_addr_t phys_addr, pgprot_t prot,
-			      unsigned int page_shift)
+int kmsan_ioremap_page_range(unsigned long start, unsigned long end,
+			     phys_addr_t phys_addr, pgprot_t prot,
+			     unsigned int page_shift)
 {
 	gfp_t gfp_mask = GFP_KERNEL | __GFP_ZERO;
 	struct page *shadow, *origin;
 	unsigned long off = 0;
-	int nr;
+	int nr, err = 0, clean = 0, mapped;
 
 	if (!kmsan_enabled || kmsan_in_runtime())
-		return;
+		return 0;
 
 	nr = (end - start) / PAGE_SIZE;
 	kmsan_enter_runtime();
-	for (int i = 0; i < nr; i++, off += PAGE_SIZE) {
+	for (int i = 0; i < nr; i++, off += PAGE_SIZE, clean = i) {
 		shadow = alloc_pages(gfp_mask, 1);
 		origin = alloc_pages(gfp_mask, 1);
-		__vmap_pages_range_noflush(
+		if (!shadow || !origin) {
+			err = -ENOMEM;
+			goto ret;
+		}
+		mapped = __vmap_pages_range_noflush(
 			vmalloc_shadow(start + off),
 			vmalloc_shadow(start + off + PAGE_SIZE), prot, &shadow,
 			PAGE_SHIFT);
-		__vmap_pages_range_noflush(
+		if (mapped) {
+			err = mapped;
+			goto ret;
+		}
+		shadow = NULL;
+		mapped = __vmap_pages_range_noflush(
 			vmalloc_origin(start + off),
 			vmalloc_origin(start + off + PAGE_SIZE), prot, &origin,
 			PAGE_SHIFT);
+		if (mapped) {
+			__vunmap_range_noflush(
+				vmalloc_shadow(start + off),
+				vmalloc_shadow(start + off + PAGE_SIZE));
+			err = mapped;
+			goto ret;
+		}
+		origin = NULL;
+	}
+	/* Page mapping loop finished normally, nothing to clean up. */
+	clean = 0;
+
+ret:
+	if (clean > 0) {
+		/*
+		 * Something went wrong. Clean up shadow/origin pages allocated
+		 * on the last loop iteration, then delete mappings created
+		 * during the previous iterations.
+		 */
+		if (shadow)
+			__free_pages(shadow, 1);
+		if (origin)
+			__free_pages(origin, 1);
+		__vunmap_range_noflush(
+			vmalloc_shadow(start),
+			vmalloc_shadow(start + clean * PAGE_SIZE));
+		__vunmap_range_noflush(
+			vmalloc_origin(start),
+			vmalloc_origin(start + clean * PAGE_SIZE));
 	}
 	flush_cache_vmap(vmalloc_shadow(start), vmalloc_shadow(end));
 	flush_cache_vmap(vmalloc_origin(start), vmalloc_origin(end));
 	kmsan_leave_runtime();
+	return err;
 }
 
 void kmsan_iounmap_page_range(unsigned long start, unsigned long end)
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 1355d95cce1ca..31ff782d368b0 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -313,8 +313,8 @@ int ioremap_page_range(unsigned long addr, unsigned long end,
 				 ioremap_max_page_shift);
 	flush_cache_vmap(addr, end);
 	if (!err)
-		kmsan_ioremap_page_range(addr, end, phys_addr, prot,
-					 ioremap_max_page_shift);
+		err = kmsan_ioremap_page_range(addr, end, phys_addr, prot,
+					       ioremap_max_page_shift);
 	return err;
 }
 
-- 
2.40.0.577.gac1e443424-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230413131223.4135168-2-glider%40google.com.
