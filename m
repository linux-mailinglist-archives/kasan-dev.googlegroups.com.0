Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBXFWZK4AMGQEAIK23BQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id CF76C9A44AF
	for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 19:31:09 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-e035949cc4esf3354452276.1
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Oct 2024 10:31:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729272668; cv=pass;
        d=google.com; s=arc-20240605;
        b=ibxtVzYiNhLDF8akfEhScze0pVBi7E/Npjn/dI577cGlsP77GfQDm++FzdEIvEZj3z
         M+uTYJptSuSJb0/AU1oFaPzIrJqlhyY+zJKVbvOxLH2WZ0p5vZmi+P10I+cmvTJ7LCTk
         MX2XElYERxu+XXDxbYzWZcN64Kll8EDsDtYxqu6wl0nKqK+/a8ovxmyXXL9kjyCgrcel
         vS9uH+O6T31B2QbYr3xX8O4dTu8mv7OOG0BuPdNxgzTPeYDYlcizm2h7CghPkzOyM3sk
         prD5AYda6yH1zyK/lMJWjeblx/tFS6Yx0QB02jbf3c77ywwfaadvBkHFJGImKMZg6zBa
         5h4Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=gE4qI34nnOJHT/9dEciOo8w3fJS4xpl7V7S+nqdkZaA=;
        fh=KpXsE58UuX5Fy1vg/cA8OgHYre837Yf0Fp4Hy26x3f8=;
        b=lBO5sDLfgXn8NSvwhcTx2wbBz5Sko4cZF7NJv0rAWfT8kQFfdJbJu9teefg1HtI6M1
         XLx8gc4GPKd32XroWu6V6KdiJWYVwyWwR8mmz67DbLutRIj4fSqltoQ2QLInPBFebZSg
         qJGigKuDSMopw0qFCAJV+1Qe9jZHIsz34ZOTATFypXe7qRzG3/56grx3XnYio/6yysfW
         7ej/eMi2AeTW5veHNtowtlU51Mh+h+jIFtd3wjY+RXaMqh4w16nG9uNV8C9XV7QvuBR4
         HIouXvyXBj7hq3mMQJDJyQzXM1x7w6IGrWCrtXN049FK70GUSVK/LxFFK/AIVTWgIA9p
         Sa3w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cizc+7Im;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729272668; x=1729877468; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=gE4qI34nnOJHT/9dEciOo8w3fJS4xpl7V7S+nqdkZaA=;
        b=RAZSyOR1VwTY3GIPfsUYh2LOsnxOEGdjPWyXTJXN8zkn08h1tyTixn7hQwGlUybW//
         Ui44E3cuX5c0U57Kmd5nhKz21IGRS1FI5X99O1R/yBMQOCmr8PuhM8dGugNz9biEnT/8
         6TKmCE6uEZdv50HKLX1TYEmG3hW7CPNMAllisYo2EQ+VumBuBcQkrjhAwQr44L+XLFGP
         D2VQGPjtdEtp0gLAx3S+NBS5e6yUI6NfiJ7V+2Y4mzRhisw0JNqrQZkcG7V1BTmu0o4z
         QcKy6SiW26d4AcfxQi7uVwTN8UeSVZyvGao7GwjGGpdasC+Ymmm2ay20Jr32dd4k+4+p
         D4xA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1729272668; x=1729877468; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=gE4qI34nnOJHT/9dEciOo8w3fJS4xpl7V7S+nqdkZaA=;
        b=QXWQsHHum8iD/lQs5DjuVfA2zsS7WgP7ICjUhK+RMsc8iNr+2qFyfF0wEzPCPOkX34
         i0YcF0DU45q/j6Z5//o2TiLMbEyl1/0KLBF512IpGaFMOYdwoOHVg9CTmZaM4Vgzhf08
         o0Bs61754zME8+zLT7CTJhUx7WloDq5HSYL5xGsDq8SQGyYW/jbbvlAlklU3jPiPifyQ
         iL1Xx2mKMD2K9uWNsMO/810rAD0xrFU+KajSSDClORfwoW/IuR7rboLaGPbPAr9Wl3Ey
         Le/cFrMf9b0ZQaKlIwrc69Vk/0rN/zn7eJor+vj9SlPYeEIfEPyiReqMzoLX9audJZeh
         Q7UA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729272668; x=1729877468;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=gE4qI34nnOJHT/9dEciOo8w3fJS4xpl7V7S+nqdkZaA=;
        b=N1lx0fd+dP306+VGQDsNU00tYH61Kcj7okQxpDUiGpiHckEbWG2PqKUKa1190FuDXh
         uJYg+HMJaNFUBvG/EPldS2nfd+IDOen9hyVtp9lIcXS8SiEtd3DSzQHrYKzjhBTvQswp
         Kao1ifXJQaIIABsoddd4e1hcqhn+MWxcwgiwJ6ePFgLXHbssFiiIAHSd7R4GjhLxI6Fo
         kZ3WqcNeb8IDckO8pDp3hzPvKiFwZQtRzO4QBc9aesXfWKF6nwYUUsjaPwmIkBMlzf31
         tZWGmeh54mtsxpcLWsZ1z08OTXfB6yJYKqoxFOc+bT1aDqJdp30yDnxVns991ABIGoga
         7plQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWzLYZRz0oBbS0Rum38jNMTGkphsUZjeIS5ou79KbggEnfD2aBdfPF8g83M+c3A0gxn7g/pyA==@lfdr.de
X-Gm-Message-State: AOJu0YyROPfbJ04lorfgUyRLfNKA9NXGSuHcvCyiqUB8/sOFYvQAql9d
	/128Slxkr1rZIZSl6i4jEboHkCVlowPBFuHIow8GyI9i75adRfyo
X-Google-Smtp-Source: AGHT+IG2yGhS8kXlny+Q3iXjtqEKTLQZaWzdTeVjfpb2S6UWNeiTWWKBXtyMy3vnC0OswQhFPt0Vqg==
X-Received: by 2002:a05:6902:124a:b0:e29:1def:1032 with SMTP id 3f1490d57ef6-e2bb16ac49emr3174456276.41.1729272668634;
        Fri, 18 Oct 2024 10:31:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1005:b0:e29:1ffa:37db with SMTP id
 3f1490d57ef6-e2b9bfe6af2ls282073276.0.-pod-prod-09-us; Fri, 18 Oct 2024
 10:31:08 -0700 (PDT)
X-Received: by 2002:a05:690c:60c4:b0:6e3:1063:91ca with SMTP id 00721157ae682-6e5bfc589bamr36836657b3.40.1729272667841;
        Fri, 18 Oct 2024 10:31:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729272667; cv=none;
        d=google.com; s=arc-20240605;
        b=bJzJqaBXcKBue0vcQxQmH7cJUG20rzRINtYZxQDP+7YuKMi6pXvsu58hV7211C9obw
         ZZGPbvnwYWbrVjlULmdc4GDmOJSImLwZ7YDAYDMBwrBDvmhCvHxv7nvAi67q4oxTqKGv
         svw/HLoCCd4SSPHUph1FIZD8KsBMSKemZY+KJhKFkcsK9jpgr5ezlp5Kr1KgPaFQtj+k
         cM7vlXH56WQLtlZfmLBySoUNVXfkYGgfAssNeTtdWsyssrX4z0nicI1KDe6imD2QHeaV
         MHHaleSF9yNXVCbA7oJcHXUXShFu+5RmbES4FpO3yfcmMzePdXBO56tn7bdTdEdVYIeO
         ED6A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=EPaaeu37JE/wM6SvauUhRnxy0xWFM+VjQPTyakMCkTU=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=c9Qec5QTH24oWjmshXoyuKdVFHsd1tHfLH71oE9YhsK9Zg1qByQe+1zmkZRjiKhCpw
         V7K3xM8eKIJxv8ktjKvhIxRDS8YI+Bs5ulu4alEVrtinKa0WbW/AnVYKA85wsAnJ/fkM
         PvFrockuhEuTlbEgCFJo08OrspEMKaqK3qpFe9XCkz+Vh8GdcPpSQ2xg/cXwf4qPeMc6
         /IT+x3fAEgLAwFRQVG9Wo1ut47RV2DPDiGx5cnRZzLFtbKrd3hjdx+7OybwqtmvafoEO
         yv3zIr1HNhrj8CZHUquKabI0ZQAoDoJnHUih/G9dngkMEVCnOUIZyS2c5IacsA1+2Zsn
         fMng==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=cizc+7Im;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6e5bffb24c6si831257b3.1.2024.10.18.10.31.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Oct 2024 10:31:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-71e79f73aaeso1759736b3a.3
        for <kasan-dev@googlegroups.com>; Fri, 18 Oct 2024 10:31:07 -0700 (PDT)
X-Received: by 2002:a05:6a00:2d25:b0:71e:5950:97d2 with SMTP id d2e1a72fcca58-71ea3328e08mr4294187b3a.17.1729272666771;
        Fri, 18 Oct 2024 10:31:06 -0700 (PDT)
Received: from dw-tp.ibmuc.com ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ea3311f51sm1725242b3a.36.2024.10.18.10.31.01
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Oct 2024 10:31:05 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [PATCH v3 09/12] book3s64/hash: Add kfence functionality
Date: Fri, 18 Oct 2024 22:59:50 +0530
Message-ID: <5c2b61941b344077a2b8654dab46efa0322af3af.1729271995.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1729271995.git.ritesh.list@gmail.com>
References: <cover.1729271995.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=cizc+7Im;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::42e
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Now that linear map functionality of debug_pagealloc is made generic,
enable kfence to use this generic infrastructure.

1. Define kfence related linear map variables.
   - u8 *linear_map_kf_hash_slots;
   - unsigned long linear_map_kf_hash_count;
   - DEFINE_RAW_SPINLOCK(linear_map_kf_hash_lock);
2. The linear map size allocated in RMA region is quite small
   (KFENCE_POOL_SIZE >> PAGE_SHIFT) which is 512 bytes by default.
3. kfence pool memory is reserved using memblock_phys_alloc() which has
   can come from anywhere.
   (default 255 objects => ((1+255) * 2) << PAGE_SHIFT = 32MB)
4. The hash slot information for kfence memory gets added in linear map
   in hash_linear_map_add_slot() (which also adds for debug_pagealloc).

Reported-by: Pavithra Prakash <pavrampu@linux.vnet.ibm.com>
Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/include/asm/kfence.h     |   5 -
 arch/powerpc/mm/book3s64/hash_utils.c | 162 +++++++++++++++++++++++---
 2 files changed, 149 insertions(+), 18 deletions(-)

diff --git a/arch/powerpc/include/asm/kfence.h b/arch/powerpc/include/asm/kfence.h
index f3a9476a71b3..fab124ada1c7 100644
--- a/arch/powerpc/include/asm/kfence.h
+++ b/arch/powerpc/include/asm/kfence.h
@@ -10,7 +10,6 @@
 
 #include <linux/mm.h>
 #include <asm/pgtable.h>
-#include <asm/mmu.h>
 
 #ifdef CONFIG_PPC64_ELF_ABI_V1
 #define ARCH_FUNC_PREFIX "."
@@ -26,10 +25,6 @@ static inline void disable_kfence(void)
 
 static inline bool arch_kfence_init_pool(void)
 {
-#ifdef CONFIG_PPC64
-	if (!radix_enabled())
-		return false;
-#endif
 	return !kfence_disabled;
 }
 #endif
diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index f51f2cd9bf22..558d6f5202b9 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -40,6 +40,7 @@
 #include <linux/random.h>
 #include <linux/elf-randomize.h>
 #include <linux/of_fdt.h>
+#include <linux/kfence.h>
 
 #include <asm/interrupt.h>
 #include <asm/processor.h>
@@ -66,6 +67,7 @@
 #include <asm/pte-walk.h>
 #include <asm/asm-prototypes.h>
 #include <asm/ultravisor.h>
+#include <asm/kfence.h>
 
 #include <mm/mmu_decl.h>
 
@@ -271,7 +273,7 @@ void hash__tlbiel_all(unsigned int action)
 		WARN(1, "%s called on pre-POWER7 CPU\n", __func__);
 }
 
-#ifdef CONFIG_DEBUG_PAGEALLOC
+#if defined(CONFIG_DEBUG_PAGEALLOC) || defined(CONFIG_KFENCE)
 static void kernel_map_linear_page(unsigned long vaddr, unsigned long idx,
 				   u8 *slots, raw_spinlock_t *lock)
 {
@@ -325,11 +327,13 @@ static void kernel_unmap_linear_page(unsigned long vaddr, unsigned long idx,
 				     mmu_linear_psize,
 				     mmu_kernel_ssize, 0);
 }
+#endif
 
+#ifdef CONFIG_DEBUG_PAGEALLOC
 static u8 *linear_map_hash_slots;
 static unsigned long linear_map_hash_count;
 static DEFINE_RAW_SPINLOCK(linear_map_hash_lock);
-static inline void hash_debug_pagealloc_alloc_slots(void)
+static void hash_debug_pagealloc_alloc_slots(void)
 {
 	unsigned long max_hash_count = ppc64_rma_size / 4;
 
@@ -352,7 +356,8 @@ static inline void hash_debug_pagealloc_alloc_slots(void)
 		      __func__, linear_map_hash_count, &ppc64_rma_size);
 }
 
-static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr, int slot)
+static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr,
+							int slot)
 {
 	if (!debug_pagealloc_enabled() || !linear_map_hash_count)
 		return;
@@ -386,20 +391,148 @@ static int hash_debug_pagealloc_map_pages(struct page *page, int numpages,
 	return 0;
 }
 
-int hash__kernel_map_pages(struct page *page, int numpages, int enable)
+#else /* CONFIG_DEBUG_PAGEALLOC */
+static inline void hash_debug_pagealloc_alloc_slots(void) {}
+static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr, int slot) {}
+static int __maybe_unused
+hash_debug_pagealloc_map_pages(struct page *page, int numpages, int enable)
 {
-	return hash_debug_pagealloc_map_pages(page, numpages, enable);
+	return 0;
 }
+#endif /* CONFIG_DEBUG_PAGEALLOC */
 
-#else /* CONFIG_DEBUG_PAGEALLOC */
-int hash__kernel_map_pages(struct page *page, int numpages,
-					 int enable)
+#ifdef CONFIG_KFENCE
+static u8 *linear_map_kf_hash_slots;
+static unsigned long linear_map_kf_hash_count;
+static DEFINE_RAW_SPINLOCK(linear_map_kf_hash_lock);
+
+static phys_addr_t kfence_pool;
+
+static inline void hash_kfence_alloc_pool(void)
+{
+
+	/* allocate linear map for kfence within RMA region */
+	linear_map_kf_hash_count = KFENCE_POOL_SIZE >> PAGE_SHIFT;
+	linear_map_kf_hash_slots = memblock_alloc_try_nid(
+					linear_map_kf_hash_count, 1,
+					MEMBLOCK_LOW_LIMIT, ppc64_rma_size,
+					NUMA_NO_NODE);
+	if (!linear_map_kf_hash_slots) {
+		pr_err("%s: memblock for linear map (%lu) failed\n", __func__,
+				linear_map_kf_hash_count);
+		goto err;
+	}
+
+	/* allocate kfence pool early */
+	kfence_pool = memblock_phys_alloc_range(KFENCE_POOL_SIZE, PAGE_SIZE,
+				MEMBLOCK_LOW_LIMIT, MEMBLOCK_ALLOC_ANYWHERE);
+	if (!kfence_pool) {
+		pr_err("%s: memblock for kfence pool (%lu) failed\n", __func__,
+				KFENCE_POOL_SIZE);
+		memblock_free(linear_map_kf_hash_slots,
+				linear_map_kf_hash_count);
+		linear_map_kf_hash_count = 0;
+		goto err;
+	}
+	memblock_mark_nomap(kfence_pool, KFENCE_POOL_SIZE);
+
+	return;
+err:
+	pr_info("Disabling kfence\n");
+	disable_kfence();
+}
+
+static inline void hash_kfence_map_pool(void)
+{
+	unsigned long kfence_pool_start, kfence_pool_end;
+	unsigned long prot = pgprot_val(PAGE_KERNEL);
+
+	if (!kfence_pool)
+		return;
+
+	kfence_pool_start = (unsigned long) __va(kfence_pool);
+	kfence_pool_end = kfence_pool_start + KFENCE_POOL_SIZE;
+	__kfence_pool = (char *) kfence_pool_start;
+	BUG_ON(htab_bolt_mapping(kfence_pool_start, kfence_pool_end,
+				    kfence_pool, prot, mmu_linear_psize,
+				    mmu_kernel_ssize));
+	memblock_clear_nomap(kfence_pool, KFENCE_POOL_SIZE);
+}
+
+static inline void hash_kfence_add_slot(phys_addr_t paddr, int slot)
 {
+	unsigned long vaddr = (unsigned long) __va(paddr);
+	unsigned long lmi = (vaddr - (unsigned long)__kfence_pool)
+					>> PAGE_SHIFT;
+
+	if (!kfence_pool)
+		return;
+	BUG_ON(!is_kfence_address((void *)vaddr));
+	BUG_ON(lmi >= linear_map_kf_hash_count);
+	linear_map_kf_hash_slots[lmi] = slot | 0x80;
+}
+
+static int hash_kfence_map_pages(struct page *page, int numpages, int enable)
+{
+	unsigned long flags, vaddr, lmi;
+	int i;
+
+	WARN_ON_ONCE(!linear_map_kf_hash_count);
+	local_irq_save(flags);
+	for (i = 0; i < numpages; i++, page++) {
+		vaddr = (unsigned long)page_address(page);
+		lmi = (vaddr - (unsigned long)__kfence_pool) >> PAGE_SHIFT;
+
+		/* Ideally this should never happen */
+		if (lmi >= linear_map_kf_hash_count) {
+			WARN_ON_ONCE(1);
+			continue;
+		}
+
+		if (enable)
+			kernel_map_linear_page(vaddr, lmi,
+					       linear_map_kf_hash_slots,
+					       &linear_map_kf_hash_lock);
+		else
+			kernel_unmap_linear_page(vaddr, lmi,
+						 linear_map_kf_hash_slots,
+						 &linear_map_kf_hash_lock);
+	}
+	local_irq_restore(flags);
 	return 0;
 }
-static inline void hash_debug_pagealloc_alloc_slots(void) {}
-static inline void hash_debug_pagealloc_add_slot(phys_addr_t paddr, int slot) {}
-#endif /* CONFIG_DEBUG_PAGEALLOC */
+#else
+static inline void hash_kfence_alloc_pool(void) {}
+static inline void hash_kfence_map_pool(void) {}
+static inline void hash_kfence_add_slot(phys_addr_t paddr, int slot) {}
+static int __maybe_unused
+hash_kfence_map_pages(struct page *page, int numpages, int enable)
+{
+	return 0;
+}
+#endif
+
+#if defined(CONFIG_DEBUG_PAGEALLOC) || defined(CONFIG_KFENCE)
+int hash__kernel_map_pages(struct page *page, int numpages, int enable)
+{
+	void *vaddr = page_address(page);
+
+	if (is_kfence_address(vaddr))
+		return hash_kfence_map_pages(page, numpages, enable);
+	else
+		return hash_debug_pagealloc_map_pages(page, numpages, enable);
+}
+
+static void hash_linear_map_add_slot(phys_addr_t paddr, int slot)
+{
+	if (is_kfence_address(__va(paddr)))
+		hash_kfence_add_slot(paddr, slot);
+	else
+		hash_debug_pagealloc_add_slot(paddr, slot);
+}
+#else
+static void hash_linear_map_add_slot(phys_addr_t paddr, int slot) {}
+#endif
 
 /*
  * 'R' and 'C' update notes:
@@ -559,7 +692,8 @@ int htab_bolt_mapping(unsigned long vstart, unsigned long vend,
 			break;
 
 		cond_resched();
-		hash_debug_pagealloc_add_slot(paddr, ret);
+		/* add slot info in debug_pagealloc / kfence linear map */
+		hash_linear_map_add_slot(paddr, ret);
 	}
 	return ret < 0 ? ret : 0;
 }
@@ -940,7 +1074,7 @@ static void __init htab_init_page_sizes(void)
 	bool aligned = true;
 	init_hpte_page_sizes();
 
-	if (!debug_pagealloc_enabled()) {
+	if (!debug_pagealloc_enabled_or_kfence()) {
 		/*
 		 * Pick a size for the linear mapping. Currently, we only
 		 * support 16M, 1M and 4K which is the default
@@ -1261,6 +1395,7 @@ static void __init htab_initialize(void)
 	prot = pgprot_val(PAGE_KERNEL);
 
 	hash_debug_pagealloc_alloc_slots();
+	hash_kfence_alloc_pool();
 	/* create bolted the linear mapping in the hash table */
 	for_each_mem_range(i, &base, &end) {
 		size = end - base;
@@ -1277,6 +1412,7 @@ static void __init htab_initialize(void)
 		BUG_ON(htab_bolt_mapping(base, base + size, __pa(base),
 				prot, mmu_linear_psize, mmu_kernel_ssize));
 	}
+	hash_kfence_map_pool();
 	memblock_set_current_limit(MEMBLOCK_ALLOC_ANYWHERE);
 
 	/*
-- 
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/5c2b61941b344077a2b8654dab46efa0322af3af.1729271995.git.ritesh.list%40gmail.com.
