Return-Path: <kasan-dev+bncBAABBZUJXCHAMGQEBVQCMTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x438.google.com (mail-wr1-x438.google.com [IPv6:2a00:1450:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id EBE18481F95
	for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 20:13:42 +0100 (CET)
Received: by mail-wr1-x438.google.com with SMTP id w25-20020adf8bd9000000b001a255212b7csf6496677wra.18
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Dec 2021 11:13:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640891622; cv=pass;
        d=google.com; s=arc-20160816;
        b=BNjlVi9Ek5+16aRvav7LRiRZpQyUJMFndrKNpaksZRegr36bgWE5aFgt6KYN0DiDCH
         tDtJwv6zqK9mENa9PgYTpM4QJNgbBKOMd+XZjOO/hG1sVetg0Worvpby+9NGEwf0SIQN
         Cgpn93PHMvEd9q4n5nnCq4ODjVYKkaz5sSHsHZbYNtXp8JCo0aLU8vvTvezyH92MsiBR
         Wvyl1/JRdhErdf7/OflSGxEpmhzHh1aCqEJ3UJkXKKCwF0IsjFKJ6/I2y0sZp8qiHf99
         peWcK2Z11eGcHf7T7iZbRoBBzOUs/RSq3ZZveCvc931Kt75Adf2SNRGLsAqm8baeV79r
         Ptdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=+PUKmRjWCSOvXBBaAw1rbKXQtcIPsXDl5eNKsOoTSyQ=;
        b=ujjeUf5xaP3hkIqNBtVVqZFzD0+yWnw5GKJDMeGqHzknYAKwA8g5ZuPP26rdm4EfVn
         unq68njGfsNc+XLMP4ZFbluJJUcLU1NvcJQOH9lnHd9xsm8lUIjX9WRnr8ktdF/BUftt
         lsNkd4qpcr4soIibaec+wjq6qarardZ/hYCGJ2YeZVC7JJw44/e+kXnvIC6GTlApHEiR
         dDw3uVgPMQuG4qy/SSen/X+oYPuoFCFfD9/IEbJB9D4Vkasw2SzxnzrSvXqR/YMq88Np
         089okEJRfCeyovmte5EfFK3M2Gs+b0yuj+J1HshBCH1n37taDTfcDH+MXzLveSbhlPjQ
         Ayww==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=WlMFm6Wh;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+PUKmRjWCSOvXBBaAw1rbKXQtcIPsXDl5eNKsOoTSyQ=;
        b=NC+9JY4XcXUgN4URhsOwefuft+/U83+reXoJ4KWrWIywLcalAj9mIYCU+FSbCgHfGR
         +jUUSvqRPpDNzajNHxl0okLTEncBqovhC9MaXL8jLGuiJqhsFAw2U0levwyxI/CoyUQy
         TzJ0KFB1QN1j8+o70Msxy0iBaYJiW/8bAuFtVvi/M892WYq+lPPVgvwLWsT1QkaJU5cp
         1spO1e5Ae4ba8ej+JI160hLYaP5uCpwC7gGxMfdKSr5pmv26ATaDgA5KApyppiZ0bINC
         yjEY2iQ3hxOKLAWTad7XVCHxK/5cr4NddRc8e09uMQQ8m3mKCCpxAsb9VjfgHSSROUgz
         AoEg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+PUKmRjWCSOvXBBaAw1rbKXQtcIPsXDl5eNKsOoTSyQ=;
        b=2U1opxkmyhLmai7YOvXW7vlhDgvFistA67HmfoTKhG0HxMLAgqcWfjxQWaMai2hWtW
         3gar5+v0/LotFE/UljoH2VAZv6E/KWp9ucWPUNaVCIscsXDaToLUdMEWuPqmOYxf7qk3
         HoclnB4IB4dcIJkWQApCePZmcmCuYmrXbescVx8AaBFbEcCp8wSmntACVwEjHQJYUMQ7
         EePscgCybryaBGpUrK1Gkw6rJvt4V/ew60vaRytUcd/QkD2/GLAb/PEZX4hKHeyjYrto
         zZ0mDEyQgU4r5wyGAkeohiZ43jZxZNVok96doF6kBm261QUSrbaiWD+LwYWBXrD4gIbj
         JNKg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Ijn13BY+gfE3wKW0Kco1jH7WSSp6A8zndmZkrnwXMB7goHKsN
	TtoVEmW3jClsHnM5UStGUJw=
X-Google-Smtp-Source: ABdhPJxQAyLKAGy5H4wr4AB1sgZI4MfYpAgm7Rcfuk7pbXIEdMTSYsmLAzSjkyo6NLPeOeULDTWlPA==
X-Received: by 2002:a5d:4568:: with SMTP id a8mr27003382wrc.471.1640891622692;
        Thu, 30 Dec 2021 11:13:42 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:a4cc:: with SMTP id h12ls299009wrb.2.gmail; Thu, 30 Dec
 2021 11:13:42 -0800 (PST)
X-Received: by 2002:a5d:4450:: with SMTP id x16mr25768920wrr.95.1640891622004;
        Thu, 30 Dec 2021 11:13:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640891622; cv=none;
        d=google.com; s=arc-20160816;
        b=QU8j1zb3XEVBlDJYw/SI01q3Nku4S9TM/ZAJaGaWKRU5l8x+eIpvClQ+kDzFie4G81
         Tn4te0z/gevwZ7XsfBJAHy+9iG0OvoK7lcw+kEemN+0zl5oU/jfkPVwsNB3WYFlri589
         z6KsPs1lo5ziQqZRQy5F47ekiVT0VyybHNLCHM8nYqzKaPFeQheqv2ObX7YZ6JhtDgfQ
         gVGoAFQ5V0TN5MMVjLT9yAATdNAIW4gIfyTqdhS+eCtLOgQxphUkKAdsGoaeJQSZX4am
         HdUKqb28k/jNEjoDV0VxsR+fYE92ofThzWiy0Pd17R9jrPNboKvSTVbc0JAlufXkAFas
         wg4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5F662mQuyZrkqe4hrthBRUYJbZYsnvhmVcSPgqbXtac=;
        b=fMQicSSvOiJYPPZzQrCEvysynFn3U/Tw+PW7cUbYmYs+Td3gqbK/KlgTH2ufs0NhvZ
         IfKMvlT56QGFiIEv9jDL/eP+I9s5+EG331Dcvbg+KODpbC5UUmNPm8K9/zWSt+gzRn+b
         LL50zOLJUSYD1iWlLnGh2pgXbGg8LstnK3v65GPTTicaaxMOJBu1TfPqfBQcVSK5QFDe
         BqSRyLOpcfPRAtEefpHncggj+2QtfOcpsE/Q52u/2MTxfX9mwq3W95t5WnAUcja/LHb/
         OfSQueKU8C4uhQfz2RxSVUl0qVUaozNhsHkgmE+45muTRFzFFI9hGxgCcQmOzGdt8QHX
         Ai3A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=WlMFm6Wh;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:2:267:: as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out0.migadu.com (out0.migadu.com. [2001:41d0:2:267::])
        by gmr-mx.google.com with ESMTPS id d15si1182362wrw.2.2021.12.30.11.13.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 30 Dec 2021 11:13:41 -0800 (PST)
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
Subject: [PATCH mm v5 17/39] kasan, x86, arm64, s390: rename functions for modules shadow
Date: Thu, 30 Dec 2021 20:12:19 +0100
Message-Id: <7c9eaa4a3afd5874727e69ea799cecf53b4bc2c0.1640891329.git.andreyknvl@google.com>
In-Reply-To: <cover.1640891329.git.andreyknvl@google.com>
References: <cover.1640891329.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=WlMFm6Wh;       spf=pass
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

Rename kasan_free_shadow to kasan_free_module_shadow and
kasan_module_alloc to kasan_alloc_module_shadow.

These functions are used to allocate/free shadow memory for kernel
modules when KASAN_VMALLOC is not enabled. The new names better
reflect their purpose.

Also reword the comment next to their declaration to improve clarity.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
---
 arch/arm64/kernel/module.c |  2 +-
 arch/s390/kernel/module.c  |  2 +-
 arch/x86/kernel/module.c   |  2 +-
 include/linux/kasan.h      | 14 +++++++-------
 mm/kasan/shadow.c          |  4 ++--
 mm/vmalloc.c               |  2 +-
 6 files changed, 13 insertions(+), 13 deletions(-)

diff --git a/arch/arm64/kernel/module.c b/arch/arm64/kernel/module.c
index 309a27553c87..d3a1fa818348 100644
--- a/arch/arm64/kernel/module.c
+++ b/arch/arm64/kernel/module.c
@@ -58,7 +58,7 @@ void *module_alloc(unsigned long size)
 				PAGE_KERNEL, 0, NUMA_NO_NODE,
 				__builtin_return_address(0));
 
-	if (p && (kasan_module_alloc(p, size, gfp_mask) < 0)) {
+	if (p && (kasan_alloc_module_shadow(p, size, gfp_mask) < 0)) {
 		vfree(p);
 		return NULL;
 	}
diff --git a/arch/s390/kernel/module.c b/arch/s390/kernel/module.c
index d52d85367bf7..b16bebd9a8b9 100644
--- a/arch/s390/kernel/module.c
+++ b/arch/s390/kernel/module.c
@@ -45,7 +45,7 @@ void *module_alloc(unsigned long size)
 	p = __vmalloc_node_range(size, MODULE_ALIGN, MODULES_VADDR, MODULES_END,
 				 gfp_mask, PAGE_KERNEL_EXEC, VM_DEFER_KMEMLEAK, NUMA_NO_NODE,
 				 __builtin_return_address(0));
-	if (p && (kasan_module_alloc(p, size, gfp_mask) < 0)) {
+	if (p && (kasan_alloc_module_shadow(p, size, gfp_mask) < 0)) {
 		vfree(p);
 		return NULL;
 	}
diff --git a/arch/x86/kernel/module.c b/arch/x86/kernel/module.c
index 95fa745e310a..c9eb8aa3b7b8 100644
--- a/arch/x86/kernel/module.c
+++ b/arch/x86/kernel/module.c
@@ -78,7 +78,7 @@ void *module_alloc(unsigned long size)
 				    MODULES_END, gfp_mask,
 				    PAGE_KERNEL, VM_DEFER_KMEMLEAK, NUMA_NO_NODE,
 				    __builtin_return_address(0));
-	if (p && (kasan_module_alloc(p, size, gfp_mask) < 0)) {
+	if (p && (kasan_alloc_module_shadow(p, size, gfp_mask) < 0)) {
 		vfree(p);
 		return NULL;
 	}
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index b88ca6b97ba3..55f1d4edf6b5 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -454,17 +454,17 @@ static inline void kasan_populate_early_vm_area_shadow(void *start,
 		!defined(CONFIG_KASAN_VMALLOC)
 
 /*
- * These functions provide a special case to support backing module
- * allocations with real shadow memory. With KASAN vmalloc, the special
- * case is unnecessary, as the work is handled in the generic case.
+ * These functions allocate and free shadow memory for kernel modules.
+ * They are only required when KASAN_VMALLOC is not supported, as otherwise
+ * shadow memory is allocated by the generic vmalloc handlers.
  */
-int kasan_module_alloc(void *addr, size_t size, gfp_t gfp_mask);
-void kasan_free_shadow(const struct vm_struct *vm);
+int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask);
+void kasan_free_module_shadow(const struct vm_struct *vm);
 
 #else /* (CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) && !CONFIG_KASAN_VMALLOC */
 
-static inline int kasan_module_alloc(void *addr, size_t size, gfp_t gfp_mask) { return 0; }
-static inline void kasan_free_shadow(const struct vm_struct *vm) {}
+static inline int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask) { return 0; }
+static inline void kasan_free_module_shadow(const struct vm_struct *vm) {}
 
 #endif /* (CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) && !CONFIG_KASAN_VMALLOC */
 
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 94136f84b449..e5c4393eb861 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -498,7 +498,7 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 
 #else /* CONFIG_KASAN_VMALLOC */
 
-int kasan_module_alloc(void *addr, size_t size, gfp_t gfp_mask)
+int kasan_alloc_module_shadow(void *addr, size_t size, gfp_t gfp_mask)
 {
 	void *ret;
 	size_t scaled_size;
@@ -534,7 +534,7 @@ int kasan_module_alloc(void *addr, size_t size, gfp_t gfp_mask)
 	return -ENOMEM;
 }
 
-void kasan_free_shadow(const struct vm_struct *vm)
+void kasan_free_module_shadow(const struct vm_struct *vm)
 {
 	if (vm->flags & VM_KASAN)
 		vfree(kasan_mem_to_shadow(vm->addr));
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index 9bf838817a47..f3c729d4e130 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2526,7 +2526,7 @@ struct vm_struct *remove_vm_area(const void *addr)
 		va->vm = NULL;
 		spin_unlock(&vmap_area_lock);
 
-		kasan_free_shadow(vm);
+		kasan_free_module_shadow(vm);
 		free_unmap_vmap_area(va);
 
 		return vm;
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/7c9eaa4a3afd5874727e69ea799cecf53b4bc2c0.1640891329.git.andreyknvl%40google.com.
