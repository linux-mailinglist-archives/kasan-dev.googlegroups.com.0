Return-Path: <kasan-dev+bncBAABB47ZQOHAMGQE5TS2RFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x338.google.com (mail-wm1-x338.google.com [IPv6:2a00:1450:4864:20::338])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E25F47B588
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 23:00:20 +0100 (CET)
Received: by mail-wm1-x338.google.com with SMTP id bg20-20020a05600c3c9400b0033a9300b44bsf553671wmb.2
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 14:00:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640037620; cv=pass;
        d=google.com; s=arc-20160816;
        b=maiWdPe39NiebSLymbKj5kY48pxG2bB2gTDAs0OGZtwBKGk4AHp5tupM3tPJYFKJLS
         sPuxideVvkbsmDVd0uXAQxQt3Pa4e0lQEeZlRVnFQDXfSGdAhYQlW0UAb5et1OocRFkT
         8P3qin4J6ae9rPO3CKo4OQJBkKmZ7z2AhzYKT5e2Rb2Of3ZukNQbbXnYFZukHPitkOg1
         BMZR2W98pe+19QP/wCAxkxV/J9SlyfkhuB2EfRC+vetwF5QUtxFmK8EocuS0A7GKAE22
         hwMiSNZcIGNdSfv4ggJSgkhwCCrnUJ9QFiYfjZHOX8knnvrpzXVsWyhVBlsrgxt1PdSW
         bFxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=o2tmzBFngGW80705HgBQ3D0nSttsCJ/dXRbcReaVkPM=;
        b=kEXdvUGdbr5sbBrva89/i+lCH8Szt7JeeVB/TPmhu3z2kjY6+O0OwAG3JBz5yY3xV5
         QTKfSd7PYSOtz62mb0AkSbeOfKBBqhBr0wJh8P0FlFWEnRS3PSQBseNGlscyU1gLr1ul
         vvHD636GCw0oHnZCVuLe5HzUh3PV0sqhDQcCpH6Z74Qz4TbjjbMbvjOt02fOqj+GrIht
         fsztaIUR/tJplQn9P/1YrtB72ME9wj+5lwOasNpCyOF22REhkZd4Vv4io1BZ25PWimoh
         +HlS5DJd7heiTQ48tEUl162hzLzKC9h5MTSz5BY5gDi1srQXdM7qvcz3PtpEuF8kwEkl
         xnMA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=gXn8zAPL;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o2tmzBFngGW80705HgBQ3D0nSttsCJ/dXRbcReaVkPM=;
        b=Gkz/YnmSSMeSmId2cWacYWsgFkFR6xODijyyHV4EKRjTDV9w7gmuODamc6k1WXb1Bw
         IOIy5ZldDBvunsfpfy/uU6J4oe1FoC7MODJSjRwM0NuAvj+DG3Q8xeB+wChiB+3qsHCt
         vHVQFl7a1TUxWRF1104yHJZ/vQUHoOvYv3cRY8lVowuPXFMUz2M3fsJcJJrPj5K+F9KJ
         OQSzooJ8xKsVoQIU43/DAYORr/EXPBDH/vPEOn0lidYNY49FJuiH3zaQ+g8qxeOAUdJo
         r9W8oET6IoVMV8OCHufXmDvIkAp6BAkYHVHZGdg43AXv1EvuXqnaysi3itxY2Nt7iAX1
         WA2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=o2tmzBFngGW80705HgBQ3D0nSttsCJ/dXRbcReaVkPM=;
        b=uC8AEkhN5wbqgqY8yvKwsfHFyvH3JxeSrX6Yrp9RvRvS02VurJsn3Kw6rVfnfVfhMP
         Q+AHoOqFURCeXrbLz+2CEZ8Sur5TyuyND1flH3Q/5ErbEQNP0WTTKklKm6r6/SLtaHo2
         VDdzSXkGSuTJWoqY7c3nRC+FYEafUDseIjwdLUMSuEIZY84HFxcOz31MuB1BPoUhP00D
         fpaB9c/7rbuD1F8ZTTI9jsNqBV1mUSuEj92Qr5yTDh44uv+XR8q2G9QS0kGDHA6pkK8l
         do5qZMKC9s+EqtVrYP4Ta5xHZIpZxqnsxqQgpJQ7979mvJbp+C4zTJ495om/waj2NDLW
         0gQQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530eTuoHczZcPGSa+bl2L8NTnViZIAUMd8gYwx4cfCbYK9qncR8t
	p4RiA14gDfbccllHulrEPag=
X-Google-Smtp-Source: ABdhPJw95vr+9gCtzi63LN92dQv0h39Wf1R7uwQlckfbatC08QAVUg1iAYkySGLnzujjNHnyEqL5sA==
X-Received: by 2002:a05:6000:1a41:: with SMTP id t1mr95431wry.261.1640037620127;
        Mon, 20 Dec 2021 14:00:20 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:ca47:: with SMTP id m7ls235162wml.3.gmail; Mon, 20 Dec
 2021 14:00:19 -0800 (PST)
X-Received: by 2002:a1c:f609:: with SMTP id w9mr33421wmc.99.1640037619443;
        Mon, 20 Dec 2021 14:00:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640037619; cv=none;
        d=google.com; s=arc-20160816;
        b=UMJ7RTlQYHCfq15bspBf18YP7t8Udzd1rzvjoNpJFkgGNl7PeUrc3xdhtsQ5GjyRsr
         gOeFGeU7K8WEhT+PzWzVGNF5LuA6WTKFDmtV1DAegvUiJotfotex+KC4hivklJWxy/b6
         Cj5KhQfUMnKsyD0z9hm4WHz5wBttYp9FuqQZI/COch+wStvUbeFdGTiWImXBUxsUXFJc
         2TuCgqW7dlmo4G/L9fs7wTj41FcUNHTDNuervNUu3rohdkupKHLRNfZsAnZhZ8l7QGo6
         OGV5Vla76StVcVmvI2Nxd1W/uGvJ4OdzCyvZEEN29yhJ17kY+sgIBpnvdt4j4epsyUFm
         Js5w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=clbwNiEdodHr8oU8gA1KlS9psTCZ+RadAtlc0DLpWew=;
        b=k0xTxNOTO/ieIPKazDbkj/AucSNvWTndE6Jyje0wMGaHrGl1mRSs7XVY+8XTIBR8i5
         hnYc21hbsSF2z4akWhJPKT1upFekBm3ghgeq5xI+8VTul61eKmhYiFb9DFFazujOTh7g
         LWnCfnytzwZQPo5xk5ROw/qe4P2UOY/WzsT1Bf97yYbsDmTU6xDgVo2GOJIss5KZOkyU
         aQ2BA499FIpmC6o+oVylI+MoJM6+AKa+K66Pyj/tLe8YHGjNEk72JjBHeqjkS7Kh+ZGv
         zp8Ijy3D8aOlMV0nJC3bJEemQZ5tgLaBmguIMQAsNe7edMPcrnCeCurleDYc2HkDYpoV
         42wQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=gXn8zAPL;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out1.migadu.com (out1.migadu.com. [91.121.223.63])
        by gmr-mx.google.com with ESMTPS id d15si781880wrw.2.2021.12.20.14.00.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 20 Dec 2021 14:00:19 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as permitted sender) client-ip=91.121.223.63;
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
Subject: [PATCH mm v4 17/39] kasan, x86, arm64, s390: rename functions for modules shadow
Date: Mon, 20 Dec 2021 22:59:32 +0100
Message-Id: <84de4863847a3aa21e2b6e9f64683d05a4f0c773.1640036051.git.andreyknvl@google.com>
In-Reply-To: <cover.1640036051.git.andreyknvl@google.com>
References: <cover.1640036051.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=gXn8zAPL;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 91.121.223.63 as
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
index eb6e527a6b77..10011a07231d 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2525,7 +2525,7 @@ struct vm_struct *remove_vm_area(const void *addr)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/84de4863847a3aa21e2b6e9f64683d05a4f0c773.1640036051.git.andreyknvl%40google.com.
