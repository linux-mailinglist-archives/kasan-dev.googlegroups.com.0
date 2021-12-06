Return-Path: <kasan-dev+bncBAABBCMJXKGQMGQEYCFXD7I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A28846AABD
	for <lists+kasan-dev@lfdr.de>; Mon,  6 Dec 2021 22:45:46 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id k25-20020a05600c1c9900b00332f798ba1dsf199817wms.4
        for <lists+kasan-dev@lfdr.de>; Mon, 06 Dec 2021 13:45:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1638827146; cv=pass;
        d=google.com; s=arc-20160816;
        b=PgAGaxIdLUaKjFgc1p2VtJLQuifsYpZJQOu9nEEjWaOp2P3347kjXNE2w4birQd/cF
         jKKKVr6L9laxqy3+S5L+8ps4JFnyRTq1LG+buc3KY1iIlsNOJFU5/WC8fyoI/GeW09Te
         cctYZ9wx6mgeM1Ar/eZbu3Nj3G7vxNAPDue134JVIksTIPNj0HfTF4tV4a8D7pPAnlnP
         xo+KnjMP9CN90UfivegQbLLg1Lc2o1sNs47ZJpQfcg76UkkQcMl6QEfFCMP4yr0IuGoG
         QhoA0VAXSdi5X/6xCjb7BVzSvvCGDa3Y1DT4O6Qpivn64yibp7ukAejXBe9XmP7vrnT+
         fwtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=k2FOHHLxAXNzC/rFfYMnZMGguCEPpLe/AmELUtxnejk=;
        b=N9oxQVPdZjWiBUcQlz3knbR2MrDclgAmhOILifAAmwY5LLitO710wTWDWym5Skz7Zw
         VLeJ0aXNEcOxoWp2v84UFzT+1Okdiso+P1shCgQo/+hqe4VWJ/HpTDo0t1v49klgKkOO
         L+3G1vCe2dnwHM7JAb7dQ+qd21wmvPvAYeoGAEMN97bXfa1VEacG3DO/fwrIrhhZDxxr
         24eZfKlUMGBu6/mF7juXMH+HSX/dOtyJ47zKu9gY6DsgWtyxmnw48zvpEOaTIpid44sZ
         LOzh/PFiTbtHBmR4O5D5yS84groGEa2s+ki5og9mBI1+wZl7M03ZmMsWakJLXqBtAO3k
         +hkw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="d7P/LxHy";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k2FOHHLxAXNzC/rFfYMnZMGguCEPpLe/AmELUtxnejk=;
        b=Rheu+08ZSJtq0K86mXABDRihxl0oVBo1wJwBa1UBEyKYIoaNR3s10o+9NKrhmjghX1
         mJ8K6z9c0vU3eSSPH+5Oe5ydfV69aqcQ9yLy9pKMFVQMajFl5rxNKnlxx0C3dO884yMF
         SWCT1rg/BM437FDTJJuRz7OeYAzkbGlRzw24T3tjgOyS1kQuYHlFNVLbjOkG81wGHQIi
         XGtYHLCdS7rujSrg58MOCDkKWKJ/UQWXV/cAqBv1F0bnUiPwpHO+2XB/3Qj7qT4JCDYX
         f+HmSWcYreK2XYY3PTTCCZQfjcNfQAO+idWPI1PGKNlqu9uGJndxl7zIQN2XctOs4NQu
         WA4w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=k2FOHHLxAXNzC/rFfYMnZMGguCEPpLe/AmELUtxnejk=;
        b=XSHrajA3ZOP0wndhQQtbvk3dg635Arb/GjxV3gv4abrOD1Msxpea2NIY3EhIHSkcoP
         W+DadRUtW/0aquQ56twDoaYLV88nv7pWlxJgVXiSodIlO7ItgtHswBMdc8g9BN703NCQ
         RCbsG0zHR619uW2SJEbnmFlwztihhCqKJvkz92H841UDQl3ZEMrB8Wf7Npi7wnDqjEyZ
         gZ2V0rbGHZJ66HLTjDM0cmYLYZyQ0plvJhsEugyxAliC4/9fL1z9LQkbdWIu3/sMrjxL
         nSQEMRLOURwJwDICEAJMUnCGFg9aUO2eXzDF2zcSANrE+CZatgJ/vzh/AeHb8bjbmr8u
         CWGQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533tO2PFn0KzKuUjBj+NLVYwRAclnvDU6hzQ0hLKeshaRxxzcqEF
	fmuAL+c5SWijkR9IkFJb4vY=
X-Google-Smtp-Source: ABdhPJwq/z/a9Uw0uo9YkT5tAIrIpZEXE7iI8KhTfJ/rOoQYQtDwjwannoQt5wiKLJ4/o6mYUsplVQ==
X-Received: by 2002:a1c:a503:: with SMTP id o3mr1594860wme.98.1638827145979;
        Mon, 06 Dec 2021 13:45:45 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:fe0b:: with SMTP id n11ls1149170wrr.0.gmail; Mon, 06 Dec
 2021 13:45:45 -0800 (PST)
X-Received: by 2002:a5d:5186:: with SMTP id k6mr45965652wrv.146.1638827145377;
        Mon, 06 Dec 2021 13:45:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1638827145; cv=none;
        d=google.com; s=arc-20160816;
        b=y8xy9PWd15jt+6aOEC+LfWQwipBlBKPJ6gOnXIudL5KDqx5vCKHpMLYmi/7igtRVPk
         RnHadDKzgZlVHumVVBTKpnjwo+9EAzmvQWgVw9vDaGP9xt57t5zWM008U4PgdLUTWWB5
         Cho8guhuuNkqdi5LerWjZgwJdygAbRCwYrayk8awutvsHp6sQ/Aock1Vs6RlG2uW7R3P
         cQ9kw7oXw8Vd5JBFdwUyb8qeqhH7HTlCEc26YNvc1gVHiGp2dXOVckWTEzUinBXNa3TV
         UIUihYU/ko9gLkYDUyFbcfaX0fz+RCb9rGGF4N8pHbj6GEvYJ5nQYV6ZRLQEHeTVBbi9
         k3lw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5vrmXGtyQkXmrhoONS3mEv98+EJ5a6iWSXEuOfvldi8=;
        b=J9V8943jQLweJCEGmfVOjIkcWkgBuV3yL72AYrTETXCuomMT8lfrpX37WtI4BkILAT
         Osrlv5qgI+C5mXAteIvQ8jA2PcphOznrilFP3yT/iQYIinQB48/03IKVV/KBKtksW7M9
         x5xDUQqTin44UThqT0KX4qtjKPtaY8L5Ye4peOIUT/VXYLqwVR7w3XvhfgcLmndu8nBZ
         6PSshNgDrCxFsArHMHT/zvBV7XpHGwi+/p7UhMOuEkJs4Y9Wvf4nqD7uY8MH854nlh+d
         /xICbJjDcFivBFlwsUH9z7t5p3qF6Ucclk7Ow5wbS4XtQIji4NxPnbMTZX0kyF/p1v1g
         EYOQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b="d7P/LxHy";
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id d9si521637wrf.0.2021.12.06.13.45.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 06 Dec 2021 13:45:45 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	Peter Collingbourne <pcc@google.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Will Deacon <will@kernel.org>,
	Mark Rutland <mark.rutland@arm.com>,
	linux-arm-kernel@lists.infradead.org,
	Evgenii Stepanov <eugenis@google.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 17/34] kasan, x86, arm64, s390: rename functions for modules shadow
Date: Mon,  6 Dec 2021 22:43:54 +0100
Message-Id: <11f5a6419f8830fdedc84dca5f847543ef7960f4.1638825394.git.andreyknvl@google.com>
In-Reply-To: <cover.1638825394.git.andreyknvl@google.com>
References: <cover.1638825394.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b="d7P/LxHy";       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204
 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
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
---
 arch/arm64/kernel/module.c |  2 +-
 arch/s390/kernel/module.c  |  2 +-
 arch/x86/kernel/module.c   |  2 +-
 include/linux/kasan.h      | 14 +++++++-------
 mm/kasan/shadow.c          |  4 ++--
 mm/vmalloc.c               |  2 +-
 6 files changed, 13 insertions(+), 13 deletions(-)

diff --git a/arch/arm64/kernel/module.c b/arch/arm64/kernel/module.c
index b5ec010c481f..f8bd5100efb5 100644
--- a/arch/arm64/kernel/module.c
+++ b/arch/arm64/kernel/module.c
@@ -58,7 +58,7 @@ void *module_alloc(unsigned long size)
 				PAGE_KERNEL, 0, NUMA_NO_NODE,
 				__builtin_return_address(0));
 
-	if (p && (kasan_module_alloc(p, size) < 0)) {
+	if (p && (kasan_alloc_module_shadow(p, size) < 0)) {
 		vfree(p);
 		return NULL;
 	}
diff --git a/arch/s390/kernel/module.c b/arch/s390/kernel/module.c
index b01ba460b7ca..a753cebedda9 100644
--- a/arch/s390/kernel/module.c
+++ b/arch/s390/kernel/module.c
@@ -44,7 +44,7 @@ void *module_alloc(unsigned long size)
 	p = __vmalloc_node_range(size, MODULE_ALIGN, MODULES_VADDR, MODULES_END,
 				 GFP_KERNEL, PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE,
 				 __builtin_return_address(0));
-	if (p && (kasan_module_alloc(p, size) < 0)) {
+	if (p && (kasan_alloc_module_shadow(p, size) < 0)) {
 		vfree(p);
 		return NULL;
 	}
diff --git a/arch/x86/kernel/module.c b/arch/x86/kernel/module.c
index 169fb6f4cd2e..dec41d9ba337 100644
--- a/arch/x86/kernel/module.c
+++ b/arch/x86/kernel/module.c
@@ -77,7 +77,7 @@ void *module_alloc(unsigned long size)
 				    MODULES_END, GFP_KERNEL,
 				    PAGE_KERNEL, 0, NUMA_NO_NODE,
 				    __builtin_return_address(0));
-	if (p && (kasan_module_alloc(p, size) < 0)) {
+	if (p && (kasan_alloc_module_shadow(p, size) < 0)) {
 		vfree(p);
 		return NULL;
 	}
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 1031070be3f3..4eec58e6ef82 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -453,17 +453,17 @@ static inline void kasan_populate_early_vm_area_shadow(void *start,
 		!defined(CONFIG_KASAN_VMALLOC)
 
 /*
- * These functions provide a special case to support backing module
- * allocations with real shadow memory. With KASAN vmalloc, the special
- * case is unnecessary, as the work is handled in the generic case.
+ * These functions allocate and free shadow memory for kernel modules.
+ * They are only required when KASAN_VMALLOC is not supported, as otherwise
+ * shadow memory is allocated by the generic vmalloc handlers.
  */
-int kasan_module_alloc(void *addr, size_t size);
-void kasan_free_shadow(const struct vm_struct *vm);
+int kasan_alloc_module_shadow(void *addr, size_t size);
+void kasan_free_module_shadow(const struct vm_struct *vm);
 
 #else /* (CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) && !CONFIG_KASAN_VMALLOC */
 
-static inline int kasan_module_alloc(void *addr, size_t size) { return 0; }
-static inline void kasan_free_shadow(const struct vm_struct *vm) {}
+static inline int kasan_alloc_module_shadow(void *addr, size_t size) { return 0; }
+static inline void kasan_free_module_shadow(const struct vm_struct *vm) {}
 
 #endif /* (CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) && !CONFIG_KASAN_VMALLOC */
 
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 4a4929b29a23..585c2bf1073b 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -498,7 +498,7 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 
 #else /* CONFIG_KASAN_VMALLOC */
 
-int kasan_module_alloc(void *addr, size_t size)
+int kasan_alloc_module_shadow(void *addr, size_t size)
 {
 	void *ret;
 	size_t scaled_size;
@@ -529,7 +529,7 @@ int kasan_module_alloc(void *addr, size_t size)
 	return -ENOMEM;
 }
 
-void kasan_free_shadow(const struct vm_struct *vm)
+void kasan_free_module_shadow(const struct vm_struct *vm)
 {
 	if (vm->flags & VM_KASAN)
 		vfree(kasan_mem_to_shadow(vm->addr));
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index d2a00ad4e1dd..c5235e3e5857 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -2524,7 +2524,7 @@ struct vm_struct *remove_vm_area(const void *addr)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/11f5a6419f8830fdedc84dca5f847543ef7960f4.1638825394.git.andreyknvl%40google.com.
