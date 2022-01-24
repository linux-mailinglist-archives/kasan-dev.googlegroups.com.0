Return-Path: <kasan-dev+bncBAABBXOUXOHQMGQEQKCISNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13c.google.com (mail-lf1-x13c.google.com [IPv6:2a00:1450:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 191224987B2
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 19:05:18 +0100 (CET)
Received: by mail-lf1-x13c.google.com with SMTP id s16-20020a056512215000b0042bd76cb189sf9415264lfr.6
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Jan 2022 10:05:18 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643047517; cv=pass;
        d=google.com; s=arc-20160816;
        b=vlUHkdsmXhTxJpdMjsRmdcdwrKklF7a+smAr/nFN6WESOrKcUSJT85Rr0XWBoGKkcU
         0gvoIxSHRL+0mR/laqDuhDJt96IwI0gg/HEJoHs7Xf1xoDu0nR+aVrLLFaBcPZGgGP9r
         Gh1tGsuQub1UyaQ06hy3/V/YqT8xNDqNQ6KdL438wrCqDUqttVgtRDt6xKm+SHLGDoGm
         cvwm0hsIqygAzouMNP7rb/JPYmY6QL8TZmIwgV9pwt/lA/8cbH78v8WaunSK+BelG2AT
         E0nwCUU0PchPyKBMqNWNMjtoelS9ntNrufUa3T/Tb9d8h4eiV2cBF0bOj5T8yFOcefic
         1s1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=5yLe9UF2TWmcY+tcdbWuipNWPFLHyXCOmLKE7V7aK0c=;
        b=Asw2H9G1KZ52LXz3UOEBnnK/erxelerQXHvexcAhQ8ki5jrHQkoARz52C9NeCVV3X6
         g8iVU4Ft16meSnLL7RC/khk5cvVVwY6f8ATCGC96icz+BeZnaSH5jsi4fjsjaoX5EByU
         uw4fHzUIF1hhCN6YBfyzU14HUXpo8wa2RErOoHW6xhMoPaxsflnOClgW7f2COYoz4BDY
         wbAw7tqPqQ46rPi3LjKq22uzc1ENI9KQq1DWfydUQ376IaJSTZj8KMu7Sb7+eu1b+4G+
         o4IcC0+R8c8E21Et86h/eIsn5ifSHlgaV/iyFGAa6z7F3XsFt0aGHJumjL+qGvR8k0V6
         g7OA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mOukMrCw;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5yLe9UF2TWmcY+tcdbWuipNWPFLHyXCOmLKE7V7aK0c=;
        b=Q8QTrIdTTX3fEmxYUaVv5WQb/yHzkYDhnxiR45QrD94kUAGmPHpSRbp4wfmwzW97Qq
         5+uidYzUH6zfdrV10RJBuqaZZ5OnfRLZX6z2mQZfn+1H01NlO6cIW9YMX7BvuD0TSKWH
         ASrl5UWu3pJIEPkR6NAhEHziVEnPQv+ZyVa3Ped15vT2q1EIv1FMSASkCkMXoZ/Ps4vV
         nQ6F3dvvyHaq/LZU+XmhAKTbcPaGRQs/Ajme75zPJIbMT+81I763xaGhLf69vt3VAC1r
         qLnG41BDQgnc0pf6Z6Dy4970uPzfZSDdlvJ1agEtv5dybfmsirf2CiZ1dUzth6m4C47f
         sYlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5yLe9UF2TWmcY+tcdbWuipNWPFLHyXCOmLKE7V7aK0c=;
        b=FR5jJ4HXZK4ly1HzZm5UuNFGB3bme5aGMyFIl4dUZnN/v00D4uT/2z6viAhBG4FSeJ
         yhO9e3sLPtIb19d/Pj2vR2w708E4WcQvAYXxG1WtkBdZXpztYiGAP7Yza44wlrPkHHhO
         Lr9baPz3H9hVQJmDEojQD9kcmGT/WWTTvhj3vgjA971DgDN2ipViYkLlwL58i9nlJ6Vs
         5iJRACuqNLyj27sNUYnUksyQITbgK35TjErvgBvF+h/PROA4pnPGE3rJS9HIBFmDldOc
         Ie/MLeU4WMggJWU/+gjkWgU4ISybKKCCTRaN9P8dsp/F+yEqJkNqkLb+sWl+am+mrzx+
         G1+g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531gNwT2UUaU2sNS56V2sKh0txVQpqeLQLbOGOo7SwP/YQWcca0j
	XGMGXxf+ax08DMK90j+tWj4=
X-Google-Smtp-Source: ABdhPJwHMV/SLTAwfAdUqqekIVCFrbJW70QXZAxt+jBgxv536IE3sHyz+WGnHTmrtC6G+q+iNnk3Lw==
X-Received: by 2002:a2e:c52:: with SMTP id o18mr11748065ljd.316.1643047517644;
        Mon, 24 Jan 2022 10:05:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:39b:: with SMTP id e27ls2478739ljp.6.gmail; Mon, 24
 Jan 2022 10:05:16 -0800 (PST)
X-Received: by 2002:a2e:5810:: with SMTP id m16mr2833465ljb.261.1643047516790;
        Mon, 24 Jan 2022 10:05:16 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643047516; cv=none;
        d=google.com; s=arc-20160816;
        b=NJrsQMFUp449ZtR1trEw3NU5PfBBv9B+7+8PfrlpWWXswhZRuwwXAKOKRkvaOvBi+k
         98okm5eIJxvrvmLT962XW/ADC3Jvwji3aq6Qbp90m8iUUT+HIBRDjfBonQc965BpmIDa
         oDrxeG7Xt9QwRX5RldImVm7imNRskWw3qqU+Ox94BQZ9W8wCwYE+lV2F8qrWCe78M5gs
         6YftqrAjp0ho0A2nDSMkX7Pi4YOHswgPKDOqLuJrJPBQWxfQGx7RyiiE0TgoqW3UbMRw
         W3HSKnta5jEG+X2imjTVTlb4t6gzkvItgtE1avsctzFgJK6uYfBSJjW7s+eyDgxpQXTr
         w16w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=iv75xpnJ8+Bgf1s/8WPLdoQRfEIPCrP2FWtA7xyhnY4=;
        b=PZlRizsiawxCT+2/AFLnwRtvXkwrnAkJyGAamYgi1mrUKBxHBEnXsM12mqkJ/Uo9N6
         bkIbomNetA7SOCQd0PMaCv0gpBrGpiksLit3m29QiYb/beGlQGqzWx5afl22wV+JJtXu
         AQXktetFlIt4CK7aNFYP75jx1H4KX467+R7IZEzuVfFRuggjdmq+n13HKGLDy7DRGsS/
         xEbSuMQpiPGZOB8u55FbCVSNxjzGDVMS9VkXixOUYkT+RYlj56KN3i5jUcEvXmuKz9Jr
         5JZ+hsPiLAhgG6Ax6Ye0niHLlhtx5LVAqSyV6xSx10HO0Lrru9206HUrthNikvw3Q/x1
         lQNw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=mOukMrCw;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out2.migadu.com (out2.migadu.com. [188.165.223.204])
        by gmr-mx.google.com with ESMTPS id u2si580801lfq.10.2022.01.24.10.05.16
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 24 Jan 2022 10:05:16 -0800 (PST)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 188.165.223.204 as permitted sender) client-ip=188.165.223.204;
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
Subject: [PATCH v6 17/39] kasan, x86, arm64, s390: rename functions for modules shadow
Date: Mon, 24 Jan 2022 19:04:51 +0100
Message-Id: <36db32bde765d5d0b856f77d2d806e838513fe84.1643047180.git.andreyknvl@google.com>
In-Reply-To: <cover.1643047180.git.andreyknvl@google.com>
References: <cover.1643047180.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Migadu-Auth-User: linux.dev
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=mOukMrCw;       spf=pass
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
index 4165304d3547..b6712a25c996 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/36db32bde765d5d0b856f77d2d806e838513fe84.1643047180.git.andreyknvl%40google.com.
