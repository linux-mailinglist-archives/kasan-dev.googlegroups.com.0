Return-Path: <kasan-dev+bncBCRKFI7J2AJRBW4P52GAMGQEWOFBPPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3e.google.com (mail-oo1-xc3e.google.com [IPv6:2607:f8b0:4864:20::c3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EDCD458E05
	for <lists+kasan-dev@lfdr.de>; Mon, 22 Nov 2021 13:06:53 +0100 (CET)
Received: by mail-oo1-xc3e.google.com with SMTP id v2-20020a4ae6c2000000b002c622008d77sf9591223oot.12
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Nov 2021 04:06:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637582812; cv=pass;
        d=google.com; s=arc-20160816;
        b=anejmvpmCRqmpvDcrOES9Se3dwxr4aPzVsamAu7fNds/Hjq3A+zX9sLQ4rrII2d3o+
         ViySa5oDlbwHSPf2+hk9BRU8YGj6N6Jr2Bywi9Aro8zvt5XM4XR/Zgmv+7kKItIaqErm
         /xaG5F2bjuPera42GUoevzA3Op4R/hBZWBSHZrascctzD5AA/SyqbKgKfIJccfoeD5ug
         OkZWDQ2vQeOO9DRzBzM5yXRnL570rnlrJ7Vqp5F0gbJ19PMnyl5eSH2P8gVO+D+O90TH
         a+ZGRreQw101UA5/wff72hAGnN7AgZc4dDCTcri670RrGpcx5iLyJwurpr6yzO9uz0Y6
         BDxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=D1naAFz2CUgbKQMng+4/tSsPuxs19ovlmdczhXdO59c=;
        b=WDEBgl0OrM+RVy87cirqsyNGT1Be3yJTnri4PkT6kfnGnXR8exsQ1qLmZDKMEH0Bvt
         sMs2sH98boEoKzd5ncDDfuC29vK77lQwppV7BVx1ilVPI5V+T0wfTNMtvcoB7fhK4OC1
         c4Z2QbqEvfzpTWMTZ+VDRewnx4dnB73GkJwz9N+zHqeLjLJxPZ9hmAWUmQ5SRk78vuVA
         9kwce2slSYgLMGVglMY1xbK83R19TQqAcILpIkcHW88fYLQ1v4VkAktMK+a9IkI2X7AZ
         3yupY7Vd9OPUut+Z6+pUEFkhPve1AfRLMKD3iOXkhl2llE1Y9JGSNEGfryv9A7h3tgjD
         +Gew==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=D1naAFz2CUgbKQMng+4/tSsPuxs19ovlmdczhXdO59c=;
        b=BD3sbUqgXjyX1FTy/Za1NOh+PaEe8saCZ8Wn+NZ9Oxktb37N5Xk891b6AiIvmCVul0
         qfpRZzW9Pu0OXrEZqsmqf8GNIamLWqZh5tLTn8Svgynso1nJO0paAim+fzmWV4a2yTak
         NzkimqamnGw3WXReGZ9D/DWIh1m/JXAM9O8ej1s/Uf0TuPMmhAms56JaMsj1E/BrlfFy
         v3U7RSgxx+szO5YJ3hVdTYhUuEke50TJN2cdAJ7/H8053+eYoT93ILXpo1qmVgWCPyal
         R2ubzpBCQzd8Dd9JMS50MLdx+LY5VGJsK1H6vYcKv/orDHQjngl2uGZOGLpnpur5GYsP
         Ftmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=D1naAFz2CUgbKQMng+4/tSsPuxs19ovlmdczhXdO59c=;
        b=12+nU1VzTQL65jUhfKtHqWYXYG63dWOLsgX3+ihDONFffqMHU7oMCRy6QpsGdZzo4C
         xohBwwBPKHsx2UBs4ovI+aEcYaLPFmCICjCPA39YqPdCrvxTfBT7uboLVDdP7z2vDhNp
         lEViy676D8+2PlcF/sA20jCLh4zjQuNMsbD7xQWPwzCbG4FqQAPVXzLoVvZlsvqhCh/4
         Y2J11yoiB6NBVlmX+9c9hKinL7rQ5W5Oyk6zCnTOPj6zb+BdHJ2yEom09go5tcZ66rLi
         UzUUR6W3clyq9C+qGXOIlM1S38p/zD6Sw5dbSdjaKd9aBKpuDFlIWXSl5K7zl0x/QMXe
         9D5g==
X-Gm-Message-State: AOAM531AV2wvjq6YoTNu+pDBjm6tUzXMOBDpzL6Xx7yLMEdsIFdnaN45
	YZALb6cfMuzPfuKx1tB9ckc=
X-Google-Smtp-Source: ABdhPJwDht49WvqwqF9ryuUmjVX/oaK/rKCgkJRfqj7sNCzy6csdzcXLHfTGj5lJU8mZgbIUsbW0EQ==
X-Received: by 2002:a9d:2608:: with SMTP id a8mr23804042otb.265.1637582812034;
        Mon, 22 Nov 2021 04:06:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:4110:: with SMTP id w16ls2511461ott.6.gmail; Mon,
 22 Nov 2021 04:06:51 -0800 (PST)
X-Received: by 2002:a9d:750c:: with SMTP id r12mr23783880otk.273.1637582811643;
        Mon, 22 Nov 2021 04:06:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637582811; cv=none;
        d=google.com; s=arc-20160816;
        b=N+BrqpT+YtHUdeiIV/kXUM1VGS4h65LTSRmniteBIpxIdWI3fgMLzi5z6SWB2O+8BZ
         tRrwD33f2kuHOEAN6SqRhTXJ/RkhpruEbCKEj1cFz1Skr+B6uZNq7P7rb1DfyNOeFTqX
         eZt1SN8YP1bUiBOkyXOLHQgFeTC2GOOpZEi2AROuE+3BLmFwYFs1n74B0rQ1OTmEVTEC
         jbLX1UwHID86UXMtmEF+LY1aHHHGRIAWSGUX0X1B2sjoqyE06Qsyxrhl5DiHcAuT+vZM
         YUEjwQ+9kLmHaWnRCzpMPvUikb0FtEC+LeFgryLhyWRZyCjmz0XHcJsjZeGrjczeFZTc
         8pxQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=jjenGVR7g4di4zW64vygTr0VLy5Su9zzaRzV9dGZ5x8=;
        b=FOUS/aMRO/CI+OHarUfvETTHvJMnXlHoGCMZgHbzdvR8RuJZN+gVP5tro4y1ph1tDp
         oC2p0IEsgSbqXhU7X3Oy94t4FyogoM2SQDcNl+OJOFGfcehuekm449NCQiuYcaQdgAE8
         qKv/Df7/+NvyFh+d1GpCRjethYwkmDJZxERxvHuRsO6IBPd1gyUBeMXmlFAoDGLrSqY5
         VICv2EsdSSWX9RgqyiUU2HCSlhYLVTtz7XANfcYH3twiTg42tlD630RQXoqTQWt07bBx
         YiBOVLEk3VR0TEDL+L2Yut1Qv/rxUviJ+0k/RYUju2WW4TjTPVnIBKLA6P/m62HWQpUf
         Lh5w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id d17si936805oiw.0.2021.11.22.04.06.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 22 Nov 2021 04:06:51 -0800 (PST)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggpemm500024.china.huawei.com (unknown [172.30.72.54])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4HyQwc0PV9z9170;
	Mon, 22 Nov 2021 20:06:24 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggpemm500024.china.huawei.com (7.185.36.203) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Mon, 22 Nov 2021 20:06:49 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Mon, 22 Nov 2021 20:06:48 +0800
From: "'Kefeng Wang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov
	<dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>,
	<linux-arm-kernel@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
	<linux-s390@vger.kernel.org>, <kasan-dev@googlegroups.com>,
	<linux-mm@kvack.org>
CC: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>,
	Heiko Carstens <hca@linux.ibm.com>, Vasily Gorbik <gor@linux.ibm.com>,
	Christian Borntraeger <borntraeger@linux.ibm.com>, Alexander Gordeev
	<agordeev@linux.ibm.com>, Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar
	<mingo@redhat.com>, Borislav Petkov <bp@alien8.de>, Dave Hansen
	<dave.hansen@linux.intel.com>, Alexander Potapenko <glider@google.com>,
	Kefeng Wang <wangkefeng.wang@huawei.com>, Yongqiang Liu
	<liuyongqiang13@huawei.com>
Subject: [PATCH] mm: Delay kmemleak object creation of module_alloc()
Date: Mon, 22 Nov 2021 20:17:42 +0800
Message-ID: <20211122121742.142203-1-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.26.2
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems705-chm.china.huawei.com (10.3.19.182) To
 dggpemm500001.china.huawei.com (7.185.36.107)
X-CFilter-Loop: Reflected
X-Original-Sender: wangkefeng.wang@huawei.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188
 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
X-Original-From: Kefeng Wang <wangkefeng.wang@huawei.com>
Reply-To: Kefeng Wang <wangkefeng.wang@huawei.com>
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

Yongqiang reports a kmemleak panic when module ismod/rmmod with KASAN
enabled[1] on x86.

The module allocate memory, and it's kmemleak_object is created successfully,
but the KASAN shadow memory of module allocation is not ready, when kmemleak
scan the module's pointer, it will panic due to no shadow memory.

module_alloc
  __vmalloc_node_range
    kmemleak_vmalloc
				kmemleak_scan
				  update_checksum
  kasan_module_alloc
    kmemleak_ignore

The bug should exist on ARM64/S390 too, add a VM_DELAY_KMEMLEAK flags, delay
vmalloc'ed object register of kmemleak in module_alloc().

[1] https://lore.kernel.org/all/6d41e2b9-4692-5ec4-b1cd-cbe29ae89739@huawei.com/
Reported-by: Yongqiang Liu <liuyongqiang13@huawei.com>
Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
---
 arch/arm64/kernel/module.c | 4 ++--
 arch/s390/kernel/module.c  | 5 +++--
 arch/x86/kernel/module.c   | 7 ++++---
 include/linux/kasan.h      | 4 ++--
 include/linux/vmalloc.h    | 7 +++++++
 mm/kasan/shadow.c          | 9 +++++++--
 mm/vmalloc.c               | 3 ++-
 7 files changed, 27 insertions(+), 12 deletions(-)

diff --git a/arch/arm64/kernel/module.c b/arch/arm64/kernel/module.c
index b5ec010c481f..e6da010716d0 100644
--- a/arch/arm64/kernel/module.c
+++ b/arch/arm64/kernel/module.c
@@ -36,7 +36,7 @@ void *module_alloc(unsigned long size)
 		module_alloc_end = MODULES_END;
 
 	p = __vmalloc_node_range(size, MODULE_ALIGN, module_alloc_base,
-				module_alloc_end, gfp_mask, PAGE_KERNEL, 0,
+				module_alloc_end, gfp_mask, PAGE_KERNEL, VM_DELAY_KMEMLEAK,
 				NUMA_NO_NODE, __builtin_return_address(0));
 
 	if (!p && IS_ENABLED(CONFIG_ARM64_MODULE_PLTS) &&
@@ -58,7 +58,7 @@ void *module_alloc(unsigned long size)
 				PAGE_KERNEL, 0, NUMA_NO_NODE,
 				__builtin_return_address(0));
 
-	if (p && (kasan_module_alloc(p, size) < 0)) {
+	if (p && (kasan_module_alloc(p, size, gfp_mask) < 0)) {
 		vfree(p);
 		return NULL;
 	}
diff --git a/arch/s390/kernel/module.c b/arch/s390/kernel/module.c
index b01ba460b7ca..8d66a93562ca 100644
--- a/arch/s390/kernel/module.c
+++ b/arch/s390/kernel/module.c
@@ -37,14 +37,15 @@
 
 void *module_alloc(unsigned long size)
 {
+	gfp_t gfp_mask = GFP_KERNEL;
 	void *p;
 
 	if (PAGE_ALIGN(size) > MODULES_LEN)
 		return NULL;
 	p = __vmalloc_node_range(size, MODULE_ALIGN, MODULES_VADDR, MODULES_END,
-				 GFP_KERNEL, PAGE_KERNEL_EXEC, 0, NUMA_NO_NODE,
+				 gfp_mask, PAGE_KERNEL_EXEC, VM_DELAY_KMEMLEAK, NUMA_NO_NODE,
 				 __builtin_return_address(0));
-	if (p && (kasan_module_alloc(p, size) < 0)) {
+	if (p && (kasan_module_alloc(p, size, gfp_mask) < 0)) {
 		vfree(p);
 		return NULL;
 	}
diff --git a/arch/x86/kernel/module.c b/arch/x86/kernel/module.c
index 169fb6f4cd2e..ff134d0f1ca1 100644
--- a/arch/x86/kernel/module.c
+++ b/arch/x86/kernel/module.c
@@ -67,6 +67,7 @@ static unsigned long int get_module_load_offset(void)
 
 void *module_alloc(unsigned long size)
 {
+	gfp_t gfp_mask = GFP_KERNEL;
 	void *p;
 
 	if (PAGE_ALIGN(size) > MODULES_LEN)
@@ -74,10 +75,10 @@ void *module_alloc(unsigned long size)
 
 	p = __vmalloc_node_range(size, MODULE_ALIGN,
 				    MODULES_VADDR + get_module_load_offset(),
-				    MODULES_END, GFP_KERNEL,
-				    PAGE_KERNEL, 0, NUMA_NO_NODE,
+				    MODULES_END, gfp_mask,
+				    PAGE_KERNEL, VM_DELAY_KMEMLEAK, NUMA_NO_NODE,
 				    __builtin_return_address(0));
-	if (p && (kasan_module_alloc(p, size) < 0)) {
+	if (p && (kasan_module_alloc(p, size, gfp_mask) < 0)) {
 		vfree(p);
 		return NULL;
 	}
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index d8783b682669..89c99e5e67de 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -474,12 +474,12 @@ static inline void kasan_populate_early_vm_area_shadow(void *start,
  * allocations with real shadow memory. With KASAN vmalloc, the special
  * case is unnecessary, as the work is handled in the generic case.
  */
-int kasan_module_alloc(void *addr, size_t size);
+int kasan_module_alloc(void *addr, size_t size, gfp_t gfp_mask);
 void kasan_free_shadow(const struct vm_struct *vm);
 
 #else /* (CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) && !CONFIG_KASAN_VMALLOC */
 
-static inline int kasan_module_alloc(void *addr, size_t size) { return 0; }
+static inline int kasan_module_alloc(void *addr, size_t size, gfp_t gfp_mask) { return 0; }
 static inline void kasan_free_shadow(const struct vm_struct *vm) {}
 
 #endif /* (CONFIG_KASAN_GENERIC || CONFIG_KASAN_SW_TAGS) && !CONFIG_KASAN_VMALLOC */
diff --git a/include/linux/vmalloc.h b/include/linux/vmalloc.h
index 6e022cc712e6..56d2b7828b31 100644
--- a/include/linux/vmalloc.h
+++ b/include/linux/vmalloc.h
@@ -28,6 +28,13 @@ struct notifier_block;		/* in notifier.h */
 #define VM_MAP_PUT_PAGES	0x00000200	/* put pages and free array in vfree */
 #define VM_NO_HUGE_VMAP		0x00000400	/* force PAGE_SIZE pte mapping */
 
+#if defined(CONFIG_KASAN) && (defined(CONFIG_KASAN_GENERIC) || \
+	defined(CONFIG_KASAN_SW_TAGS)) && !defined(CONFIG_KASAN_VMALLOC)
+#define VM_DELAY_KMEMLEAK	0x00000800	/* delay kmemleak object create */
+#else
+#define VM_DELAY_KMEMLEAK	0
+#endif
+
 /*
  * VM_KASAN is used slightly differently depending on CONFIG_KASAN_VMALLOC.
  *
diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
index 4a4929b29a23..6ca43b43419b 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -498,7 +498,7 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 
 #else /* CONFIG_KASAN_VMALLOC */
 
-int kasan_module_alloc(void *addr, size_t size)
+int kasan_module_alloc(void *addr, size_t size, gfp_mask)
 {
 	void *ret;
 	size_t scaled_size;
@@ -520,9 +520,14 @@ int kasan_module_alloc(void *addr, size_t size)
 			__builtin_return_address(0));
 
 	if (ret) {
+		struct vm_struct *vm = find_vm_area(addr);
 		__memset(ret, KASAN_SHADOW_INIT, shadow_size);
-		find_vm_area(addr)->flags |= VM_KASAN;
+		vm->flags |= VM_KASAN;
 		kmemleak_ignore(ret);
+
+		if (vm->flags | VM_DELAY_KMEMLEAK)
+			kmemleak_vmalloc(vm, size, gfp_mask);
+
 		return 0;
 	}
 
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index d2a00ad4e1dd..23c595b15839 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -3074,7 +3074,8 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 	clear_vm_uninitialized_flag(area);
 
 	size = PAGE_ALIGN(size);
-	kmemleak_vmalloc(area, size, gfp_mask);
+	if (!(vm_flags & VM_DELAY_KMEMLEAK))
+		kmemleak_vmalloc(area, size, gfp_mask);
 
 	return addr;
 
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211122121742.142203-1-wangkefeng.wang%40huawei.com.
