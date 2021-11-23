Return-Path: <kasan-dev+bncBCRKFI7J2AJRBWHR6OGAMGQEWUPZEYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23a.google.com (mail-oi1-x23a.google.com [IPv6:2607:f8b0:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 74FE845A52D
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Nov 2021 15:21:14 +0100 (CET)
Received: by mail-oi1-x23a.google.com with SMTP id r15-20020acaa80f000000b002bcc50ca40dsf13898935oie.5
        for <lists+kasan-dev@lfdr.de>; Tue, 23 Nov 2021 06:21:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637677273; cv=pass;
        d=google.com; s=arc-20160816;
        b=ewWC670gIcjOEBReIS2aWHv+tI8ZtYyVtAPxQaP5PLHl/NHLF+wwjaHgivODD7s1F4
         DSFW4IOQgctDtIH/vA5FKBAB5XOCVYbw5rGTkYmQLUv8htlxS4UjzlUNt6GzV8sGUVUT
         01yHHTtIFw97BZtUIH2/ELOiolZYXL3m69qtd3qILXdgVVu0f+dflyj07zUNKKCkjhto
         uAwW0yI8NsVfPmgtjLCAFUwJ0kPuZ47U3SjLpkDtEMAovd/2+naFK+e/YxpVnuE0ekHZ
         WI/MBmUKelUZ0j1VijE53NG0Bx8FE9AYsv2eTXAOUfgYEyccuQC+tbRuyY0z+axBnnuS
         mzVA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=JZoi9yKYvcYCuIHkwdwqAFyCc6bOuui/xQ7kTzuFGIA=;
        b=TeTu9u7uc34ys7BTSNRHV1Z5+i4YVXaNK4U0qnd4XfGBYZerMihrCycJg6vXWC/ez2
         RqeTHTXcKbYpWSMh5PegBb11RzKTEmb5N5WgkUHUoDx+4nxojZ1wC3IfoqdVRi7oiCbw
         qk6acJHwoacYm39A1IIvHw2n7zPV4jw5Fh8g8WUCHHC7AuuES0Rh9ob4vHv2zlXKzBS5
         mJ75pdYC5eswyKc1hMuMFXfY4lCQTYOa2r72hw2e9LjuzUDKJoZMPgAMh0A5FLNq9mgS
         6RAUGJQcsOo+hWI59ln4iZXwZ+pf1TuD1jHaunaLrTqKmP0Coof3Wn2OME6SSbM86NKI
         IMYQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=JZoi9yKYvcYCuIHkwdwqAFyCc6bOuui/xQ7kTzuFGIA=;
        b=RJmSZcvgcRfH2Q2Gnw5iII+qPpBtQD9DKN6tQ0nxtSk32KkgPdNFgRftQPApMwhNz/
         47kWwRghtSEefwWOVpYRz+czwiDmW5tENfxhXPJ4B0UZfIemurxZAVSUF5XHXICFC44J
         ZxBiUNbVpK6VEWNxZAwulUN2NLSJFneHRKh5U56CvH3Um4jZQU7gul2fjJOUaai1vG4i
         2Vrk1f9YCUGsrkM5WXBwl1IPAOwUdVv605f+D4p8dymm48VC1dVpb/3uL5Ik4u/II2tH
         8Xj0WHtB1CJxu4MVRMmSYJxT5QuzUEax4NMDHT99Xzqe81MHN310ZBk80PnRpW1pKOc0
         zZtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=JZoi9yKYvcYCuIHkwdwqAFyCc6bOuui/xQ7kTzuFGIA=;
        b=5EXLW0h66kmpUTLUkq0StQqwJ/i+BJNr9pw45Lmdx1qIyFkOfPkWjIiKuBOKEiAle9
         ppkqBl1Uea2l7unzitWqSMUmVnnBWx5pH7EK8lYokSNCzM0NsPvhKe9oglnjCCSoSHIp
         kWTne9kiikvOzvVrsocpg6k+Uo3fOYNXSj/moU0FIL17xS0wFsQoehi4Rugnti7EG7GN
         SAMc1fxREuB1vmg8j2gBZ9m8ECyR2nw1/Q18obbi9nrleAmm1V3XGQ1wLQmG22Qit3m9
         0zJdHN+W8YcY38rczhhNkHW8p1UxiYks+IPJhXp8Hv8Ie6rPM7h9rhiMEjnm4PpO3kdL
         dWZw==
X-Gm-Message-State: AOAM533Gms/LbtdGymAGiF0/xxSWiLAUh+/YtgkKovbtGgTuSHt2/ikS
	dZzXLZLIsLckJQAgkOdE3AA=
X-Google-Smtp-Source: ABdhPJyEVQQC8MXi+0BiQXo/Rk2zEGebjNjdgeDAFaCBeduGIgNXbyhZpnT8Ed0CSqF9Sgd/oxfgcg==
X-Received: by 2002:aca:a897:: with SMTP id r145mr2676985oie.136.1637677272871;
        Tue, 23 Nov 2021 06:21:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:19a5:: with SMTP id bj37ls4083995oib.0.gmail; Tue,
 23 Nov 2021 06:21:12 -0800 (PST)
X-Received: by 2002:a05:6808:ec3:: with SMTP id q3mr2703438oiv.57.1637677272177;
        Tue, 23 Nov 2021 06:21:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637677272; cv=none;
        d=google.com; s=arc-20160816;
        b=XM+rHVjH9p9QbpIW97I9ZFai26QfOIl4l1f9LZNV9VBc6TqhXYlrSux32zCDrPEnKa
         MhiNWCk8stTee3KrfSIPWt+AUkS59/MwNBV6/fIcOfr/a86NlPHaGE7KaUpLyZOpQz6K
         +2TGEgVmwnqu0zE5ufjhZVMBo1acV+uPuYtrVHgfDbCTeCFt18fFeVtslKyIQfN0Gg0M
         5QzjX2fE87EjxS5EjvL2LBvZ2FLagn866h1ZBtFq28mmFUpDOvi9QghYD6th/pmWHHqy
         ENCcIl4Tuv2iDSX9+vdlzqjX2oWNg8V6X2uixCercqth9mZXakF1Q6C0oRxZGCZ3xnNI
         ladQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=9ock/u/ohPFWaprE0wS2hNpCcCzhU9rGtazF5P6ipGY=;
        b=LqEOF5f11hHnSrowDbIoWKogj0HpuxrAj7LrHSCObwNC5y4VLO/NraeFGcFUKzL7JU
         XkDVKwsFOQ7gQ9UJI5zZoHvdpmfBDH6TAJQz6sf9jH5S75vTuJkGr+h6H70x5WjYchLU
         vGXL7YWDqgFvI+puH6adjXP1Id0IGZ0StdeUuJXqcCS1NDRVVVyrvAPw2GHp1j/bEo82
         wSQF/szqALSC1aoN/mhGtR6gmfGN/mqe8w7DCdCBgrtwQPfezkjQYFkL1fAsHNsppxII
         urwoxMdX00q+Oac9YryMA5edJtVHmJNYMkMGBpmSQ6LaGEOd0AmxQ3a9SBmr1gLCjKoi
         ZALw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id g64si148391oia.1.2021.11.23.06.21.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 23 Nov 2021 06:21:12 -0800 (PST)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggpemm500020.china.huawei.com (unknown [172.30.72.57])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4Hz5s651Lhz90r9;
	Tue, 23 Nov 2021 22:20:42 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggpemm500020.china.huawei.com (7.185.36.49) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Tue, 23 Nov 2021 22:21:08 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Tue, 23 Nov 2021 22:21:07 +0800
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
Subject: [PATCH v2] mm: Delay kmemleak object creation of module_alloc()
Date: Tue, 23 Nov 2021 22:32:20 +0800
Message-ID: <20211123143220.134361-1-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.26.2
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems704-chm.china.huawei.com (10.3.19.181) To
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

Yongqiang reports a kmemleak panic when module insmod/rmmod with KASAN
enabled on x86[1].

When the module allocates memory, it's kmemleak_object is created successfully,
but the KASAN shadow memory of module allocation is not ready, so when kmemleak
scan the module's pointer, it will panic due to no shadow memory with KASAN.

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
v2:
- fix type error on changelog and kasan_module_alloc()

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
index 4a4929b29a23..2ade2f484562 100644
--- a/mm/kasan/shadow.c
+++ b/mm/kasan/shadow.c
@@ -498,7 +498,7 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
 
 #else /* CONFIG_KASAN_VMALLOC */
 
-int kasan_module_alloc(void *addr, size_t size)
+int kasan_module_alloc(void *addr, size_t size, gfp_t gfp_mask)
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
+		if (vm->flags & VM_DELAY_KMEMLEAK)
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
2.27.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211123143220.134361-1-wangkefeng.wang%40huawei.com.
