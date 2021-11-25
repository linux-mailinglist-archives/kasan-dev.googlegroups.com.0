Return-Path: <kasan-dev+bncBCRKFI7J2AJRBJ4B7WGAMGQEOMGDP2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id A099945D5C7
	for <lists+kasan-dev@lfdr.de>; Thu, 25 Nov 2021 08:52:08 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id s6-20020a05622a018600b002b2d93b9c73sf5302634qtw.9
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Nov 2021 23:52:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637826727; cv=pass;
        d=google.com; s=arc-20160816;
        b=id85vvSAYFGaeoX6XyjXdUsg2qiNx+C0fhAO8b9S8Mh6u6NrYBsZXw24JiW/qphEQd
         GRg58naZ+IG4qNwCZJENzbVjkplvuVylXNEoVFNtrzPv6SCzytqTBLyNhi04UC21fDOF
         SgBlEzFwBBU166kezKGmGbwpQhszNsSygcW5EHhJGPGQ+VD00cBl05slp0NZQ62oYLvA
         v2duLUS0Dppon5ZSaUA0waX4nNd1tBJufzx/Qi+6oyiOnQEI3bbL1d8dSVyRGPvMIRYs
         CQCubU+BTW3NfRbG0sSQ/ZXgNBwctXF5HKzucpAi70c6InhcpJqUCoEvHviMz+a4tEdl
         9lng==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=FHX+2pMW0VKl5kVhCmTc2XC0Tq3bMfGqLtQwy7fyJsA=;
        b=hIhwPlB8r/sezG/a8xsvmgxlLKl1TxAMKq/kYVUtGKBSZ/oUZb3w9pGzDNKJ9iYrpH
         P2Js67Jx4LyrK07CeUZJy+9qtxeqXhvlc5y/+czd57ls4wdU3OEtVd8TvBy+7pJsdHBB
         S97K/QVKl7JN0S6MACaoqDX6B9YteZ19o4u9XUiUb7NXWXHjR2frVpAHuGC8hzNz5FXt
         cSq6Oozt/Z1QI+gsTdsF48DzK5pwHxiriju69VPfTLjo/czQK0eFqoLDP9yMdFqxJYK2
         gpkHLY5KdRoKbTq9B0jaz95XyJIGIOuI1LW3L5nWhnMbOoLC+eM0N4MbAte1+71Ti+sD
         6DIQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=FHX+2pMW0VKl5kVhCmTc2XC0Tq3bMfGqLtQwy7fyJsA=;
        b=kqtSyVXOdUYr+sREPYrWPCbd1AA/IKqmaKGz/4KJg0cXuYyzVxLxuyaOnwRq88TRxB
         gQnvuu4Nc/a9IR+J+pTnzFES7cvOWKJPYIgfB4wk0XCaiuG7pizrLtlkINy4NjR+tuHu
         RVOOEoatdzzfCASfmsAV/1mtk8mYApJ4Q57y1uAtgN8u+oAHzm3ZzeEH+LT9vQawvVua
         hs8xg7finCmnkyUdyIJ/gYp+PqJJOMdIRPYTemu+g/R1lFZD1Z/YrPJYXaKBYiYxhxHA
         x6H3MazYKtebVyCBZRKg9AiZFdug5BdatU7frdtGAmxnDGYEwUYo6w3df1BU9Hwh/0N0
         Kmdw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=FHX+2pMW0VKl5kVhCmTc2XC0Tq3bMfGqLtQwy7fyJsA=;
        b=OaF60XqYW0C9jQ9AK/GXqzQXP1aaF4uVRGEHHxdxgqwh42RI2BiuSot65f0fovEU2g
         85sOp1snrbW6NDPhZgfCChVpKfFU7k65jkSiTcBcgl8TqBzA0NLTrXMfl122IzaJb2+7
         mtd2gXh5KfrI0GWtmstdYiDBYkehRfynDWxok+/Ec1C/IydtXRIZrSvrYIAcQMe5zmF+
         ukabOJ/N9ZUPxcC01LHctxIXJRaf2h5gcfMN7Xw5q8Q03xDVn1scbKapLa0xH5YC+8Vz
         q4PLus4q/3Xa/VnqsF9rssg/11K7CSBD1/N3kzybIX+6akxziaKc8ZGeODMIihFi5aTA
         pjAg==
X-Gm-Message-State: AOAM533AG4b0LRbp1wLwdBqWD8vjRiLA7ecxPgRnrqePNnezlKJTvclI
	p5zrsn6amH0Qmh1G3c4nV80=
X-Google-Smtp-Source: ABdhPJwxKG4RvjP6veDtRBTSVpakGskn/latAFryxWOTxu6yfbQm4o4DuPgLsdqsyA0LGMK/Rd6SlA==
X-Received: by 2002:ad4:4bcf:: with SMTP id l15mr3265905qvw.93.1637826727535;
        Wed, 24 Nov 2021 23:52:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5c05:: with SMTP id i5ls1316208qti.4.gmail; Wed, 24 Nov
 2021 23:52:07 -0800 (PST)
X-Received: by 2002:a05:622a:64b:: with SMTP id a11mr5776565qtb.640.1637826727047;
        Wed, 24 Nov 2021 23:52:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637826727; cv=none;
        d=google.com; s=arc-20160816;
        b=Rz9UBGz4hVzuXQn81SHgaA2NHjyy3t7N6uV3mZPH8x6Wn0XP9m/yi+8te2rw/I50Ay
         RzvK1VQnkADJpcAuFGUku03uIG2tCauYJ3+PXHGJSwUzU4RWc/jP1dh2ArjN6LVwopbl
         GWacNt4q6ECvbKkr+4QiIrGhHn3MoLpBQ/s2+M9GT+n4pnhm7evV2Psqqhb1y3/eRL/7
         ECc9XSL8Yn3rFZuMkSulfylwihFt8kYUM6IkAZenKQSvadaoXL8ZlUa3OWfsUKZ40yVH
         2gtJOK5m136DQf/vadJUWv/rXjbRe1wZKus9fPqWnvADbop/ClAOpXhyjHgBrnUclnFo
         eIsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=vd96azyMuETd5XP7HoFpi0M8x4N5MbGTCSqWtxQBz84=;
        b=L6r74FJOIGNf2/suNUglpk/30oIONyPL9DogRR0igAnFece3O40hzhFzu+ZsQ4qmyR
         p5WF0toaZBq0V3y/rL2kzIR+5JDtLj28gwy+XK0qjDwWqqZnRPmGFY/TQAJrnYc8GarP
         uHaaiGf6CPH9joKJkG5lOcAvhAqNC4yYBOBCn2Js0aMuS9YFSBOmlRrWWFdmOpJ/QU+7
         PDyM/bKK1GEbhFrk7/KSPB3boqe9KuSHG9V1pW/3CmQUkqWM4DHeed9wKZgvnyV9dWtY
         E2AiVuo68EJN7lqPJ2Ct7d5uytL1PkbfX5CjCSHotDu8ObArPQaLI+sIAf1gRAVyDLb3
         vHzg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id i6si430480qko.3.2021.11.24.23.52.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Nov 2021 23:52:07 -0800 (PST)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggpemm500023.china.huawei.com (unknown [172.30.72.54])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4J09792nkfz91Jh;
	Thu, 25 Nov 2021 15:51:33 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggpemm500023.china.huawei.com (7.185.36.83) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Thu, 25 Nov 2021 15:52:00 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Thu, 25 Nov 2021 15:51:59 +0800
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
Subject: [PATCH v4] mm: Defer kmemleak object creation of module_alloc()
Date: Thu, 25 Nov 2021 16:03:07 +0800
Message-ID: <20211125080307.27225-1-wangkefeng.wang@huawei.com>
X-Mailer: git-send-email 2.26.2
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.175.113.25]
X-ClientProxiedBy: dggems706-chm.china.huawei.com (10.3.19.183) To
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

Yongqiang reports a kmemleak panic when module insmod/rmmod
with KASAN enabled(without KASAN_VMALLOC) on x86[1].

When the module area allocates memory, it's kmemleak_object
is created successfully, but the KASAN shadow memory of module
allocation is not ready, so when kmemleak scan the module's
pointer, it will panic due to no shadow memory with KASAN check.

module_alloc
  __vmalloc_node_range
    kmemleak_vmalloc
				kmemleak_scan
				  update_checksum
  kasan_module_alloc
    kmemleak_ignore

Note, there is no problem if KASAN_VMALLOC enabled, the modules
area entire shadow memory is preallocated. Thus, the bug only
exits on ARCH which supports dynamic allocation of module area
per module load, for now, only x86/arm64/s390 are involved.


Add a VM_DEFER_KMEMLEAK flags, defer vmalloc'ed object register
of kmemleak in module_alloc() to fix this issue.

[1] https://lore.kernel.org/all/6d41e2b9-4692-5ec4-b1cd-cbe29ae89739@huawei.com/

Fixes: 793213a82de4 ("s390/kasan: dynamic shadow mem allocation for modules")
Fixes: 39d114ddc682 ("arm64: add KASAN support")
Fixes: bebf56a1b176 ("kasan: enable instrumentation of global variables")
Reported-by: Yongqiang Liu <liuyongqiang13@huawei.com>
Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
---
V4:
- add fix tag
- fix missing change about VM_DELAY_KMEMLEAK
v3:
- update changelog to add more explanation
- use DEFER instead of DELAY sugguested by Catalin.
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
index b5ec010c481f..309a27553c87 100644
--- a/arch/arm64/kernel/module.c
+++ b/arch/arm64/kernel/module.c
@@ -36,7 +36,7 @@ void *module_alloc(unsigned long size)
 		module_alloc_end = MODULES_END;
 
 	p = __vmalloc_node_range(size, MODULE_ALIGN, module_alloc_base,
-				module_alloc_end, gfp_mask, PAGE_KERNEL, 0,
+				module_alloc_end, gfp_mask, PAGE_KERNEL, VM_DEFER_KMEMLEAK,
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
index b01ba460b7ca..d52d85367bf7 100644
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
+				 gfp_mask, PAGE_KERNEL_EXEC, VM_DEFER_KMEMLEAK, NUMA_NO_NODE,
 				 __builtin_return_address(0));
-	if (p && (kasan_module_alloc(p, size) < 0)) {
+	if (p && (kasan_module_alloc(p, size, gfp_mask) < 0)) {
 		vfree(p);
 		return NULL;
 	}
diff --git a/arch/x86/kernel/module.c b/arch/x86/kernel/module.c
index 169fb6f4cd2e..95fa745e310a 100644
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
+				    PAGE_KERNEL, VM_DEFER_KMEMLEAK, NUMA_NO_NODE,
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
index 6e022cc712e6..506fc6e6a126 100644
--- a/include/linux/vmalloc.h
+++ b/include/linux/vmalloc.h
@@ -28,6 +28,13 @@ struct notifier_block;		/* in notifier.h */
 #define VM_MAP_PUT_PAGES	0x00000200	/* put pages and free array in vfree */
 #define VM_NO_HUGE_VMAP		0x00000400	/* force PAGE_SIZE pte mapping */
 
+#if defined(CONFIG_KASAN) && (defined(CONFIG_KASAN_GENERIC) || \
+	defined(CONFIG_KASAN_SW_TAGS)) && !defined(CONFIG_KASAN_VMALLOC)
+#define VM_DEFER_KMEMLEAK	0x00000800	/* defer kmemleak object creation */
+#else
+#define VM_DEFER_KMEMLEAK	0
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
+		if (vm->flags & VM_DEFER_KMEMLEAK)
+			kmemleak_vmalloc(vm, size, gfp_mask);
+
 		return 0;
 	}
 
diff --git a/mm/vmalloc.c b/mm/vmalloc.c
index d2a00ad4e1dd..bf3c2fe8f528 100644
--- a/mm/vmalloc.c
+++ b/mm/vmalloc.c
@@ -3074,7 +3074,8 @@ void *__vmalloc_node_range(unsigned long size, unsigned long align,
 	clear_vm_uninitialized_flag(area);
 
 	size = PAGE_ALIGN(size);
-	kmemleak_vmalloc(area, size, gfp_mask);
+	if (!(vm_flags & VM_DEFER_KMEMLEAK))
+		kmemleak_vmalloc(area, size, gfp_mask);
 
 	return addr;
 
-- 
2.26.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211125080307.27225-1-wangkefeng.wang%40huawei.com.
