Return-Path: <kasan-dev+bncBCRKFI7J2AJRBNUP7GGAMGQENTUEHOI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 605C445C6DA
	for <lists+kasan-dev@lfdr.de>; Wed, 24 Nov 2021 15:10:00 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id v2-20020a4ae6c2000000b002c622008d77sf1694091oot.12
        for <lists+kasan-dev@lfdr.de>; Wed, 24 Nov 2021 06:10:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637762999; cv=pass;
        d=google.com; s=arc-20160816;
        b=jgx3ouqgLIEGEtdX2+hQ0tjChKfmDYjMjccFzw7BERr4AjS4uzPQZn3PP2FicGDa/X
         t5k56GNAfnkVNJJz9FBan9Zwa9y0GjIjami7xFw0Z/uo402ePoylzMeUWDoqDYUaZIFR
         oTiL4XWU6IV6RarEtHVpFVFt+cb7+pS+7oT9lC9Jh/Cgf+oak4I6/rpvAwIJmv2XMltE
         oC2aIpIAtCTXK1EGUV4otPWsgegMAQLBRe4vXK6PnIMdJcmgM1K0d+qLcHnj5tGBKtJl
         o+xIjwT1wkrq8Ab/l4DI4+fNoozZ81n/7U3hMKybKgFrhUiqFxzial0x5J8gAYy53xM7
         QEBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:message-id
         :date:subject:cc:to:from:dkim-signature;
        bh=V6Ux+ygy2SOQN31aG8NuC4D2kN3xbmK8KmuS1Nm5qHU=;
        b=Zf5i85jGEUN/yanfBQED5zb00cslhzn8SqvdXfeXZC2g9pFb+makLV5He8oerUf68+
         caXTZXnaRFhStIIAXuAH4db0iw/TzbgrvOZWkdErwySZMXTnwwfxW+hUnCGsktACOTn4
         eLOaCcn53AmxZ/3jaSWBlbWKTTrVmKZIAx+1t2aE0WtVyCMR4aOrhWMzR3drPk6P529s
         FSouLC0CZTtwUybsLv4nsln7ULmCM33m97oJaT4Kwwh+KgSwVPL1zsE0RcqrK5xjzvGk
         yZgFcUpUZR0RPW3VfQS1iGSDI5Z6KYOEprsZw8oewdXyWERNsl6clJUUv22hB0mrZoTg
         tRTg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=from:to:cc:subject:date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=V6Ux+ygy2SOQN31aG8NuC4D2kN3xbmK8KmuS1Nm5qHU=;
        b=hv7LNY3t2bitts6njobHUVbqSlGfxPK25N8FPRULWbjEiOBHVcyIWwperf5RFezEoq
         Fu3XjFF6LYgoKxPmJWd6yq1ETi/KgAOe0EQ72V+SCSneyirRMBCuktVmvZZMdwKuBkJa
         FLNUcMLCKD/IrkysjChhbPofevYIKi5RCYsozqm4Ay+RtGbZjviZuW54JWZj5uWrx2mJ
         FK5kgw1KIENHM04HfhBsYT5TriEUx++sqoEhqG53wF1UabBq4ugv9jAD1GGum3AdS5a7
         mgkUQiHbsiwbEHHW1UIfGPc/kTPawLWf6PIUEooToGJJUXg17SajkfYvC7BDjTbqZHNb
         fuAw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=V6Ux+ygy2SOQN31aG8NuC4D2kN3xbmK8KmuS1Nm5qHU=;
        b=LKmuaEi4GRp/j6nIMqB2XnGGc3u9M2+O7HCpq4bh1cG4Rkb8260sCjouQBq4OWyluu
         GqH40PMPIanfMjsQjkqMkyf8wIBVd5ANRxsecTW8mzidUDlokGB41k8Fo68aKAmf4nCi
         XHbgpG16Z3NpvDadqdp+M5HTzJPIKvzezpazpJnilAynR3fx85HSE9nkav2hcIHBGMEV
         VKhJJCqZ6qvoM67KFxbDD40vhsRo6hLjNX6Eh0mTZD+2ei+Cwg4nFtKG8QIGET2hvYUo
         EQZ5S4/AS4FLlkX1EkWyM+X0ijS9Agm2KuxGy09ZtmM4/jEEc2bijO65aw7JzvavFlWJ
         xtFg==
X-Gm-Message-State: AOAM530LXmKQRY/NhttzlQf78UC07uZ/IjxOzlR1vtVq5xskfL+lmBsK
	6w2/2mIR8+HTfjIreZfPU3o=
X-Google-Smtp-Source: ABdhPJyLFsg/xi7YPVZj0bmUxkfeMPJeqsmHqXPQQXGVOQtAgyYTMHCP/oE1oio7kjOST7IUcUoJhA==
X-Received: by 2002:aca:1a05:: with SMTP id a5mr6581120oia.146.1637762999028;
        Wed, 24 Nov 2021 06:09:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:45d8:: with SMTP id y207ls911538ooa.3.gmail; Wed, 24 Nov
 2021 06:09:58 -0800 (PST)
X-Received: by 2002:a4a:cf12:: with SMTP id l18mr8962709oos.25.1637762998652;
        Wed, 24 Nov 2021 06:09:58 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637762998; cv=none;
        d=google.com; s=arc-20160816;
        b=Wutcm8uU9obTSnTva15KJRSw3imwnPKFeCRI/nlFrStSTe6ytbXzs2MIEMj+jbDk5J
         BRd4TfllYbCrFXanP+ia56JYPM8drh5vZaNI67IB8JeIGqe3Lu/i1Z7cqxYaO1gRkoEP
         6oEP3VwU/2jznDIwCI6rkyS5OcSXMgtam4cPRJPn3atMMf0P8KBSp2xwSFGo9GBREX6S
         wFOzrDfNn7zJD+ZQRSLEq23Iv3Y6TmLQMdDiLbI9JKorHlIa4RsdK6e/JgxHfxHTmhSb
         jjmksIueCMKc5WEQhUq9UzLMOGydLWCrMvHXhjHojutsg+XLopMdsgJfc2swyaEyzbH0
         3DuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from;
        bh=EEpsBAkwGyRWSRbnOoxeEL6126HaLNQDathi6lYt5YQ=;
        b=NCFa2t2ChyyrYsHbPPPBXjWOUnvBLXUbh+J5Hq4NZqRIJ1V0KpuRjL47yBxoiKBP5Q
         Vt1tV5JzbLIVW5H+KQ/G/s+Wju3qjx2Bnno81EfKagWpvKCHY118mvkkrW+xaQHqE2g+
         dUiXFCLO07pI/uh7khKZcdagdzavqd40ndftfzNZwtKn5MINYxDZRBUMpE9G7Pi7vYpR
         clERAxHctTO8qFtlduqX42HLvSmiUsQy7hAbSO2gMOEmTLL4oTnWg+JBKTPigOmANqy9
         yZO8ucW7qvXnD+RgXBF6xfWpc7AcrqTcxNiRRvB5poIEs974CEo1jkCFcIJDUinDn/Sd
         Zmkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) smtp.mailfrom=wangkefeng.wang@huawei.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=huawei.com
Received: from szxga02-in.huawei.com (szxga02-in.huawei.com. [45.249.212.188])
        by gmr-mx.google.com with ESMTPS id g64si444oia.1.2021.11.24.06.09.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 24 Nov 2021 06:09:58 -0800 (PST)
Received-SPF: pass (google.com: domain of wangkefeng.wang@huawei.com designates 45.249.212.188 as permitted sender) client-ip=45.249.212.188;
Received: from dggpemm500021.china.huawei.com (unknown [172.30.72.57])
	by szxga02-in.huawei.com (SkyGuard) with ESMTP id 4HzjYb1m3vzbj4c;
	Wed, 24 Nov 2021 22:09:23 +0800 (CST)
Received: from dggpemm500001.china.huawei.com (7.185.36.107) by
 dggpemm500021.china.huawei.com (7.185.36.109) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Wed, 24 Nov 2021 22:09:25 +0800
Received: from localhost.localdomain.localdomain (10.175.113.25) by
 dggpemm500001.china.huawei.com (7.185.36.107) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256) id
 15.1.2308.20; Wed, 24 Nov 2021 22:09:24 +0800
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
Subject: [PATCH v3] mm: Defer kmemleak object creation of module_alloc()
Date: Wed, 24 Nov 2021 22:20:34 +0800
Message-ID: <20211124142034.192078-1-wangkefeng.wang@huawei.com>
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
Reported-by: Yongqiang Liu <liuyongqiang13@huawei.com>
Signed-off-by: Kefeng Wang <wangkefeng.wang@huawei.com>
---
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
+		if (vm->flags & VM_DELAY_KMEMLEAK)
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211124142034.192078-1-wangkefeng.wang%40huawei.com.
