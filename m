Return-Path: <kasan-dev+bncBDQ27FVWWUFRB2O3TDTQKGQE7IY554Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id DB6B627569
	for <lists+kasan-dev@lfdr.de>; Thu, 23 May 2019 07:21:46 +0200 (CEST)
Received: by mail-pf1-x43e.google.com with SMTP id r4sf3341260pfh.16
        for <lists+kasan-dev@lfdr.de>; Wed, 22 May 2019 22:21:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558588905; cv=pass;
        d=google.com; s=arc-20160816;
        b=ROU9v+8uqrdgkLCX+tfAtrYXBrhuQwzKSIFH6QabsAtGfhVvaQqQrsTZuRUn0HhE/w
         G7z41gnU/2BYR8ZtQOymG+rgG9gl3CGCO6uDsBYQH6qKzBP0rkOB9b6O89XbQPrFSiCK
         Elak/Cvel7tn8LIH5Dlgj8Y6yk7B5nSR7YhBR7IK72C+e6t6RCkR79MomvIImxY5OkQD
         J2XGnJWNtV/bKItMoeKtPXSSszpeMANasvDzZct2QvVJncxs2IEvbLVqTOkOfcOByXrz
         Jxx/AUAA3nzY6ry7hdnPJl8fZgl0L+qb1KkAgAeQnM+6accMxhzHuiW5qbxi4T627XVB
         IyCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=03oZ8PcLMKZLaGwfD/QC0r7hINGH+rF8+u3CUyUuALE=;
        b=FfWkNNwfsZ3qotTY0w2a4EjIzipx/YNKVNOgRMfRgl0z7nS6vwApF2RkE72a+SiJaQ
         iqePMzKNbOyqJrOG7N1iNksezWAw1xMGvJHaJcMXXadTBFRRtIcN9BxGI90URBv6U14s
         Ru3MECzF8CMXTUFQ0ZAEN/jaOEkqM8eS8AKi5JVLYbPFQCSiYxp2qkEEkLGMoHc0lrlY
         JWPSGkGVgeXUCky41DHyJIfPP8aG0T000BKGbGKLwE9hTtX1U6HwxQBgTE3yMVbfoIVZ
         ZbSE87FrBXEYu0eGWdmTx5xE0O9Wow2tWGiq+HfuO71bf7aQmDto3B+IPNwn3/Y+TmeI
         19xQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="oAv+/z2j";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=03oZ8PcLMKZLaGwfD/QC0r7hINGH+rF8+u3CUyUuALE=;
        b=L69y7LT07Y/0V5i02it/CHXs9YXQqHxiFNkkq5J7t6s5CZXn6qAbaF9lKv0+Fn1GAB
         Egc2Ntb0BdhMsp3ITWpBDFW19cFTgNv1nSsKA6xgKG/rcM+EO3XrvJBumTBrcGbzqtVc
         4ix2b9yfHyNxaGPpvrOGc1Q5bcB5AEBmFHmDJHtpEVmmgtOCVoc1GyU/dlzeoeG29xgj
         gf/7GpI5+jKmIIBxn83WaIsgFg87paLgj0ktTl106t0Guw8bYU18Wj4t3ZhNf71xEGuM
         0/zU9IFCFYxPjLdJzTafcct81WsilzXLr6mKhXq+4BpsENTYj3LNqVnCQFW6gkK5RnB1
         b0rQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=03oZ8PcLMKZLaGwfD/QC0r7hINGH+rF8+u3CUyUuALE=;
        b=QhhRLp4eIzwikjjDVdrTBppA47Nw72wSgAaSH7m3JusiZgx15GeroGmwyX+mxs7FNA
         6+qaWF7sO82nASa5/17taB0um8o+7TTIik0/DuAn/aTMN+LPeyStyLZpHM2mz32GMVgW
         UnmfQ0w8pgU9te0zSc9KdiZOe8YBbw0/TW8b/PrG02QQp6MQl0qa1D6LUqiimqx4FInt
         8bEtIOXSIaHFJJXQpvg1+7KP//95KjN6JESTXWZyh0sHP+PTNMgUiC1Sd/ZAi6+LbB1x
         ZXSGqlkzAscFtsqsEh3cVAZf6RT9umyCoFYoL/6aJ/y/Ujh+VAqp++zcrT5aO4qsqzJ2
         HhRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXvzZStbt5jnlp7fd3SCIZGIIMkwgvBmSDQ8YDxb5h1JXBdRZAg
	qolkwLQzWMySeRg7y4qylQ8=
X-Google-Smtp-Source: APXvYqxvmUQnzlp7dmSdpglsQF0uvx9IAaOLdz8pyZLvxt354qtU7tYqovkP74ff84fgvSfG4ViBmg==
X-Received: by 2002:a65:4c07:: with SMTP id u7mr92146205pgq.93.1558588905287;
        Wed, 22 May 2019 22:21:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:5c4a:: with SMTP id v10ls1193369pgr.1.gmail; Wed, 22 May
 2019 22:21:44 -0700 (PDT)
X-Received: by 2002:a63:4006:: with SMTP id n6mr95827900pga.424.1558588904965;
        Wed, 22 May 2019 22:21:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558588904; cv=none;
        d=google.com; s=arc-20160816;
        b=WQhrCBgv3l1GzUsqFEEj+g+FTvqx1Qr3PrIUkwEQPc9RuJdlSQrcFF3Nhoyl+QtEe3
         dRWHtG9pk12VWJoBU3CeVwgOFJ+4K9USm/IN5qFCPam8hShiA/oCldBpR4iIjOzvZH0M
         38u8/oJ9QPJxL0u5q1/xIGGp8tkJoVotD7w7UvISuZb10Vx4JMp4rmi8zxT+xJbh8MhH
         zgn+191AJMcvqmebgr6DpS3QXLxWnbGYHMZA9SW2TQZhju6LnRj1Y9dzs0BP7EkG8dpz
         eqpRDyIb1F2B2DD+eUfzFCM6kZTyBgYentHKOCmfUbqZGHpWYH68RtfBZ7wmP0yz/5lU
         EMEg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=fvP5oPwjqbAX/bEXmLdpE4Ur4fPSKjQ3so3j2BcFboA=;
        b=mRn8aJxZk8t/1b0nQyUVR2x5beLeWd0E3S8S+tqgJa1jIhO1bqb77jSJuNa7vrk+1Q
         bgcn3mjxQUUOwzCuiZT5/n9cbgVNBzkuPlOw3TITLDVVYPFO2Wbhp+9a+M99xfQ7hZsc
         udtA2cOEV0VSRUWI7w9ME6/xE5Dpz9xCVbhWdBQZCIvXGa7Y8SjdatwJhxeSAKknkQQ3
         8TaAfwLK0prz6xafIFbDLSzJLLFbai/Z4CMWqgahgkRmlEuC39tpEpZxkgPcWYgHChhL
         TK8D7PXyLCCyQzFEvbvsRnIC/rYC1V2WTZJOBVIrn9mvR1tZQm674LurZAAQjqvU5WVU
         nZWg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b="oAv+/z2j";
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x642.google.com (mail-pl1-x642.google.com. [2607:f8b0:4864:20::642])
        by gmr-mx.google.com with ESMTPS id s125si1502245pgs.1.2019.05.22.22.21.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 May 2019 22:21:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as permitted sender) client-ip=2607:f8b0:4864:20::642;
Received: by mail-pl1-x642.google.com with SMTP id g9so2185458plm.6
        for <kasan-dev@googlegroups.com>; Wed, 22 May 2019 22:21:44 -0700 (PDT)
X-Received: by 2002:a17:902:446:: with SMTP id 64mr95255617ple.322.1558588904706;
        Wed, 22 May 2019 22:21:44 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id b18sm52001748pfp.32.2019.05.22.22.21.43
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 22 May 2019 22:21:44 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: aneesh.kumar@linux.ibm.com,
	christophe.leroy@c-s.fr,
	bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	Daniel Axtens <dja@axtens.net>,
	"Aneesh Kumar K . V" <aneesh.kumar@linux.vnet.ibm.com>
Subject: [RFC PATCH 4/7] powerpc: KASAN for 64bit Book3E
Date: Thu, 23 May 2019 15:21:17 +1000
Message-Id: <20190523052120.18459-5-dja@axtens.net>
X-Mailer: git-send-email 2.19.1
In-Reply-To: <20190523052120.18459-1-dja@axtens.net>
References: <20190523052120.18459-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b="oAv+/z2j";       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::642 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

Wire up KASAN. Only outline instrumentation is supported.

The KASAN shadow area is mapped into vmemmap space:
0x8000 0400 0000 0000 to 0x8000 0600 0000 0000.
To do this we require that vmemmap be disabled. (This is the default
in the kernel config that QorIQ provides for the machine in their
SDK anyway - they use flat memory.)

Only the kernel linear mapping (0xc000...) is checked. The vmalloc and
ioremap areas (also in 0x800...) are all mapped to the zero page. As
with the Book3S hash series, this requires overriding the memory <->
shadow mapping.

Also, as with both previous 64-bit series, early instrumentation is not
supported.  It would allow us to drop the check_return_arch_not_ready()
hook in the KASAN core, but it's tricky to get it set up early enough:
we need it setup before the first call to instrumented code like printk().
Perhaps in the future.

Only KASAN_MINIMAL works.

Tested on e6500. KVM, kexec and xmon have not been tested.

The test_kasan module fires warnings as expected, except for the
following tests:

 - Expected/by design:
kasan test: memcg_accounted_kmem_cache allocate memcg accounted object

 - Due to only supporting KASAN_MINIMAL:
kasan test: kasan_stack_oob out-of-bounds on stack
kasan test: kasan_global_oob out-of-bounds global variable
kasan test: kasan_alloca_oob_left out-of-bounds to left on alloca
kasan test: kasan_alloca_oob_right out-of-bounds to right on alloca
kasan test: use_after_scope_test use-after-scope on int
kasan test: use_after_scope_test use-after-scope on array

Thanks to those who have done the heavy lifting over the past several
years:
 - Christophe's 32 bit series: https://lists.ozlabs.org/pipermail/linuxppc-dev/2019-February/185379.html
 - Aneesh's Book3S hash series: https://lwn.net/Articles/655642/
 - Balbir's Book3S radix series: https://patchwork.ozlabs.org/patch/795211/

Cc: Christophe Leroy <christophe.leroy@c-s.fr>
Cc: Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
Cc: Balbir Singh <bsingharora@gmail.com>
Signed-off-by: Daniel Axtens <dja@axtens.net>
[- Removed EXPORT_SYMBOL of the static key
 - Fixed most checkpatch problems
 - Replaced kasan_zero_page[] by kasan_early_shadow_page[]
 - Reduced casting mess by using intermediate locals
 - Fixed build failure on pmac32_defconfig]
Signed-off-by: Christophe Leroy <christophe.leroy@c-s.fr>
---
 arch/powerpc/Kconfig                         |  1 +
 arch/powerpc/Kconfig.debug                   |  2 +-
 arch/powerpc/include/asm/kasan.h             | 71 ++++++++++++++++++++
 arch/powerpc/mm/kasan/Makefile               |  1 +
 arch/powerpc/mm/kasan/kasan_init_book3e_64.c | 50 ++++++++++++++
 arch/powerpc/mm/nohash/Makefile              |  5 ++
 6 files changed, 129 insertions(+), 1 deletion(-)
 create mode 100644 arch/powerpc/mm/kasan/kasan_init_book3e_64.c

diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
index 6a66a2da5b1a..4e266b019dd7 100644
--- a/arch/powerpc/Kconfig
+++ b/arch/powerpc/Kconfig
@@ -170,6 +170,7 @@ config PPC
 	select HAVE_ARCH_AUDITSYSCALL
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_KASAN			if PPC32
+	select HAVE_ARCH_KASAN			if PPC_BOOK3E_64 && !SPARSEMEM_VMEMMAP
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if COMPAT
diff --git a/arch/powerpc/Kconfig.debug b/arch/powerpc/Kconfig.debug
index c59920920ddc..23a37facc854 100644
--- a/arch/powerpc/Kconfig.debug
+++ b/arch/powerpc/Kconfig.debug
@@ -396,5 +396,5 @@ config PPC_FAST_ENDIAN_SWITCH
 
 config KASAN_SHADOW_OFFSET
 	hex
-	depends on KASAN
+	depends on KASAN && PPC32
 	default 0xe0000000
diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm/kasan.h
index 296e51c2f066..ae410f0e060d 100644
--- a/arch/powerpc/include/asm/kasan.h
+++ b/arch/powerpc/include/asm/kasan.h
@@ -21,12 +21,15 @@
 #define KASAN_SHADOW_START	(KASAN_SHADOW_OFFSET + \
 				 (PAGE_OFFSET >> KASAN_SHADOW_SCALE_SHIFT))
 
+#ifdef CONFIG_PPC32
 #define KASAN_SHADOW_OFFSET	ASM_CONST(CONFIG_KASAN_SHADOW_OFFSET)
 
 #define KASAN_SHADOW_END	0UL
 
 #define KASAN_SHADOW_SIZE	(KASAN_SHADOW_END - KASAN_SHADOW_START)
 
+#endif /* CONFIG_PPC32 */
+
 #ifdef CONFIG_KASAN
 void kasan_early_init(void);
 void kasan_mmu_init(void);
@@ -36,5 +39,73 @@ static inline void kasan_init(void) { }
 static inline void kasan_mmu_init(void) { }
 #endif
 
+#ifdef CONFIG_PPC_BOOK3E_64
+#include <asm/pgtable.h>
+#include <linux/jump_label.h>
+
+/*
+ * We don't put this in Kconfig as we only support KASAN_MINIMAL, and
+ * that will be disabled if the symbol is available in Kconfig
+ */
+#define KASAN_SHADOW_OFFSET	ASM_CONST(0x6800040000000000)
+
+#define KASAN_SHADOW_SIZE	(KERN_VIRT_SIZE >> KASAN_SHADOW_SCALE_SHIFT)
+
+extern struct static_key_false powerpc_kasan_enabled_key;
+extern unsigned char kasan_early_shadow_page[];
+
+static inline bool kasan_arch_is_ready_book3e(void)
+{
+	if (static_branch_likely(&powerpc_kasan_enabled_key))
+		return true;
+	return false;
+}
+#define kasan_arch_is_ready kasan_arch_is_ready_book3e
+
+static inline void *kasan_mem_to_shadow_book3e(const void *ptr)
+{
+	unsigned long addr = (unsigned long)ptr;
+
+	if (addr >= KERN_VIRT_START && addr < KERN_VIRT_START + KERN_VIRT_SIZE)
+		return kasan_early_shadow_page;
+
+	return (void *)(addr >> KASAN_SHADOW_SCALE_SHIFT) + KASAN_SHADOW_OFFSET;
+}
+#define kasan_mem_to_shadow kasan_mem_to_shadow_book3e
+
+static inline void *kasan_shadow_to_mem_book3e(const void *shadow_addr)
+{
+	/*
+	 * We map the entire non-linear virtual mapping onto the zero page so if
+	 * we are asked to map the zero page back just pick the beginning of that
+	 * area.
+	 */
+	if (shadow_addr >= (void *)kasan_early_shadow_page &&
+	    shadow_addr < (void *)(kasan_early_shadow_page + PAGE_SIZE))
+		return (void *)KERN_VIRT_START;
+
+	return (void *)(((unsigned long)shadow_addr - KASAN_SHADOW_OFFSET) <<
+			KASAN_SHADOW_SCALE_SHIFT);
+}
+#define kasan_shadow_to_mem kasan_shadow_to_mem_book3e
+
+static inline bool kasan_addr_has_shadow_book3e(const void *ptr)
+{
+	unsigned long addr = (unsigned long)ptr;
+
+	/*
+	 * We want to specifically assert that the addresses in the 0x8000...
+	 * region have a shadow, otherwise they are considered by the kasan
+	 * core to be wild pointers
+	 */
+	if (addr >= KERN_VIRT_START && addr < (KERN_VIRT_START + KERN_VIRT_SIZE))
+		return true;
+
+	return (ptr >= kasan_shadow_to_mem((void *)KASAN_SHADOW_START));
+}
+#define kasan_addr_has_shadow kasan_addr_has_shadow_book3e
+
+#endif /* CONFIG_PPC_BOOK3E_64 */
+
 #endif /* __ASSEMBLY */
 #endif
diff --git a/arch/powerpc/mm/kasan/Makefile b/arch/powerpc/mm/kasan/Makefile
index 6577897673dd..f8f164ad8ade 100644
--- a/arch/powerpc/mm/kasan/Makefile
+++ b/arch/powerpc/mm/kasan/Makefile
@@ -3,3 +3,4 @@
 KASAN_SANITIZE := n
 
 obj-$(CONFIG_PPC32)           += kasan_init_32.o
+obj-$(CONFIG_PPC_BOOK3E_64)   += kasan_init_book3e_64.o
diff --git a/arch/powerpc/mm/kasan/kasan_init_book3e_64.c b/arch/powerpc/mm/kasan/kasan_init_book3e_64.c
new file mode 100644
index 000000000000..f116c211d83c
--- /dev/null
+++ b/arch/powerpc/mm/kasan/kasan_init_book3e_64.c
@@ -0,0 +1,50 @@
+// SPDX-License-Identifier: GPL-2.0
+
+#define DISABLE_BRANCH_PROFILING
+
+#include <linux/kasan.h>
+#include <linux/printk.h>
+#include <linux/memblock.h>
+#include <linux/sched/task.h>
+#include <asm/pgalloc.h>
+
+DEFINE_STATIC_KEY_FALSE(powerpc_kasan_enabled_key);
+
+static void __init kasan_init_region(struct memblock_region *reg)
+{
+	void *start = __va(reg->base);
+	void *end = __va(reg->base + reg->size);
+	unsigned long k_start, k_end, k_cur;
+
+	if (start >= end)
+		return;
+
+	k_start = (unsigned long)kasan_mem_to_shadow(start);
+	k_end = (unsigned long)kasan_mem_to_shadow(end);
+
+	for (k_cur = k_start; k_cur < k_end; k_cur += PAGE_SIZE) {
+		void *va = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
+
+		map_kernel_page(k_cur, __pa(va), PAGE_KERNEL);
+	}
+	flush_tlb_kernel_range(k_start, k_end);
+}
+
+void __init kasan_init(void)
+{
+	struct memblock_region *reg;
+
+	for_each_memblock(memory, reg)
+		kasan_init_region(reg);
+
+	/* map the zero page RO */
+	map_kernel_page((unsigned long)kasan_early_shadow_page,
+			__pa(kasan_early_shadow_page), PAGE_KERNEL_RO);
+
+	/* Turn on checking */
+	static_branch_inc(&powerpc_kasan_enabled_key);
+
+	/* Enable error messages */
+	init_task.kasan_depth = 0;
+	pr_info("KASAN init done (64-bit Book3E)\n");
+}
diff --git a/arch/powerpc/mm/nohash/Makefile b/arch/powerpc/mm/nohash/Makefile
index 33b6f6f29d3f..310149f217d7 100644
--- a/arch/powerpc/mm/nohash/Makefile
+++ b/arch/powerpc/mm/nohash/Makefile
@@ -16,3 +16,8 @@ endif
 # This is necessary for booting with kcov enabled on book3e machines
 KCOV_INSTRUMENT_tlb.o := n
 KCOV_INSTRUMENT_fsl_booke.o := n
+
+ifdef CONFIG_KASAN
+CFLAGS_fsl_booke_mmu.o		+= -DDISABLE_BRANCH_PROFILING
+CFLAGS_tlb.o			+= -DDISABLE_BRANCH_PROFILING
+endif
-- 
2.19.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190523052120.18459-5-dja%40axtens.net.
For more options, visit https://groups.google.com/d/optout.
