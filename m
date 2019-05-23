Return-Path: <kasan-dev+bncBDQ27FVWWUFRB5W3TDTQKGQE2UKRIPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 15FE92756C
	for <lists+kasan-dev@lfdr.de>; Thu, 23 May 2019 07:21:59 +0200 (CEST)
Received: by mail-qt1-x83c.google.com with SMTP id z7sf4337157qtq.13
        for <lists+kasan-dev@lfdr.de>; Wed, 22 May 2019 22:21:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1558588918; cv=pass;
        d=google.com; s=arc-20160816;
        b=NiFJpgIUCij2RpF0BdKOWgv3oLjAw3cYYMaMMe38uaHTLS+t/X7UfY5aj09mwl8zSK
         5irFGXGu6CPxoyquSaq2489eyaJL3pcPiSX9ajNNhagkCbFJXJThVa7uvqwqKHv6fn/0
         Yn7mqt2CopO3mGSVWI2XvLZiXiUM4dDtc1olVaAcI4HpwmOxG5mhISkYK/busU5GEls3
         EC9a2B9qxoVXeWn+uR4owNKtk6IZYpxE8hNVyR1btV2CpEVHcA8AbO6mJtFpvcDab2rl
         fZ2v0l2+SAB9jRN1EOh79vjcHQXtipLJMqE4bMiDTunfKPod+tGoSLp9RLDnzLVIYU0j
         As1Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2csQEu2v9d9t8MHdcofaSn5RbCopIEgcGLQFGWjmo9Y=;
        b=yqCI7kuy1KqaeIH4O3turWU6g+M59rj7rcOfliQJ0YWcgc+WtJN6H7hXurp9aR5XFf
         8pe4m5MTw0izxFb3TV9dDnkCSxZe0PCAQLczBw5MzEZSFHCnBVSKPu9vmgZ3BmXUDRXg
         ZR0bfTTl6qmKp4F0YJx1XG3xfFOY1e9uisTMR5M8L/QIG1Ulk1MJOaK6Q/XaXo3CZGEG
         N5CtVwKOWGImS/k/gJRnjeTvp4wsB3NCPYzZfmCCpT9vsP3Z6HvTUoEy9WuJ82heL5eR
         kZ5qMbry9d6IivdN8GkDFHvVfXosksXYZCNeeq33iZqWAp5w3sBERA7IfRVbUOMB0dDa
         0zPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=mkcv9ET3;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2csQEu2v9d9t8MHdcofaSn5RbCopIEgcGLQFGWjmo9Y=;
        b=bDJCmQcEsu2WZcuagiZhG/8hd2kCHGj7ntg1GWZFyqqqiTPN36xxuuBfwlpHpSCUmx
         OaDuBHxn4YiQi7hzFu7Ir/53TyBx0eJUCH+0cXP+44y4k2kTALrP2ctpffyrnrZ9C2xP
         HZPH3XgXpdctSzC42k2Ry5jPmaRtrzCjYPciDArCR80ik9XYkjWnDu+rADIxK1umms6q
         E42FBMVcSdDjay1cU05aX2wswTzFJJALlbvKwWXFd7Xlc5m+2pWbU4hNYVEGGDvosL/7
         6Eq2tVNR3imFvLi9lHv3YiO3iMlvrGrym00RCqzBXqT/z9GpV3IZM4Bu17/I+tAoC/qf
         jAaw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=2csQEu2v9d9t8MHdcofaSn5RbCopIEgcGLQFGWjmo9Y=;
        b=QtHmC/7qoQxG/kv+mgIdFeaKm/RTRJXlTuI4a7BosTwoiSNbZhSYD7u5unFcdJZm1s
         5Xkwy0EsdL0NDKtFJdmuTw4ikq/MVRTfMfNDdDXmYq2Yv2IA0SPmTHj1NV0REysWdI00
         OVgTnPMVkRqgj1F3a6Y2jeGxXPecWi0P+sxGuDU2kY78KpScy5DH2Qk7KANixeeDPK44
         GMwpkL+sLlp7tbgPXz+0dbn3wXCbhpYsos+gktz21LCmPluFousjVGlMXaB1aBUBWCYs
         gDH1iZwvp5TNBqWvEUbOHxMHZDsgTVEi3/g2qbqydct0IYK4c8UZddPkqTtYGeb+Y6WB
         WFvA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAX2EWrSrtWUMY/JPhHWA1vWYUNSK+jgAeBqcdpZlQBeCSbpYqdu
	xLNGTD67PxR+Rczb4dA5o9U=
X-Google-Smtp-Source: APXvYqzUxGOO8JInqbAYJOJnetzz/BP0TRmkBYt473nUF/uahZf8tggFVehNoma1h4Gxym7i3Fs7zA==
X-Received: by 2002:a05:620a:146d:: with SMTP id j13mr6706623qkl.222.1558588918129;
        Wed, 22 May 2019 22:21:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:4e93:: with SMTP id c141ls864659qkb.14.gmail; Wed, 22
 May 2019 22:21:57 -0700 (PDT)
X-Received: by 2002:a37:9ce:: with SMTP id 197mr73737330qkj.190.1558588917891;
        Wed, 22 May 2019 22:21:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1558588917; cv=none;
        d=google.com; s=arc-20160816;
        b=kUzP8VVsMX2bY3vRFP3yLzW0VebTVE4KV2cqjccqKkYSwTNPK4hLhZUB/VzsUs0NFU
         AjshCKzg975rnPC8E7NbEujNivgrBgKQf4Vr4o7oyJse912qJRPCRW89wf4BNgIrk40a
         8QL/ubHNSfjzsNe1lS/vZguWOU4zJ7cUpXNW+ld4FK1SMUuO814AIarpg1L2pCbVDbFY
         6D9fUaJKkOnkRp3Y8jMPD5W61C70IulNMsfSkX9WQ94Xdkf919lmmpkw+xUOuyjAg44h
         VKhdSxXgYcE2Mu1LFwg/uieCfXcok6uI/pR5Zahoth0OHWVLurc0YOuvP2vslrjh0bgo
         Nd2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=LGGVPIzxI40wSzO9GQC0XJd99DGaK5BkBws0m1VowW8=;
        b=CL7JxAk0dtkRL/1VSP4n+FICqMc1gvYqFPuTaC5Tte8B8srQouGV3iCB9XWdQracv5
         J/lzoZgNf6SbZygwLLVDj9045m0kfnkR7ixulHIdUagc8JorRSajk3XCTa9GTNQB3gaH
         zy1brXh2/PUlvRjtsB53omU5lLfaQergtqrzK176e08yZ6lg/FarPChMLlfPFjXIIc8U
         B7/70AzQL9WJe/9PEiiAALMh2aqpZ8Mzba5G/FbcaiqauxRgmw5SAQYDYFMLSy2jAORy
         aEJOXhQqY5GLkqdvBGweliQoYUyTOf4lxgALCmHsf6e31AS9y3KMwLv7duEpD3qpTaEH
         w6NA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=mkcv9ET3;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pf1-x443.google.com (mail-pf1-x443.google.com. [2607:f8b0:4864:20::443])
        by gmr-mx.google.com with ESMTPS id v67si1553028qka.2.2019.05.22.22.21.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 May 2019 22:21:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as permitted sender) client-ip=2607:f8b0:4864:20::443;
Received: by mail-pf1-x443.google.com with SMTP id 13so2555960pfw.9
        for <kasan-dev@googlegroups.com>; Wed, 22 May 2019 22:21:57 -0700 (PDT)
X-Received: by 2002:a63:c14:: with SMTP id b20mr94605719pgl.163.1558588917324;
        Wed, 22 May 2019 22:21:57 -0700 (PDT)
Received: from localhost (ppp167-251-205.static.internode.on.net. [59.167.251.205])
        by smtp.gmail.com with ESMTPSA id o6sm56470594pfa.88.2019.05.22.22.21.55
        (version=TLS1_2 cipher=ECDHE-RSA-CHACHA20-POLY1305 bits=256/256);
        Wed, 22 May 2019 22:21:56 -0700 (PDT)
From: Daniel Axtens <dja@axtens.net>
To: aneesh.kumar@linux.ibm.com,
	christophe.leroy@c-s.fr,
	bsingharora@gmail.com
Cc: linuxppc-dev@lists.ozlabs.org,
	kasan-dev@googlegroups.com,
	Daniel Axtens <dja@axtens.net>
Subject: [RFC PATCH 7/7] powerpc: Book3S 64-bit "heavyweight" KASAN support
Date: Thu, 23 May 2019 15:21:20 +1000
Message-Id: <20190523052120.18459-8-dja@axtens.net>
X-Mailer: git-send-email 2.19.1
In-Reply-To: <20190523052120.18459-1-dja@axtens.net>
References: <20190523052120.18459-1-dja@axtens.net>
MIME-Version: 1.0
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=mkcv9ET3;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::443 as
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

KASAN support on powerpc64 is interesting:

 - We want to be able to support inline instrumentation so as to be
   able to catch global and stack issues.

 - We run a lot of code at boot in real mode. This includes stuff like
   printk(), so it's not feasible to just disable instrumentation
   around it.

   [For those not immersed in ppc64, in real mode, the top nibble or
   byte (depending on radix/hash mmu) of the address is ignored. To
   make things work, we put the linear mapping at
   0xc000000000000000. This means that a pointer to part of the linear
   mapping will work both in real mode, where it will be interpreted
   as a physical address of the form 0x000..., and out of real mode,
   where it will go via the linear mapping.]

 - Inline instrumentation requires a fixed offset.

 - Because of our running things in real mode, the offset has to
   point to valid memory both in and out of real mode.

This makes finding somewhere to put the KASAN shadow region a bit fun.

One approach is just to give up on inline instrumentation; and this is
what the 64 bit book3e code does. This way we can delay all checks
until after we get everything set up to our satisfaction. However,
we'd really like to do better.

What we can do - if we know _at compile time_ how much physical memory
we have - is to set aside the top 1/8th of the memory and use that.
This is a big hammer (hence the "heavyweight" name) and comes with 2
big consequences:

 - kernels will simply fail to boot on machines with less memory than
   specified when compiling.

 - kernels running on machines with more memory than specified when
   compiling will simply ignore the extra memory.

If you can bear this consequence, you get pretty full support for
KASAN.

This is still pretty WIP but I wanted to get it out there sooner
rather than later. Ongoing work:

 - Currently incompatible with KUAP (top priority to fix)

 - Currently incompatible with ftrace (no idea why yet)

 - Only supports radix at the moment

 - Very minimal testing (boots a Ubuntu VM, test_kasan runs)

 - Extend 'lightweight' outline support from book3e that will work
   without requring memory to be known at compile time.

 - It assumes physical memory is contiguous. I don't really think
   we can get around this, so we should try to ensure it.

Despite the limitations, it can still find bugs,
e.g. http://patchwork.ozlabs.org/patch/1103775/

Massive thanks to mpe, who had the idea for the initial design.

Signed-off-by: Daniel Axtens <dja@axtens.net>

---

Tested on qemu-pseries and qemu-powernv, seems to work on both
of those. Does not work on the talos that I tested on, no idea
why yet.

---
 arch/powerpc/Kconfig                         |  1 +
 arch/powerpc/Kconfig.debug                   | 15 +++++
 arch/powerpc/Makefile                        |  7 ++
 arch/powerpc/include/asm/kasan.h             | 45 +++++++++++++
 arch/powerpc/kernel/prom.c                   | 40 ++++++++++++
 arch/powerpc/mm/kasan/Makefile               |  1 +
 arch/powerpc/mm/kasan/kasan_init_book3s_64.c | 67 ++++++++++++++++++++
 7 files changed, 176 insertions(+)
 create mode 100644 arch/powerpc/mm/kasan/kasan_init_book3s_64.c

diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
index 4e266b019dd7..203cd07cf6e0 100644
--- a/arch/powerpc/Kconfig
+++ b/arch/powerpc/Kconfig
@@ -171,6 +171,7 @@ config PPC
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_KASAN			if PPC32
 	select HAVE_ARCH_KASAN			if PPC_BOOK3E_64 && !SPARSEMEM_VMEMMAP
+	select HAVE_ARCH_KASAN			if PPC_BOOK3S_64 && !CONFIG_FTRACE && !PPC_KUAP
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if COMPAT
diff --git a/arch/powerpc/Kconfig.debug b/arch/powerpc/Kconfig.debug
index 23a37facc854..c0916408668c 100644
--- a/arch/powerpc/Kconfig.debug
+++ b/arch/powerpc/Kconfig.debug
@@ -394,6 +394,21 @@ config PPC_FAST_ENDIAN_SWITCH
         help
 	  If you're unsure what this is, say N.
 
+config PHYS_MEM_SIZE_FOR_KASAN
+	int "Physical memory size for KASAN (MB)"
+	depends on KASAN && PPC_BOOK3S_64
+	help
+	  To get inline instrumentation support for KASAN on 64-bit Book3S
+	  machines, you need to specify how much physical memory your system
+	  has. A shadow offset will be calculated based on this figure, which
+	  will be compiled in to the kernel. KASAN will use this offset to
+	  access its shadow region, which is used to verify memory accesses.
+
+	  If you attempt to boot on a system with less memory than you specify
+	  here, your system will fail to boot very early in the process. If you
+	  boot on a system with more memory than you specify, the extra memory
+	  will wasted - it will be reserved and not used.
+
 config KASAN_SHADOW_OFFSET
 	hex
 	depends on KASAN && PPC32
diff --git a/arch/powerpc/Makefile b/arch/powerpc/Makefile
index c345b79414a9..33e7bba4c8db 100644
--- a/arch/powerpc/Makefile
+++ b/arch/powerpc/Makefile
@@ -229,6 +229,13 @@ ifdef CONFIG_476FPE_ERR46
 		-T $(srctree)/arch/powerpc/platforms/44x/ppc476_modules.lds
 endif
 
+ifdef CONFIG_KASAN
+ifdef CONFIG_PPC_BOOK3S_64
+# 0xa800000000000000 = 12105675798371893248
+KASAN_SHADOW_OFFSET = $(shell echo 7 \* 1024 \* 1024 \* $(CONFIG_PHYS_MEM_SIZE_FOR_KASAN) / 8 + 12105675798371893248 | bc)
+endif
+endif
+
 # No AltiVec or VSX instructions when building kernel
 KBUILD_CFLAGS += $(call cc-option,-mno-altivec)
 KBUILD_CFLAGS += $(call cc-option,-mno-vsx)
diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm/kasan.h
index ae410f0e060d..7f75f904998b 100644
--- a/arch/powerpc/include/asm/kasan.h
+++ b/arch/powerpc/include/asm/kasan.h
@@ -107,5 +107,50 @@ static inline bool kasan_addr_has_shadow_book3e(const void *ptr)
 
 #endif /* CONFIG_PPC_BOOK3E_64 */
 
+#ifdef CONFIG_PPC_BOOK3S_64
+#include <asm/pgtable.h>
+#include <linux/jump_label.h>
+
+/*
+ * The KASAN shadow offset is such that the linear map (0xc000...) is
+ * shadowed by the last 8th of physical memory. This way, if the code
+ * uses 0xc addresses throughout, accesses work both in in real mode
+ * (where the top nibble is ignored) and outside of real mode.
+ */
+#define KASAN_SHADOW_OFFSET ((u64)CONFIG_PHYS_MEM_SIZE_FOR_KASAN * \
+				1024 * 1024 * 7 / 8 + 0xa800000000000000UL)
+
+#define KASAN_SHADOW_SIZE ((u64)CONFIG_PHYS_MEM_SIZE_FOR_KASAN * \
+				1024 * 1024 * 1 / 8)
+
+static inline bool kasan_arch_can_register_global_book3s(const void * addr) {
+
+	/*
+	 * We don't define a particular area for modules, we just put them in
+	 * vmalloc space. This means that they live in an area backed entirely
+	 * by our read-only zero page. The global registration system is not
+	 * smart enough to deal with this and attempts to poison it, which
+	 * blows up. Unless we want to split out an area of vmalloc space for
+	 * modules and back it with real shadow memory, just refuse to register
+	 * globals in vmalloc space.
+	 */
+
+	return ((unsigned long)addr < VMALLOC_START);
+}
+#define kasan_arch_can_register_global kasan_arch_can_register_global_book3s
+
+#define ARCH_HAS_KASAN_EARLY_SHADOW
+extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
+
+#define R_PTRS_PER_PTE	(1 << RADIX_PTE_INDEX_SIZE)
+#define R_PTRS_PER_PMD	(1 << RADIX_PMD_INDEX_SIZE)
+#define R_PTRS_PER_PUD	(1 << RADIX_PUD_INDEX_SIZE)
+extern pte_t kasan_early_shadow_pte[R_PTRS_PER_PTE];
+extern pmd_t kasan_early_shadow_pmd[R_PTRS_PER_PMD];
+extern pud_t kasan_early_shadow_pud[R_PTRS_PER_PUD];
+extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
+
+#endif
+
 #endif /* __ASSEMBLY */
 #endif
diff --git a/arch/powerpc/kernel/prom.c b/arch/powerpc/kernel/prom.c
index 4221527b082f..7ae90942d52f 100644
--- a/arch/powerpc/kernel/prom.c
+++ b/arch/powerpc/kernel/prom.c
@@ -75,6 +75,7 @@ unsigned long tce_alloc_start, tce_alloc_end;
 u64 ppc64_rma_size;
 #endif
 static phys_addr_t first_memblock_size;
+static phys_addr_t top_phys_addr;
 static int __initdata boot_cpu_count;
 
 static int __init early_parse_mem(char *p)
@@ -573,6 +574,9 @@ void __init early_init_dt_add_memory_arch(u64 base, u64 size)
 		first_memblock_size = size;
 	}
 
+	if (base + size > top_phys_addr)
+		top_phys_addr = base + size;
+
 	/* Add the chunk to the MEMBLOCK list */
 	if (add_mem_to_memblock) {
 		if (validate_mem_limit(base, &size))
@@ -616,6 +620,8 @@ static void __init early_reserve_mem_dt(void)
 static void __init early_reserve_mem(void)
 {
 	__be64 *reserve_map;
+	phys_addr_t kasan_shadow_start __maybe_unused;
+	phys_addr_t kasan_memory_size __maybe_unused;
 
 	reserve_map = (__be64 *)(((unsigned long)initial_boot_params) +
 			fdt_off_mem_rsvmap(initial_boot_params));
@@ -654,6 +660,40 @@ static void __init early_reserve_mem(void)
 		return;
 	}
 #endif
+
+#if defined(CONFIG_KASAN) && defined(CONFIG_PPC_BOOK3S_64)
+	kasan_memory_size = (unsigned long long)CONFIG_PHYS_MEM_SIZE_FOR_KASAN
+				 * 1024 * 1024;
+	if (top_phys_addr < kasan_memory_size) {
+		/*
+		 * We are doomed. Attempts to call e.g. panic() are likely to
+		 * fail because they call out into instrumented code, which
+		 * will almost certainly access memory beyond the end of
+		 * physical memory. Hang here so that at least the NIP points
+		 * somewhere that will help you debug it if you look at it in
+		 * qemu.
+		 */
+		while (true) ;
+	} else if (top_phys_addr > kasan_memory_size) {
+		/* print a biiiig warning in hopes people notice */
+		pr_err("==================================================\n"
+		       "Physical memory exceeds compiled-in maximum!\n"
+		       "This kernel was compiled for KASAN with %u MB physical"
+		       "memory\n"
+		       "The actual physical memory detected is %llu MB\n"
+		       "Memory above the compiled limit will be ignored!\n"
+		       "==================================================\n",
+		       CONFIG_PHYS_MEM_SIZE_FOR_KASAN,
+		       top_phys_addr / (1024 * 1024));
+	}
+
+	kasan_shadow_start = _ALIGN_DOWN(kasan_memory_size * 7 / 8, PAGE_SIZE);
+	DBG("reserving %llx -> %llx for KASAN",
+	    kasan_shadow_start, top_phys_addr);
+	memblock_reserve(kasan_shadow_start,
+			 top_phys_addr - kasan_shadow_start);
+#endif
+
 }
 
 #ifdef CONFIG_PPC_TRANSACTIONAL_MEM
diff --git a/arch/powerpc/mm/kasan/Makefile b/arch/powerpc/mm/kasan/Makefile
index f8f164ad8ade..1f52f688751d 100644
--- a/arch/powerpc/mm/kasan/Makefile
+++ b/arch/powerpc/mm/kasan/Makefile
@@ -4,3 +4,4 @@ KASAN_SANITIZE := n
 
 obj-$(CONFIG_PPC32)           += kasan_init_32.o
 obj-$(CONFIG_PPC_BOOK3E_64)   += kasan_init_book3e_64.o
+obj-$(CONFIG_PPC_BOOK3S_64)   += kasan_init_book3s_64.o
diff --git a/arch/powerpc/mm/kasan/kasan_init_book3s_64.c b/arch/powerpc/mm/kasan/kasan_init_book3s_64.c
new file mode 100644
index 000000000000..dce34120959b
--- /dev/null
+++ b/arch/powerpc/mm/kasan/kasan_init_book3s_64.c
@@ -0,0 +1,67 @@
+// SPDX-License-Identifier: GPL-2.0
+/*
+ * KASAN for 64-bit Book3S powerpc
+ *
+ * Copyright (C) 2019 IBM Corporation
+ * Author: Daniel Axtens <dja@axtens.net>
+ */
+
+#define DISABLE_BRANCH_PROFILING
+
+#include <linux/kasan.h>
+#include <linux/printk.h>
+#include <linux/sched/task.h>
+#include <asm/pgalloc.h>
+
+unsigned char kasan_early_shadow_page[PAGE_SIZE] __page_aligned_bss;
+
+pte_t kasan_early_shadow_pte[R_PTRS_PER_PTE] __page_aligned_bss;
+pmd_t kasan_early_shadow_pmd[R_PTRS_PER_PMD] __page_aligned_bss;
+pud_t kasan_early_shadow_pud[R_PTRS_PER_PUD] __page_aligned_bss;
+p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D] __page_aligned_bss;
+
+void __init kasan_init(void)
+{
+	int i;
+	void * k_start = kasan_mem_to_shadow((void *)RADIX_KERN_VIRT_START);
+	void * k_end = kasan_mem_to_shadow((void *)RADIX_VMEMMAP_END);
+
+	unsigned long pte_val = __pa(kasan_early_shadow_page)
+					| pgprot_val(PAGE_KERNEL) | _PAGE_PTE;
+
+	if (!early_radix_enabled())
+		panic("KASAN requires radix!");
+
+	for (i = 0; i < PTRS_PER_PTE; i++)
+		kasan_early_shadow_pte[i] = __pte(pte_val);
+
+	for (i = 0; i < PTRS_PER_PMD; i++)
+		pmd_populate_kernel(&init_mm, &kasan_early_shadow_pmd[i],
+				    kasan_early_shadow_pte);
+
+	for (i = 0; i < PTRS_PER_PUD; i++)
+		pud_populate(&init_mm, &kasan_early_shadow_pud[i],
+			     kasan_early_shadow_pmd);
+
+
+	memset(kasan_mem_to_shadow((void*)PAGE_OFFSET), KASAN_SHADOW_INIT,
+		KASAN_SHADOW_SIZE);
+
+	kasan_populate_early_shadow(k_start, k_end);
+	flush_tlb_kernel_range((unsigned long)k_start, (unsigned long)k_end);
+
+	/* mark early shadow region as RO and wipe */
+	for (i = 0; i < PTRS_PER_PTE; i++)
+		__set_pte_at(&init_mm, (unsigned long)kasan_early_shadow_page,
+			&kasan_early_shadow_pte[i],
+			pfn_pte(virt_to_pfn(kasan_early_shadow_page),
+			__pgprot(_PAGE_PTE | _PAGE_KERNEL_RO | _PAGE_BASE)),
+			0);
+	memset(kasan_early_shadow_page, 0, PAGE_SIZE);
+
+	kasan_init_tags();
+
+	/* Enable error messages */
+	init_task.kasan_depth = 0;
+	pr_info("KASAN init done (64-bit Book3S heavyweight mode)\n");
+}
-- 
2.19.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20190523052120.18459-8-dja%40axtens.net.
For more options, visit https://groups.google.com/d/optout.
