Return-Path: <kasan-dev+bncBCXLBLOA7IGBBW6OZ3XQKGQE6K6HLLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x137.google.com (mail-lf1-x137.google.com [IPv6:2a00:1450:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id 7390D11E5FB
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Dec 2019 15:59:40 +0100 (CET)
Received: by mail-lf1-x137.google.com with SMTP id x79sf391563lff.19
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Dec 2019 06:59:40 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1576249180; cv=pass;
        d=google.com; s=arc-20160816;
        b=uh4Y/WV7mfB0DTdlO7FeUnIAcPs9QcYN0TahNG9b1ZdSSi4Pt2N4o+dnMUn828e+Jz
         ApR7HrIHxv/bzR/5fTOqQbMqqpOptJx8ndO9xpmey9ISPy6K2CVT/Z1rDVTtR4xPU7hj
         mWO/p60rYUw5CdIGVi8bAa6slb59W0gLtsERDg6hmnTd/PEcpY6DS/hynRBwXrokf1R9
         xmnhj3NecJUt+nFomzoKr8nFmlYCr6XwJF7dox7o0Upt713POnb0qGZdajG7k17MQusb
         eONPXI66RcWWB6KFtL+tocjO8qFnyAGhxkUFMDN2kXtyIzpCnAaUUoXqLDf9svHb7z6r
         ejMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:date:cc:to:subject:from:message-id
         :mime-version:sender:dkim-signature;
        bh=Kn2JCcbJfXEB9tjipwmZtY1svlGQ1+L3qGJJgwWPR9w=;
        b=WINVZgpwkOsyjEQ1dMLeG/09II+HQPfwLm2lFaXgl31YB0MtQDQD/Am2EwjaKiXbg7
         yradCBA+Q44JfQ2qihLmF+73CidYGyDmuEV4eGEtQLO0/vs/UgA2eJOBdN2ziNaj/mi6
         V0ryZ/zV6DOHJ6gamyU8snVXormzZlJo5azEDKeaPJloCjhBdC1PSFbqsQEUWRP5JWOi
         w8KxMWR6MJljEp793RUFDPy/uNHoMdnwlZkp52TiZcA//5M/9BXDH1BT8BPMiHixSKme
         S6Qh1Ube1NCex/z+Yd/l2pJmD11QCUiliwaVJa/p2KN22Cp76VGCEi2TDgnKJXi365RK
         alig==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=eNsSuvgn;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:message-id:from:subject:to:cc:date
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Kn2JCcbJfXEB9tjipwmZtY1svlGQ1+L3qGJJgwWPR9w=;
        b=PoBscGTRkKrguBn4NBiyO4ti6Bvlk4P5dmk3z0vwq3TkGqzjHC1kwkMYXVQp419nHR
         mrUkaMeCX9bxfYR0ZUSVJf++ydJq84TUP64fQxctzRIfPIKf8jaze9rtWbnJaPSuhbo7
         hqX4A+qvfz9u9lH/R48CKuzBF3GA+HzywgUp98SMxO19q8aQZUASd/cz3GXAqE0p9Qi6
         UdEU7HeBOmk3W4O8uxR+zREwluBrPGDXv0Oas59zc4U1XGGfket9qQjGnl3TQ3KbSUlp
         nF48hstJH2mcXMzwllFPidBMEMhFME30mIRJgMQju0GorlTVvCU35DzWIsSa2CCYafKQ
         TbdA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:message-id:from:subject:to
         :cc:date:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Kn2JCcbJfXEB9tjipwmZtY1svlGQ1+L3qGJJgwWPR9w=;
        b=YIsQDOzclLXllNlXyqJh3IZtRYgznn5y77RN6EdtT1hwa5kxfZed6wkxRnYPz1FxOw
         ywY5WXlkKnEJxmJ2oTr9zYZk0KQLpWiPeqcVf5XfyDCMtSnces+7uRMNSTept0/v/ipz
         HIXxAOb0BY59PV4SyhxuON/tFZhioZ5+FU3vSp/EQsgiB1lVVXwWTPuIpT6BJH0pDJmS
         CJyMNE3u6QQ5Aa56t0FjQRd+dmuwLWGwJMgC2ej0pkIC14Em3pEvzSJIJkVsgKDOhPu0
         x5Hta9hAhvBUw3OwGZEl9aYit3n18oBPYPp9Fwh3ZJvuBG80PuSv7nXaNaYRr/IJDQd4
         9SNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXHLIgziXDt3wMCP5ZuHZHbRfZSp8cP07DiXcvVnaA8HmEm1ryp
	agYQVnBf8n8y+F5y4XoPOw4=
X-Google-Smtp-Source: APXvYqyAWYYg6v8WI68ibk6tDSAYgmWfLPbHe0rnOdzh6vKPCdCiCnQb2IQdo25feBWA1pQJ8xObjg==
X-Received: by 2002:a2e:980b:: with SMTP id a11mr9771709ljj.189.1576249179982;
        Fri, 13 Dec 2019 06:59:39 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:44c8:: with SMTP id d8ls923568lfm.10.gmail; Fri, 13 Dec
 2019 06:59:39 -0800 (PST)
X-Received: by 2002:ac2:4a91:: with SMTP id l17mr9442491lfp.75.1576249179320;
        Fri, 13 Dec 2019 06:59:39 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1576249179; cv=none;
        d=google.com; s=arc-20160816;
        b=vPql+lIGuNw0g36osJiDGFANiqHCJniVBCa47dE5Q7nMaYx77+JqXUeoeLyqxizUhk
         DEzfuqZjLShNqKDRq8hAbpn8TCU397LlWeDnAIYxsSliaT+NiBIth2Io04eTa7WHHkyo
         a7m/utdgDQ4qny4yuOy9ew1CRsIgOUCc/VwuaK0QoUOsQX7UEMZE6d05XansVqvnP9cn
         q6m7uJBenCY/+owrgublOPAMvedq38pl4sLj46djV6RA979nCDHG40IZl8iQit7oUHNI
         Yl93FoHd7q1N9OMUrEwlqRyiJjDOyhBuq9nNZA4vR9aQJmafVyiF7V474Tph4/PSThZ9
         +UCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=date:cc:to:subject:from:message-id:dkim-signature;
        bh=ciNClaFt4bgE8XImcN+vK2ienGGRWFLoOBnDEXiWkyo=;
        b=tYQU1YHX2K1LAHyoB+ZyK4sSfql3bXjQgrnI85/GMbUNHtGaYcl9uTfYBim1CZ/dgA
         T78o6dbAPDJqEhFKlEeG5Nn9bbbaeTTOgMyzcw9/XvqquXz146Kf3F6rmmo0KezVImjQ
         zg5G4g7rn0SOLq+BeQzxVwV+Y93MUD0O7XJxpW+HcqIECf4ez0iyBuvGL66wTZCEwCEP
         hyZwZjLG2hCtW/Ir3UwqyAnk5uMcGPlSnIFip/rTphyTQvV1Tu8tbKXJ0FRE56COWoZJ
         kYjVtGdpPkO03yqbuhi3v/hObbX3NLjUcV05fcNJiq4KT5LNw1lfT63XSVJr9R3IWmto
         jwZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b=eNsSuvgn;
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id u5si386813lfm.0.2019.12.13.06.59.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 13 Dec 2019 06:59:39 -0800 (PST)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-ext [192.168.12.233])
	by localhost (Postfix) with ESMTP id 47ZDN82bdGz9vBJg;
	Fri, 13 Dec 2019 15:59:36 +0100 (CET)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id JbWyOEqSF5fS; Fri, 13 Dec 2019 15:59:36 +0100 (CET)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 47ZDN81JZNz9vBJc;
	Fri, 13 Dec 2019 15:59:36 +0100 (CET)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id A27798B8CE;
	Fri, 13 Dec 2019 15:59:37 +0100 (CET)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id gYnh7uNCBj0G; Fri, 13 Dec 2019 15:59:37 +0100 (CET)
Received: from po16098vm.idsi0.si.c-s.fr (unknown [192.168.4.90])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 471608B8C4;
	Fri, 13 Dec 2019 15:59:37 +0100 (CET)
Received: by po16098vm.idsi0.si.c-s.fr (Postfix, from userid 0)
	id DDB6B63777; Fri, 13 Dec 2019 14:59:36 +0000 (UTC)
Message-Id: <66a26ff96689f6f84b25ed11dcff6c3818801fe7.1576248635.git.christophe.leroy@c-s.fr>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Subject: [PATCH v2] powerpc/32: add support of KASAN_VMALLOC
To: Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>, dja@axtens.net
Cc: linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, linux-mm@kvack.org
Date: Fri, 13 Dec 2019 14:59:36 +0000 (UTC)
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b=eNsSuvgn;       spf=pass (google.com:
 domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted
 sender) smtp.mailfrom=christophe.leroy@c-s.fr
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

Add support of KASAN_VMALLOC on PPC32.

To allow this, the early shadow covering the VMALLOC space
need to be removed once high_memory var is set and before
freeing memblock.

And the VMALLOC area need to be aligned such that boundaries
are covered by a full shadow page.

Signed-off-by: Christophe Leroy <christophe.leroy@c-s.fr>

---
v2: rebased ; exclude specific module handling when CONFIG_KASAN_VMALLOC is set.
---
 arch/powerpc/Kconfig                         |  1 +
 arch/powerpc/include/asm/book3s/32/pgtable.h |  5 +++++
 arch/powerpc/include/asm/kasan.h             |  2 ++
 arch/powerpc/include/asm/nohash/32/pgtable.h |  5 +++++
 arch/powerpc/mm/kasan/kasan_init_32.c        | 33 +++++++++++++++++++++++++++-
 arch/powerpc/mm/mem.c                        |  3 +++
 6 files changed, 48 insertions(+), 1 deletion(-)

diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
index 1ec34e16ed65..a247bbfb03d4 100644
--- a/arch/powerpc/Kconfig
+++ b/arch/powerpc/Kconfig
@@ -173,6 +173,7 @@ config PPC
 	select HAVE_ARCH_HUGE_VMAP		if PPC_BOOK3S_64 && PPC_RADIX_MMU
 	select HAVE_ARCH_JUMP_LABEL
 	select HAVE_ARCH_KASAN			if PPC32
+	select HAVE_ARCH_KASAN_VMALLOC		if PPC32
 	select HAVE_ARCH_KGDB
 	select HAVE_ARCH_MMAP_RND_BITS
 	select HAVE_ARCH_MMAP_RND_COMPAT_BITS	if COMPAT
diff --git a/arch/powerpc/include/asm/book3s/32/pgtable.h b/arch/powerpc/include/asm/book3s/32/pgtable.h
index 0796533d37dd..5b39c11e884a 100644
--- a/arch/powerpc/include/asm/book3s/32/pgtable.h
+++ b/arch/powerpc/include/asm/book3s/32/pgtable.h
@@ -193,7 +193,12 @@ int map_kernel_page(unsigned long va, phys_addr_t pa, pgprot_t prot);
 #else
 #define VMALLOC_START ((((long)high_memory + VMALLOC_OFFSET) & ~(VMALLOC_OFFSET-1)))
 #endif
+
+#ifdef CONFIG_KASAN_VMALLOC
+#define VMALLOC_END	_ALIGN_DOWN(ioremap_bot, PAGE_SIZE << KASAN_SHADOW_SCALE_SHIFT)
+#else
 #define VMALLOC_END	ioremap_bot
+#endif
 
 #ifndef __ASSEMBLY__
 #include <linux/sched.h>
diff --git a/arch/powerpc/include/asm/kasan.h b/arch/powerpc/include/asm/kasan.h
index 296e51c2f066..fbff9ff9032e 100644
--- a/arch/powerpc/include/asm/kasan.h
+++ b/arch/powerpc/include/asm/kasan.h
@@ -31,9 +31,11 @@
 void kasan_early_init(void);
 void kasan_mmu_init(void);
 void kasan_init(void);
+void kasan_late_init(void);
 #else
 static inline void kasan_init(void) { }
 static inline void kasan_mmu_init(void) { }
+static inline void kasan_late_init(void) { }
 #endif
 
 #endif /* __ASSEMBLY */
diff --git a/arch/powerpc/include/asm/nohash/32/pgtable.h b/arch/powerpc/include/asm/nohash/32/pgtable.h
index 552b96eef0c8..60c4d829152e 100644
--- a/arch/powerpc/include/asm/nohash/32/pgtable.h
+++ b/arch/powerpc/include/asm/nohash/32/pgtable.h
@@ -114,7 +114,12 @@ int map_kernel_page(unsigned long va, phys_addr_t pa, pgprot_t prot);
 #else
 #define VMALLOC_START ((((long)high_memory + VMALLOC_OFFSET) & ~(VMALLOC_OFFSET-1)))
 #endif
+
+#ifdef CONFIG_KASAN_VMALLOC
+#define VMALLOC_END	_ALIGN_DOWN(ioremap_bot, PAGE_SIZE << KASAN_SHADOW_SCALE_SHIFT)
+#else
 #define VMALLOC_END	ioremap_bot
+#endif
 
 /*
  * Bits in a linux-style PTE.  These match the bits in the
diff --git a/arch/powerpc/mm/kasan/kasan_init_32.c b/arch/powerpc/mm/kasan/kasan_init_32.c
index 0e6ed4413eea..88036fb88350 100644
--- a/arch/powerpc/mm/kasan/kasan_init_32.c
+++ b/arch/powerpc/mm/kasan/kasan_init_32.c
@@ -129,6 +129,31 @@ static void __init kasan_remap_early_shadow_ro(void)
 	flush_tlb_kernel_range(KASAN_SHADOW_START, KASAN_SHADOW_END);
 }
 
+static void __init kasan_unmap_early_shadow_vmalloc(void)
+{
+	unsigned long k_start = (unsigned long)kasan_mem_to_shadow((void *)VMALLOC_START);
+	unsigned long k_end = (unsigned long)kasan_mem_to_shadow((void *)VMALLOC_END);
+	unsigned long k_cur;
+	phys_addr_t pa = __pa(kasan_early_shadow_page);
+
+	if (!early_mmu_has_feature(MMU_FTR_HPTE_TABLE)) {
+		int ret = kasan_init_shadow_page_tables(k_start, k_end);
+
+		if (ret)
+			panic("kasan: kasan_init_shadow_page_tables() failed");
+	}
+	for (k_cur = k_start & PAGE_MASK; k_cur < k_end; k_cur += PAGE_SIZE) {
+		pmd_t *pmd = pmd_offset(pud_offset(pgd_offset_k(k_cur), k_cur), k_cur);
+		pte_t *ptep = pte_offset_kernel(pmd, k_cur);
+
+		if ((pte_val(*ptep) & PTE_RPN_MASK) != pa)
+			continue;
+
+		__set_pte_at(&init_mm, k_cur, ptep, __pte(0), 0);
+	}
+	flush_tlb_kernel_range(k_start, k_end);
+}
+
 void __init kasan_mmu_init(void)
 {
 	int ret;
@@ -165,7 +190,13 @@ void __init kasan_init(void)
 	pr_info("KASAN init done\n");
 }
 
-#ifdef CONFIG_MODULES
+void __init kasan_late_init(void)
+{
+	if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
+		kasan_unmap_early_shadow_vmalloc();
+}
+
+#if defined(CONFIG_MODULES) && !defined(CONFIG_KASAN_VMALLOC)
 void *module_alloc(unsigned long size)
 {
 	void *base;
diff --git a/arch/powerpc/mm/mem.c b/arch/powerpc/mm/mem.c
index 9488b63dfc87..3bb212c8ef2d 100644
--- a/arch/powerpc/mm/mem.c
+++ b/arch/powerpc/mm/mem.c
@@ -294,6 +294,9 @@ void __init mem_init(void)
 
 	high_memory = (void *) __va(max_low_pfn * PAGE_SIZE);
 	set_max_mapnr(max_pfn);
+
+	kasan_late_init();
+
 	memblock_free_all();
 
 #ifdef CONFIG_HIGHMEM
-- 
2.13.3

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/66a26ff96689f6f84b25ed11dcff6c3818801fe7.1576248635.git.christophe.leroy%40c-s.fr.
