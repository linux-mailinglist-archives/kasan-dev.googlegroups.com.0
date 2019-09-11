Return-Path: <kasan-dev+bncBCXLBLOA7IGBBXHX4PVQKGQEDE2W2BI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43d.google.com (mail-wr1-x43d.google.com [IPv6:2a00:1450:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2A6D7AFE15
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Sep 2019 15:51:25 +0200 (CEST)
Received: by mail-wr1-x43d.google.com with SMTP id o11sf10485991wrq.22
        for <lists+kasan-dev@lfdr.de>; Wed, 11 Sep 2019 06:51:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1568209884; cv=pass;
        d=google.com; s=arc-20160816;
        b=uwmS853Nzw7rD7pQfWAESi8MdaEyUpYX4CpazpoIZbHCSRtnyNqaB1J502f+E8hVw9
         1t60S5sSA3e+P030952S9nLq65e4XbQD5Vv06yuhGQJDmeTjvN6ITt3WVwlzPM3LAXcP
         aTuHtJeaSOT/oOQD8fPtKcMwcwUwiiPFeEAejw91vaUaH8ECMddN5qXQQLzpioxFqEUM
         W5IljXuAxShGuawdkqZuYG9UnpUarOXDWenUdLSmCotdEfiIuBMj5Fw6mMktdTUY+XLj
         h7yMnBbzL/jhqWrwltFIXZP4GxjTC/5jr6YmFDAtQUagW2B9mQMykKyEfFr8Ws8LVrbl
         FG/Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:date:cc:to:subject:from:message-id
         :mime-version:sender:dkim-signature;
        bh=OBIsvsRIrNngWln7wCpmEf/+7YsOmT5NdalY1ozkIHQ=;
        b=LBIeYzOnxTlntp+QsYFVyHqyXnQ0hsXqOCnZ9+XGfzDZ/wCIQPapaHnQYZd4c7vsRp
         OleSIMNfU2wNpJiCoZlb6V6dMCH11mXlA4O0iIFLWXAd2iM43+mO8DBfmXfTkhBmlLNB
         OtiSQIFnPufYLEOf8TbroCAyS0XMbg56arLbHZiUCYZsMyUI+4mlZIQ+6abkAd51mp5V
         8sNfgBQz8qne3SvEaIDfJozaQ+fHAn1zIiPFnPrDoIMxOHKwp1ked7wkYZhH1aEqUiUB
         rsDzLGphiKrDzZ4z1vp7qv7Hyq5Nk2/RJ7JNEUgY3PVejgamIPfaz2xKpyv2oYUDmPR8
         eeiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b="GMqpO/CD";
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:message-id:from:subject:to:cc:date
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=OBIsvsRIrNngWln7wCpmEf/+7YsOmT5NdalY1ozkIHQ=;
        b=ZSaucypt91JmUsZ7a2LgCjC42Gg7G27I0bwc5t5Tkj4zlL/2+wVyuFI7JzgFy+eGh4
         YJtab8EZGdd2TvKIoh8GqycbEiyhJHvqRh3SXeFSEhez6svtoUXvL7hXDX4MkrUyBFv5
         idNC4ZHmEAN+DKW58RgdqeeiIZ7WhNfXTME1qXCqytK8oDMO9kTTBbKtSH45fvU8VQPf
         v4+F9Gn/Z8vm9LMsOB5YsDEOAxNxB4kLpYuzUyxfxIRY0+q0kukKR2wR3l2f1OsVXqTr
         2iylM30m74Rv4RPlzkLFMoqahOhiFGPtHiYQa4zTU4qMwkAqUp9GyVYzXePm99OJsVwh
         1jbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:message-id:from:subject:to
         :cc:date:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OBIsvsRIrNngWln7wCpmEf/+7YsOmT5NdalY1ozkIHQ=;
        b=hegMROT6PQ2DCs3OzmOZ4khhsfwer55od3vcGYlwopqfbOV/2Xr2u4M8fzN+mRbmoM
         sxvAC4bAEVTxSx9YiLESHPFdp3eQS9UTz3PEJ7vWQi3iZekbaB47gSzr+ai6A/CMh3Cw
         sAn5eVoLcfOV4cUMbsL7ni5dRGVBUNo+cVWqUNBfNf0BpFX0SGu+kYL1sbtwW46WWbFl
         HVI90WL4dSNY0h4+PistPsWfo1O5ut9lYtVIMEWeAkqtWhbgriW0qiuK/WeccdvgIdcX
         rmQ6u/w9pSOTJXzQQIbKcNhMF7NyWw6ZJP7XaALQTmBmx8gfKVUJd5Mt+aPSU/4PyHLu
         /l6w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWQD00kGDrZ0Dcsg/GT5XsRjLn0hA7gOxaNLf9B5ENSV5pyDeam
	F6hXmZR+4I5LIAz5Dr9nPcg=
X-Google-Smtp-Source: APXvYqy64FpdBlDM175/M9/vMaUFkPGSaQsz3YIZ1JGEhAqT3cm5RnAV8vqPUNH0zusI76RbRYKi0A==
X-Received: by 2002:a7b:c445:: with SMTP id l5mr4174480wmi.93.1568209884788;
        Wed, 11 Sep 2019 06:51:24 -0700 (PDT)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:f3c4:: with SMTP id g4ls6436707wrp.4.gmail; Wed, 11 Sep
 2019 06:51:24 -0700 (PDT)
X-Received: by 2002:adf:8b13:: with SMTP id n19mr11884505wra.203.1568209884355;
        Wed, 11 Sep 2019 06:51:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1568209884; cv=none;
        d=google.com; s=arc-20160816;
        b=TmqCVw1sHfTmUdRDkJ7ZZwYM0vim2sBEBZ3UdfgWmhuBb9D66vAV/FQIFButXRZTjT
         mWwZqtJHRJcpYNmXYs+N6Z4MEwo1jb1VuMm9gM8TUtgXeacI5OvMAAMn3IPxDSsfA8BQ
         boWEaYxla3UYjtdYybNr1inA5DCjLg2Grya5XtAufuQfvUEUw2S/hW+9jvv0Qd7Uo9Lo
         GTF0p6kJ5WO/T2H+dE/atzpYhBPxf1prx+/QuFgLYmSS/m0D5AB41QSoN4wq9Lq+Xy6N
         botq4Ol9Z6Eolb2A8CnSzMYhQSTEDU9ygH7W2cz9a4HEk3ta9wHr9uqshfHlqv3Pg2Md
         Lv2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=date:cc:to:subject:from:message-id:dkim-signature;
        bh=aFoR0EE25KxrXQBvyb70fW7SuTw+tqYJ2ji2+VGVo/I=;
        b=JoYe8B/5fI2RRLjvLE0ASeHQURSNlrpeIK0DJTMDQ90tGQ8omilpP3nLeU0rxTczqx
         1wo5SULmarEh+8rj1fine9ny815V9SoIXEQX7TwpyyYJYbK+Og/K7LOksXHT0qOjWO+r
         EjWX+FhnkBHkw/gEVP7lJaCcN1iOiSvRC9zcxnBDB81mtOCqetQWy0VVsNwPte73uDbl
         /txJlgl4IGpVvITPbSzBIQHODg6VqgMZeUAaR0HBDPN6IV1eWR14hmVrRn1O6ZH1RwK1
         SjDU7DJnfP2rXXiDAULLp4y4NDlqH8VvSjK9DxyHSksDY7AjDxF3kcZtsQZkupoLJ8b8
         ntPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@c-s.fr header.s=mail header.b="GMqpO/CD";
       spf=pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
Received: from pegase1.c-s.fr (pegase1.c-s.fr. [93.17.236.30])
        by gmr-mx.google.com with ESMTPS id j4si1018112wro.5.2019.09.11.06.51.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 11 Sep 2019 06:51:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as permitted sender) client-ip=93.17.236.30;
Received: from localhost (mailhub1-int [192.168.12.234])
	by localhost (Postfix) with ESMTP id 46T3GL3TBkzB09Zl;
	Wed, 11 Sep 2019 15:51:22 +0200 (CEST)
X-Virus-Scanned: Debian amavisd-new at c-s.fr
Received: from pegase1.c-s.fr ([192.168.12.234])
	by localhost (pegase1.c-s.fr [192.168.12.234]) (amavisd-new, port 10024)
	with ESMTP id gkiGr0Q8LTXV; Wed, 11 Sep 2019 15:51:22 +0200 (CEST)
Received: from messagerie.si.c-s.fr (messagerie.si.c-s.fr [192.168.25.192])
	by pegase1.c-s.fr (Postfix) with ESMTP id 46T3GL20Z1zB09Zk;
	Wed, 11 Sep 2019 15:51:22 +0200 (CEST)
Received: from localhost (localhost [127.0.0.1])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id B9C328B8D1;
	Wed, 11 Sep 2019 15:51:23 +0200 (CEST)
X-Virus-Scanned: amavisd-new at c-s.fr
Received: from messagerie.si.c-s.fr ([127.0.0.1])
	by localhost (messagerie.si.c-s.fr [127.0.0.1]) (amavisd-new, port 10023)
	with ESMTP id s8WrJoXk0Ydr; Wed, 11 Sep 2019 15:51:23 +0200 (CEST)
Received: from localhost.localdomain (po15451.idsi0.si.c-s.fr [172.25.230.103])
	by messagerie.si.c-s.fr (Postfix) with ESMTP id 8A7258B8CB;
	Wed, 11 Sep 2019 15:51:23 +0200 (CEST)
Received: by localhost.localdomain (Postfix, from userid 0)
	id 4FCEE6B723; Wed, 11 Sep 2019 13:51:23 +0000 (UTC)
Message-Id: <01c3846a26faf47b11ba580fccded281c3b0a6ee.1568209870.git.christophe.leroy@c-s.fr>
From: Christophe Leroy <christophe.leroy@c-s.fr>
Subject: [PATCH] powerpc/32: add support of KASAN_VMALLOC
To: Benjamin Herrenschmidt <benh@kernel.crashing.org>, Paul Mackerras <paulus@samba.org>, Michael Ellerman <mpe@ellerman.id.au>,
    dja@axtens.net
Cc: linux-kernel@vger.kernel.org, linuxppc-dev@lists.ozlabs.org,
    kasan-dev@googlegroups.com,
    linux-mm@kvack.org
Date: Wed, 11 Sep 2019 13:51:23 +0000 (UTC)
X-Original-Sender: christophe.leroy@c-s.fr
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@c-s.fr header.s=mail header.b="GMqpO/CD";       spf=pass
 (google.com: domain of christophe.leroy@c-s.fr designates 93.17.236.30 as
 permitted sender) smtp.mailfrom=christophe.leroy@c-s.fr
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
Applies on top of Daniel's series which add KASAN_VMALLOC support.
---
 arch/powerpc/Kconfig                         |  1 +
 arch/powerpc/include/asm/book3s/32/pgtable.h |  5 +++++
 arch/powerpc/include/asm/kasan.h             |  2 ++
 arch/powerpc/include/asm/nohash/32/pgtable.h |  5 +++++
 arch/powerpc/mm/kasan/kasan_init_32.c        | 31 ++++++++++++++++++++++++++++
 arch/powerpc/mm/mem.c                        |  3 +++
 6 files changed, 47 insertions(+)

diff --git a/arch/powerpc/Kconfig b/arch/powerpc/Kconfig
index 6a7c797fa9d2..9d270d50ac9e 100644
--- a/arch/powerpc/Kconfig
+++ b/arch/powerpc/Kconfig
@@ -172,6 +172,7 @@ config PPC
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
index 0e6ed4413eea..fb3cd8037f19 100644
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
@@ -165,6 +190,12 @@ void __init kasan_init(void)
 	pr_info("KASAN init done\n");
 }
 
+void __init kasan_late_init(void)
+{
+	if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
+		kasan_unmap_early_shadow_vmalloc();
+}
+
 #ifdef CONFIG_MODULES
 void *module_alloc(unsigned long size)
 {
diff --git a/arch/powerpc/mm/mem.c b/arch/powerpc/mm/mem.c
index be941d382c8d..34bfe2c81f15 100644
--- a/arch/powerpc/mm/mem.c
+++ b/arch/powerpc/mm/mem.c
@@ -265,6 +265,9 @@ void __init mem_init(void)
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/01c3846a26faf47b11ba580fccded281c3b0a6ee.1568209870.git.christophe.leroy%40c-s.fr.
