Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBC4NW64AMGQEERIQCCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id D601E99DB8D
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Oct 2024 03:34:04 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-2e2de6496easf3528471a91.1
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2024 18:34:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1728956043; cv=pass;
        d=google.com; s=arc-20240605;
        b=aWf/x/N8ug261tg5mcyodpg6YNRpmrdxjchJTQYK52iUSpGAC9J9wzplmmRBlhFxkN
         8432BP8bNt+cwHSibkVeFT4sprADr8zPKwYF9+D7jy0tWLqiN+DqTuNby0ybA7Wizxtp
         LmJ8zBTjhXFX0WWNpNY77z4uJZVLR7eyZRgSckugkdL/8TAhN14eHPHjPfk+2cVHASYW
         5RvzQ4ZCNYqUKEMMy/uRouSM74Kx81sRp+s6aGPWniFd/uYUE5f8Ur91egJdRaMnXlRy
         F0jGKDiF/WQzipt4jPKBNmYfA19XOeXp7eySXsXO7g3TzM5K593Vt2IeeZy1rNqVfvFE
         Ib+w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=pHNbQBIT+oGu2tpYbOrAXZ9IiEgOaCFsDAuAxtRnRnk=;
        fh=QUt9UCxuBpp4I49/zE2yxhsPTwki7wX+H0H/HFCAQVw=;
        b=lkKWuU7dGgL1zyylemPLvU+LVL9Zr90aLKH1BDnSUsUlNcklGpI0cQ3f2+fe5yduBr
         WuQgIsxDw1mL0nECoBbEwy4DxZt/YapdYrIw+ZCWcRjOZp4bL8MGw81ra2TNJXKpGM0m
         YPkQ9WM8jrRSe0upTjmeX3JyE8ILbPOlGPo7AWLVZAMqNslc3EvFZvyZ98ChhkZU/dW0
         Ihr9nzP4lZm5DEWyciPW1iULllo+GLjmzEfzAmDPk0Zf9Vevq45jiz70/7mNR9jLHRkz
         pkDZQdifnCaB4JzgKWkxUgRtx5R0G/1/6C/4yipf8HUWOz7kHeGDGmspaBDT46I3GoF2
         yWww==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hwcKpgMs;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1728956043; x=1729560843; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=pHNbQBIT+oGu2tpYbOrAXZ9IiEgOaCFsDAuAxtRnRnk=;
        b=MkjDDWhy8tmOH20f5s8US46UJ4e452SB744DoyTW4IaiAqFKq4Tyg4Gjek6qhl2wUE
         iPjUNt6HEvEW9ROUGQDiqLCygGx+adN2uyXfOwCF73XEukH8FgAhJ3qKcBV44nrGPkTY
         OzSdTAvsEFiGuh/10sLvwu8+mfkndxDxpA6G1xjCUDgXgsDB+HQWgWlhOVJS+y0Xg0XT
         1who1/9p+9nPRBazaCIonjf+oMbUrECEzrkfGh/Z3Rtt0JTBgXUs3J2p50FkF13kwqct
         SO4zknAQupnn3eN1p5JEEvw4TgmkbiSKqjB1sYSg84H9sv/B5Zpxe8h1HduYUob0Rj3p
         vU+A==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1728956043; x=1729560843; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=pHNbQBIT+oGu2tpYbOrAXZ9IiEgOaCFsDAuAxtRnRnk=;
        b=l1TCttnBGV6sSHCtk0vdlBC0luoOmejaAZ1+OQX/pLsrpkLdt+hvRqo17WutZjssIg
         pRq0JRzreaXMN3BX07iZQBbQduUFSr6/Zj3175Dr4wt0pfZgSEI8BjYLy4xzmHYaCPkR
         ZYnAH39foZxPLmYq0GtCuhjTWqWachY+sAA1u4RJi6Z5KL2kdV+Rh3iH0MLXMZ+dUvEF
         G7CUGGOkrA6/wWXbAsU0BDAyAIzEHR0CoYuXJXyM7gh+CTGtfHHKhFV0UvTr88tlyPbL
         ANRPpBml4+dQ9Og94KrINy8QEEzrIEZGzGfygCpSvWWtU0ZTWP8hw6M0+xvp+LKfRxxZ
         OUyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1728956043; x=1729560843;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=pHNbQBIT+oGu2tpYbOrAXZ9IiEgOaCFsDAuAxtRnRnk=;
        b=PAGgs8iVzb/gUcB5HfCmBr4AAt5C06RK5N1CiqQWeBYQ5KpdqkxwlUWeC/9X+q5xvA
         8M9mhCq1tcdL2OxEqukoy04vbbii9DpAdehH7aOcGyqc8EP04aQzI/STZFc1+yUqqaiJ
         UCNMOMkrEuVKTXlz6L0DaDOrjADLYtvea9U1NNF/A3EU5V9y0AbTq8QErFjytkFHaT7u
         IYw6X8lZtFloZfrwtlKASKGQiPzh7TkEVbWffezupYqN1jJYReoxvas2PES4lM4akHqB
         jxsPKyBCRu+7xh+9Hyd3knsTJrqyFEX7QwouZIzV3xYTo2bBksqCWAjsNUp9tGs+v7/H
         fLWA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXjwLZIfvPpqsNh0JIMo9Ffdpgkzyc43wWjyaiN3U9ehM5GAm/vsDFhr/CDbgInVyAj6upmAg==@lfdr.de
X-Gm-Message-State: AOJu0YxAeGC0xGrwHPDMU+6wSrATwVW9t35C7SUU9QRZ7k4KstPGNaoq
	44AiMQv3fi59t3a82QYi6Hj/Mbs0TY0EhlHHAcVrsXWPkypcwuew
X-Google-Smtp-Source: AGHT+IHtwf0D8ceWas2iXMQuWWDJJ9VfLkVEUlte3tvwivdhq/nlGMPGgPDdHUT1sEEvjYNvnC2feQ==
X-Received: by 2002:a17:90b:4d91:b0:2e2:bb32:73e7 with SMTP id 98e67ed59e1d1-2e2f0d7c8e2mr20658175a91.15.1728956043358;
        Mon, 14 Oct 2024 18:34:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90b:2351:b0:2e3:1fce:882 with SMTP id
 98e67ed59e1d1-2e31fce09c3ls1352178a91.2.-pod-prod-00-us-canary; Mon, 14 Oct
 2024 18:34:02 -0700 (PDT)
X-Received: by 2002:a05:6a20:db0a:b0:1d2:e8f6:7f3 with SMTP id adf61e73a8af0-1d8bc85d1b9mr21963438637.11.1728956042050;
        Mon, 14 Oct 2024 18:34:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728956042; cv=none;
        d=google.com; s=arc-20240605;
        b=kXsqGtMGuZZzihZaWyU9Y1qXRKEMLcLkK6usw4XuY/dcT12EsUa/fR5Kz71b9WOMD4
         f1PPdmo+VhUMzipRLJW4OSpQAPnTmeqpByrkj0mz7902IUeYFqtPnnHBHcvxX9vN7FbH
         /qWiAh4aKxYAgkdBZcJLJgH0TlzmUIuNzyH6vvwBlOxgCTvd8p0nHPxs2zoAKijtKrTZ
         j6G/a4TVo/fTq0s671ZN9IOyyxkfjImj4/wPo3rDBf7eR/C3wIX+ESkEXZWBFq2yqIKJ
         QlSUKDGre2gQCYbaGhB/+bcKcifjymcyqSSes1c9tA276MOI/I+DosPSMMNaeWC0W5Vh
         2W3w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=9gdBU6NTSnQ45ASWgUOhpCdQmMAIjthCFPvKHCG5k1I=;
        fh=Bj4mozzLk9zJsLtJNyH+nEsVaBAd92VPaXopXx18a2s=;
        b=NnDYvahXg/+ki8O8l+dwcrjpFDpiuCJwDqS9AvWbdEA5DXUmM32YlqHTx4Tx59Unt+
         GAryu0Jd4/jCZQTB+FRjqfXzMy07CNOI0Sxrlpv+N+MhW/HJT2M52aKAKcVk57ngqF9F
         AhniS9yj0EYrli28gDqTTod/7GoWuU7ByE02zBouiKVfuBv19mOfW9g+6/rBV01gPkRK
         TMq8nC+cgMm9qR9ysgyTUlJGXf+1edHJVMVvaujTYBaaE52H+erQFPUBJt7rw+iTdEov
         +myQSh7urOmgltf4gWVfX8Ech+RPn/V93/dl23V7lewn/qErUP1RLD2oKjy/30IDsizp
         VrjQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=hwcKpgMs;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x431.google.com (mail-pf1-x431.google.com. [2607:f8b0:4864:20::431])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-71e7767596fsi14844b3a.6.2024.10.14.18.34.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2024 18:34:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::431 as permitted sender) client-ip=2607:f8b0:4864:20::431;
Received: by mail-pf1-x431.google.com with SMTP id d2e1a72fcca58-71e49ef3bb9so1961325b3a.1
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2024 18:34:02 -0700 (PDT)
X-Received: by 2002:a62:f252:0:b0:71e:5709:2330 with SMTP id d2e1a72fcca58-71e570923afmr12036633b3a.7.1728956041587;
        Mon, 14 Oct 2024 18:34:01 -0700 (PDT)
Received: from dw-tp.. ([171.76.80.151])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71e77508562sm189349b3a.186.2024.10.14.18.33.57
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 14 Oct 2024 18:34:01 -0700 (PDT)
From: "Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
To: linuxppc-dev@lists.ozlabs.org
Cc: kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	Marco Elver <elver@google.com>,
	Alexander Potapenko <glider@google.com>,
	Heiko Carstens <hca@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Hari Bathini <hbathini@linux.ibm.com>,
	"Aneesh Kumar K . V" <aneesh.kumar@kernel.org>,
	Donet Tom <donettom@linux.vnet.ibm.com>,
	Pavithra Prakash <pavrampu@linux.vnet.ibm.com>,
	LKML <linux-kernel@vger.kernel.org>,
	"Ritesh Harjani (IBM)" <ritesh.list@gmail.com>
Subject: [RFC RESEND v2 03/13] book3s64/hash: Remove kfence support temporarily
Date: Tue, 15 Oct 2024 07:03:26 +0530
Message-ID: <00ba1fdbf7e135fab9d3d1c8872674079452446a.1728954719.git.ritesh.list@gmail.com>
X-Mailer: git-send-email 2.46.0
In-Reply-To: <cover.1728954719.git.ritesh.list@gmail.com>
References: <cover.1728954719.git.ritesh.list@gmail.com>
MIME-Version: 1.0
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=hwcKpgMs;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::431
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Kfence on book3s Hash on pseries is anyways broken. It fails to boot
due to RMA size limitation. That is because, kfence with Hash uses
debug_pagealloc infrastructure. debug_pagealloc allocates linear map
for entire dram size instead of just kfence relevant objects.
This means for 16TB of DRAM it will require (16TB >> PAGE_SHIFT)
which is 256MB which is half of RMA region on P8.
crash kernel reserves 256MB and we also need 2048 * 16KB * 3 for
emergency stack and some more for paca allocations.
That means there is not enough memory for reserving the full linear map
in the RMA region, if the DRAM size is too big (>=16TB)
(The issue is seen above 8TB with crash kernel 256 MB reservation).

Now Kfence does not require linear memory map for entire DRAM.
It only needs for kfence objects. So this patch temporarily removes the
kfence functionality since debug_pagealloc code needs some refactoring.
We will bring in kfence on Hash support in later patches.

Signed-off-by: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
---
 arch/powerpc/include/asm/kfence.h     |  5 +++++
 arch/powerpc/mm/book3s64/hash_utils.c | 16 +++++++++++-----
 2 files changed, 16 insertions(+), 5 deletions(-)

diff --git a/arch/powerpc/include/asm/kfence.h b/arch/powerpc/include/asm/kfence.h
index fab124ada1c7..f3a9476a71b3 100644
--- a/arch/powerpc/include/asm/kfence.h
+++ b/arch/powerpc/include/asm/kfence.h
@@ -10,6 +10,7 @@

 #include <linux/mm.h>
 #include <asm/pgtable.h>
+#include <asm/mmu.h>

 #ifdef CONFIG_PPC64_ELF_ABI_V1
 #define ARCH_FUNC_PREFIX "."
@@ -25,6 +26,10 @@ static inline void disable_kfence(void)

 static inline bool arch_kfence_init_pool(void)
 {
+#ifdef CONFIG_PPC64
+	if (!radix_enabled())
+		return false;
+#endif
 	return !kfence_disabled;
 }
 #endif
diff --git a/arch/powerpc/mm/book3s64/hash_utils.c b/arch/powerpc/mm/book3s64/hash_utils.c
index e1eadd03f133..296bb74dbf40 100644
--- a/arch/powerpc/mm/book3s64/hash_utils.c
+++ b/arch/powerpc/mm/book3s64/hash_utils.c
@@ -431,7 +431,7 @@ int htab_bolt_mapping(unsigned long vstart, unsigned long vend,
 			break;

 		cond_resched();
-		if (debug_pagealloc_enabled_or_kfence() &&
+		if (debug_pagealloc_enabled() &&
 			(paddr >> PAGE_SHIFT) < linear_map_hash_count)
 			linear_map_hash_slots[paddr >> PAGE_SHIFT] = ret | 0x80;
 	}
@@ -814,7 +814,7 @@ static void __init htab_init_page_sizes(void)
 	bool aligned = true;
 	init_hpte_page_sizes();

-	if (!debug_pagealloc_enabled_or_kfence()) {
+	if (!debug_pagealloc_enabled()) {
 		/*
 		 * Pick a size for the linear mapping. Currently, we only
 		 * support 16M, 1M and 4K which is the default
@@ -1134,7 +1134,7 @@ static void __init htab_initialize(void)

 	prot = pgprot_val(PAGE_KERNEL);

-	if (debug_pagealloc_enabled_or_kfence()) {
+	if (debug_pagealloc_enabled()) {
 		linear_map_hash_count = memblock_end_of_DRAM() >> PAGE_SHIFT;
 		linear_map_hash_slots = memblock_alloc_try_nid(
 				linear_map_hash_count, 1, MEMBLOCK_LOW_LIMIT,
@@ -2120,7 +2120,7 @@ void hpt_do_stress(unsigned long ea, unsigned long hpte_group)
 	}
 }

-#if defined(CONFIG_DEBUG_PAGEALLOC) || defined(CONFIG_KFENCE)
+#ifdef CONFIG_DEBUG_PAGEALLOC
 static DEFINE_RAW_SPINLOCK(linear_map_hash_lock);

 static void kernel_map_linear_page(unsigned long vaddr, unsigned long lmi)
@@ -2194,7 +2194,13 @@ int hash__kernel_map_pages(struct page *page, int numpages, int enable)
 	local_irq_restore(flags);
 	return 0;
 }
-#endif /* CONFIG_DEBUG_PAGEALLOC || CONFIG_KFENCE */
+#else /* CONFIG_DEBUG_PAGEALLOC */
+int hash__kernel_map_pages(struct page *page, int numpages,
+					 int enable)
+{
+	return 0;
+}
+#endif /* CONFIG_DEBUG_PAGEALLOC */

 void hash__setup_initial_memory_limit(phys_addr_t first_memblock_base,
 				phys_addr_t first_memblock_size)
--
2.46.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/00ba1fdbf7e135fab9d3d1c8872674079452446a.1728954719.git.ritesh.list%40gmail.com.
