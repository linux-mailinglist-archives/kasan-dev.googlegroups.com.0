Return-Path: <kasan-dev+bncBAABBIGHSKBQMGQEMA5M5II@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5E4BB35047D
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 18:30:25 +0200 (CEST)
Received: by mail-ot1-x33f.google.com with SMTP id 38sf1270859otx.19
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 09:30:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617208224; cv=pass;
        d=google.com; s=arc-20160816;
        b=EKFk01uTPjG2dkJ7SlejyXzzPUeGJAB2l1qB/Ghph3XDdLU+OObbbu8ZZzHJ1DsquL
         u25ppe1VPZ8njwePBeiwpCpMKJlV/zRH2mto5XwEnSl9WuVRoydXRmdyIRsAwcq5E47I
         DpflonlRkSgY8R3vtUh1pQTQvqyjyKqmkCJKjDMxC83eXHf43moogympY4P3NPg2824W
         Y9+OAVI8xdZj6vQZgFeFV0BYpLgojAvEZtICJ0aIgqDOnDOMthUPcog0ilzd4Ahaea3R
         q5fpPxgIPqO0GI17em37o2BaqeH0SjjA6fuMhtVeawh8edjHFkeAYJ06GYykdD1vnA/C
         I99Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=TZEOOP4Cz/Phz0VuXJRLWCJluaC1cd1k4bBKcPJMEK4=;
        b=RNyORFLX+TxQZdHWIeUsL4PWfIQz4mgV5J1ZN+vrGOWUwjwFBAjl6UAU/dGF6nwGRG
         /6jn+21ySbbXVzmzcdkL4HtwDceNaTxLVwxgfzfxGqf9qVJKjbCnoBPjvtQe4KdBN7xH
         3YVflI7A/aL6crq3Wpa24w8BHuU5GYgFo0DfzXaFUVPz6TpWH56vqPoZK2o2EXO7HlWJ
         B9wSIV2O1sE09H9A78Lp2KSPUpG/CmIepVChHrdQQWCBbgyoIXXLgswL0ARZZEMPTewU
         truzWb4n4CUnAzR3PAyzMZBIfsrJXbbNHZSfGqJdHk5QqvIAwTNmVjzrqA7qFy5PHCtR
         iwpw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=HibTMtPM;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=TZEOOP4Cz/Phz0VuXJRLWCJluaC1cd1k4bBKcPJMEK4=;
        b=gtdXYALmRZvnOf+yJUYEUWW9sFGZOUBBmQshGArI6jMH5mgF4Tb+Cpmlp8mgdX7Ozu
         wr6l+S6pD9fcAe51SQNprC/zSRPUVd5m0+Jgox+c5K8U+XtzeN5bK4r0pMECplwPPj3O
         YDGjHMSI+NG6CoqusWxLmhEQvpCUXMHuc22uheVu+e1sHmiFE7zH83FWHgNViFUoO0Wd
         6cbqA+/gHwEHC3eZ+P24FfiQg1ssNgnfsL9WVOEzsJcrZLwij6zSfqKN0Vr/j+ruZufn
         cBlYm1uQbUwsLxEXgRg0AVz3XSa6Fi/5gAaQMAz2jtQZdoEzUQMNmWCN7J5ow21WzcXh
         O1hw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TZEOOP4Cz/Phz0VuXJRLWCJluaC1cd1k4bBKcPJMEK4=;
        b=axDbXVzybJbETkP9/CBWw86gB1v6dXxR0D7nDUNVM9897GCnqQ2YQUyio9dv7ut6Pr
         3aWsEtqQFFY20di7eofTEbo9S97dx/35lpdVZzcfZsX6LUKvvOMoEY4+iBVL3zv4I4mR
         TZSRv0ysQCATtxe43GawaPrjDrNF9knQEcDjGx4M/dut4e9GPQyeTnDoC0NE1xA+udtA
         FgH/zcL9Xzqptf+PIBpgApPpO8EwL71fLGoqKVVFgaP4BHKQ2ZfECDRE6C4lcqJYMP4y
         EMiStZt+NSuv7Q40lnirtycCkjpbU+rP0wmIvn4HR1hy1vSCsJ3dK8wTu2W8xmuz5sc6
         YHmg==
X-Gm-Message-State: AOAM530xoHsJwMjdETbZKMvEzn1WmkWDw2wZriS67wqgZn6oxFC4+yVk
	T3WH1nbXiVOhJnIljrK30IQ=
X-Google-Smtp-Source: ABdhPJyIsD2wEr/WfeGMcMnaQWAgCZn7qEft/gGqpZ7HypXDJpBlqJUNZneEIjoz5Q+yXSrcMxLlnw==
X-Received: by 2002:a4a:d2cc:: with SMTP id j12mr3418029oos.56.1617208224387;
        Wed, 31 Mar 2021 09:30:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:4c55:: with SMTP id z82ls622449oia.2.gmail; Wed, 31 Mar
 2021 09:30:24 -0700 (PDT)
X-Received: by 2002:a54:4494:: with SMTP id v20mr2845969oiv.147.1617208224113;
        Wed, 31 Mar 2021 09:30:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617208224; cv=none;
        d=google.com; s=arc-20160816;
        b=kdPZgnOpWwbmLLJLkhRPuqu2mYGtLeKB1hQgJtTTLTEuHTn7UZckV3xwVfn5be/roC
         +YE+g31/5zx1HK1DvxYrHchb0A8whCb7YkcuNmu+P6CRvRm9EOOtb7y8LWRNCtQBvedz
         xAxlG0wMhryh1s1bVry+LRDOX1muqbKnka7dwkISfUJLLp/O1dmF7zK+mbs0ji3o6mYl
         MCAOQCIgXYgpiE78FItM34gONSlfGKFs3d9UZF8aTcZ9k3/4ivO1rSnSc+BeWr2Ruh3z
         7RhL9a9NDdL+N5SjmpifbZCMnVPqE16R46vHixr+2/fTLApCgCwGPGfmacRKObOG7Elg
         5qWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=DB/sloEYmz7VRvujZiwTWQcY6o1S+cvefBjxUT4Goqw=;
        b=NfqP3bTVYMaXa0hEh4mY+rA6qwHK6mt8ZKH59UDFaDDAHeU87Ql5xuqvpN27EtgYn/
         tuuZe+5CISkCaVnE04Bplw3M5vkEFDD+jCh3nHskw8igRg1Vx5Kr6t4wwgqGPSUKFjTk
         Xj27AZ4pinfznrrQRRU3tKJ28xmYvNdgJdBYmWbE0w4k30QC0MCANfh44YrXw6JLzD+N
         WGDISSPPLE+vHjFXI6nss7+y5O/bZFol0RDylG4w0dOYVHnJRo2gNvMcGgOAMunwCJkt
         B5TTpC9V3E1krMKmD5rGwWZaRjdUrYO2VdZvRENAAIflmAKlS60u0YNDVkUb9ejXoiqo
         rP7g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=HibTMtPM;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id i14si258682ots.4.2021.03.31.09.30.21
        for <kasan-dev@googlegroups.com>;
        Wed, 31 Mar 2021 09:30:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.19.180])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygDn7EyWo2Rgrbt6AA--.6768S2;
	Thu, 01 Apr 2021 00:30:15 +0800 (CST)
Date: Thu, 1 Apr 2021 00:25:18 +0800
From: "'Jisheng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt 
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin 
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey 
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, " 
 =?UTF-8?B?QmrDtnJuIFTDtnBlbA==?=" <bjorn@kernel.org>, Alexei Starovoitov 
 <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, Andrii Nakryiko 
 <andrii@kernel.org>, Song Liu  <songliubraving@fb.com>, Yonghong Song
 <yhs@fb.com>, John Fastabend  <john.fastabend@gmail.com>, KP Singh
 <kpsingh@kernel.org>, Luke Nelson  <luke.r.nels@gmail.com>, Xi Wang
 <xi.wang@gmail.com>
Cc: linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, netdev@vger.kernel.org, bpf@vger.kernel.org
Subject: [PATCH v2 1/9] riscv: add __init section marker to some functions
Message-ID: <20210401002518.5cf48e91@xhacker>
In-Reply-To: <20210401002442.2fe56b88@xhacker>
References: <20210401002442.2fe56b88@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygDn7EyWo2Rgrbt6AA--.6768S2
X-Coremail-Antispam: 1UD129KBjvJXoWxuryfXrWUJry5ur48ur4xtFb_yoW5KFyUpr
	WkKa1kZFWYkFWvga9rAry8ur1UJ3Zaka43trsFkas8XF17ur45X34kW3yqvr1UJFWkuayr
	A34rAry5Aw4DAa7anT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUklb7Iv0xC_tr1lb4IE77IF4wAFF20E14v26ryj6rWUM7CY07I2
	0VC2zVCF04k26cxKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rw
	A2F7IY1VAKz4vEj48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Xr0_Ar1l84ACjcxK6xII
	jxv20xvEc7CjxVAFwI0_Gr1j6F4UJwA2z4x0Y4vEx4A2jsIE14v26F4j6r4UJwA2z4x0Y4
	vEx4A2jsIEc7CjxVAFwI0_Gr1j6F4UJwAS0I0E0xvYzxvE52x082IY62kv0487Mc02F40E
	FcxC0VAKzVAqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUGVWUXwAv7VC2z280aVAFwI0_Jr
	0_Gr1lOx8S6xCaFVCjc4AY6r1j6r4UM4x0Y48IcVAKI48JM4IIrI8v6xkF7I0E8cxan2IY
	04v7MxAIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8CrVAFwI
	0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVW8ZVWrXwCIc40Y
	0x0EwIxGrwCI42IY6xIIjxv20xvE14v26r1j6r1xMIIF0xvE2Ix0cI8IcVCY1x0267AKxV
	W8JVWxJwCI42IY6xAIw20EY4v20xvaj40_Gr0_Zr1lIxAIcVC2z280aVAFwI0_Jr0_Gr1l
	IxAIcVC2z280aVCY1x0267AKxVW8JVW8JrUvcSsGvfC2KfnxnUUI43ZEXa7IU81GQDUUUU
	U==
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=HibTMtPM;       spf=pass
 (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as
 permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
X-Original-From: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
Reply-To: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
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

From: Jisheng Zhang <jszhang@kernel.org>

They are not needed after booting, so mark them as __init to move them
to the __init section.

Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
---
 arch/riscv/kernel/traps.c  | 2 +-
 arch/riscv/mm/init.c       | 6 +++---
 arch/riscv/mm/kasan_init.c | 6 +++---
 arch/riscv/mm/ptdump.c     | 2 +-
 4 files changed, 8 insertions(+), 8 deletions(-)

diff --git a/arch/riscv/kernel/traps.c b/arch/riscv/kernel/traps.c
index 1357abf79570..07fdded10c21 100644
--- a/arch/riscv/kernel/traps.c
+++ b/arch/riscv/kernel/traps.c
@@ -197,6 +197,6 @@ int is_valid_bugaddr(unsigned long pc)
 #endif /* CONFIG_GENERIC_BUG */
 
 /* stvec & scratch is already set from head.S */
-void trap_init(void)
+void __init trap_init(void)
 {
 }
diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
index 067583ab1bd7..76bf2de8aa59 100644
--- a/arch/riscv/mm/init.c
+++ b/arch/riscv/mm/init.c
@@ -57,7 +57,7 @@ static void __init zone_sizes_init(void)
 	free_area_init(max_zone_pfns);
 }
 
-static void setup_zero_page(void)
+static void __init setup_zero_page(void)
 {
 	memset((void *)empty_zero_page, 0, PAGE_SIZE);
 }
@@ -75,7 +75,7 @@ static inline void print_mlm(char *name, unsigned long b, unsigned long t)
 		  (((t) - (b)) >> 20));
 }
 
-static void print_vm_layout(void)
+static void __init print_vm_layout(void)
 {
 	pr_notice("Virtual kernel memory layout:\n");
 	print_mlk("fixmap", (unsigned long)FIXADDR_START,
@@ -557,7 +557,7 @@ static inline void setup_vm_final(void)
 #endif /* CONFIG_MMU */
 
 #ifdef CONFIG_STRICT_KERNEL_RWX
-void protect_kernel_text_data(void)
+void __init protect_kernel_text_data(void)
 {
 	unsigned long text_start = (unsigned long)_start;
 	unsigned long init_text_start = (unsigned long)__init_text_begin;
diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
index 4f85c6d0ddf8..e1d041ac1534 100644
--- a/arch/riscv/mm/kasan_init.c
+++ b/arch/riscv/mm/kasan_init.c
@@ -60,7 +60,7 @@ asmlinkage void __init kasan_early_init(void)
 	local_flush_tlb_all();
 }
 
-static void kasan_populate_pte(pmd_t *pmd, unsigned long vaddr, unsigned long end)
+static void __init kasan_populate_pte(pmd_t *pmd, unsigned long vaddr, unsigned long end)
 {
 	phys_addr_t phys_addr;
 	pte_t *ptep, *base_pte;
@@ -82,7 +82,7 @@ static void kasan_populate_pte(pmd_t *pmd, unsigned long vaddr, unsigned long en
 	set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa(base_pte)), PAGE_TABLE));
 }
 
-static void kasan_populate_pmd(pgd_t *pgd, unsigned long vaddr, unsigned long end)
+static void __init kasan_populate_pmd(pgd_t *pgd, unsigned long vaddr, unsigned long end)
 {
 	phys_addr_t phys_addr;
 	pmd_t *pmdp, *base_pmd;
@@ -117,7 +117,7 @@ static void kasan_populate_pmd(pgd_t *pgd, unsigned long vaddr, unsigned long en
 	set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(base_pmd)), PAGE_TABLE));
 }
 
-static void kasan_populate_pgd(unsigned long vaddr, unsigned long end)
+static void __init kasan_populate_pgd(unsigned long vaddr, unsigned long end)
 {
 	phys_addr_t phys_addr;
 	pgd_t *pgdp = pgd_offset_k(vaddr);
diff --git a/arch/riscv/mm/ptdump.c b/arch/riscv/mm/ptdump.c
index ace74dec7492..3b7b6e4d025e 100644
--- a/arch/riscv/mm/ptdump.c
+++ b/arch/riscv/mm/ptdump.c
@@ -331,7 +331,7 @@ static int ptdump_show(struct seq_file *m, void *v)
 
 DEFINE_SHOW_ATTRIBUTE(ptdump);
 
-static int ptdump_init(void)
+static int __init ptdump_init(void)
 {
 	unsigned int i, j;
 
-- 
2.31.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210401002518.5cf48e91%40xhacker.
