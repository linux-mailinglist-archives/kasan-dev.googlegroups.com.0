Return-Path: <kasan-dev+bncBAABBDNYRCBQMGQE2FKJKUY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x737.google.com (mail-qk1-x737.google.com [IPv6:2607:f8b0:4864:20::737])
	by mail.lfdr.de (Postfix) with ESMTPS id DD56D34D706
	for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 20:27:26 +0200 (CEST)
Received: by mail-qk1-x737.google.com with SMTP id g18sf12810994qki.15
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 11:27:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617042446; cv=pass;
        d=google.com; s=arc-20160816;
        b=CqYk2hWTHPDqfrAgf+mfv0eiVQBnspKrhls5BOgMVhy6t3aqfnVlxj5w7+rDYD/d2I
         D1+NrWkW14NQKWs85Fcb0PvaXCZiEeT8ZWmlDfgXI9p58OT8BWCZZEhzbv8QHzVzNlN3
         9w2auCRvaHVd3FAmcSZRzDhFEcxvuIn0t7nwxqJnVqRwZa8DzH91onnVaOU+9Xi9UPmd
         eehS2AAOkcPIzfI9QaVpjH+30MtmF0tX2dWuRxvlDz+gR2+LIosxVLcAZt43A+T3nqiZ
         WgOea61fBLWKl5dr+TSUrM3YkDbsBguAnNadlJ83DTVHb8i3+/Q2dmDbjCceWKgxHlOv
         7Ldg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=BUeigX/CGhkopwBKnyNY8XPxj9US9vZcCiQ7lORUsdQ=;
        b=Cj8L2JHA7fBGblXCbVJOrr4HawDmO+I1tyy9VzReO6UlH9645VIA4Ul4y/iHz7E5rj
         pnFgOvx53nX4Jm3A/MOrkdb1hkc7r3bVKKMTHzBz8+aqxvNBfdw8UB3INd53zXe6mPmr
         s8HTcbelZ1JBsr4XfJ9UjEJF/zQBlgyIJzZpOU6bxz6eoPOtI8+TLr90EgWWhZFgQzv/
         /AAMghjUtRRPYYKrso+pI2URkCut+szSMx63xwHsnpI7pnzbU5yZeGmQ68Og5x6gwr2l
         AE+did29ByphiDUrfnZYgqg5C1Dg5Wa53elFz26pXdLvzF12xiECir5DZnRTpwJ1NgSn
         dUzQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=JHPuSark;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=BUeigX/CGhkopwBKnyNY8XPxj9US9vZcCiQ7lORUsdQ=;
        b=QNH+Wsk1O+hFmIREMXwsZRpPzGH9R+0DA/pO4+MueW3vIz+GrUXyqDZtSRi3oBsvHG
         oJUcYYtGYOgap4GUYWeuAXSmRLsK60231j9fZ1SBmvGqM+lPaBh7ZFRjgNHUh3UABShD
         bXLprJJbQJYe1U1N9AQDgcVbYXft0ZHyAWMoUI4k1C4cMz69hbmtZSNUBY6OnFKm+C8C
         Q0KWSdRXyj2DY26D8+4U0D8sQvAT6iyLepwgin98vtJsdO1HYUcSJ1C10M5+8c+UUXAm
         n7OeWB6iuumRv3oqHNQhHV5t2VYJPvY2m7YxdyrzoXOMVbVH76AFJDM4fUIQFw+gdTYB
         WUig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:in-reply-to
         :references:mime-version:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=BUeigX/CGhkopwBKnyNY8XPxj9US9vZcCiQ7lORUsdQ=;
        b=RqAm7rs5FnvW7AECXh5HPoIUb85abxNVxPb+t/sfxQXDOtLS0NgXK8YEWqki/wjvIr
         +KVtB0chflxXFWujZc84J78mtZQ8zenljYLvsZYh+gv8BXIv+Bu7zXdSUZONvDQ0pb/F
         AeWOJhHUXu4pBNhUscejIGOZPCFgAdJ45Zv7/VR2rjnDvl9G1MDIXftK8Ugx5HCE4GcH
         fWNL0eAAku9RIvqzRwf0EmrrxmNvFV9id50wXXCX8IO9kQbbXXWnvat2LjipKVSQ+p2q
         DQeXOJHyI5MNpm5nMNrw2pTl/YXd75M5iuDUaAO7uHEy0Zv8MhZT6XWt/lMvzczg/EJr
         j7EQ==
X-Gm-Message-State: AOAM533tYnirsVobL2JzuFeDlXXRFS0jNTAQBSgnC50gAO/2xbUrP80K
	GeT+xKZjGQVvJopo4Nxhki0=
X-Google-Smtp-Source: ABdhPJzQGG1yTK5nxU3J683mBTa4oevcNOoBkxFMePUmcjHKIbXNziQxgOKwoIeaqtOrAB4a87n7Ow==
X-Received: by 2002:a37:a08e:: with SMTP id j136mr26559488qke.266.1617042446060;
        Mon, 29 Mar 2021 11:27:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:4c6:: with SMTP id q6ls6290836qtx.6.gmail; Mon, 29
 Mar 2021 11:27:25 -0700 (PDT)
X-Received: by 2002:a05:622a:114:: with SMTP id u20mr23597029qtw.317.1617042445685;
        Mon, 29 Mar 2021 11:27:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617042445; cv=none;
        d=google.com; s=arc-20160816;
        b=UdPZSLACe4dC7dHCIVtarMbnKfVprhuNCVCe+ZOCQsicqEKMyCPCFCPu86lgV0KYXM
         sq5Rw0u6TTNH483H+Csh72WAVpzfuTUyRdWT+j+UHlpqqWUsqeBS8UN9X5fduGUmZksL
         304owU375BGbGg+vnkyr04GS4tfMYvcth596KJMsyfy1IqCwFLnV43S1F+GWPg4vU1F4
         wP9oRPXIQ2o3Ng9oQr2QXTujuQuFH95/b/wf8hYgV/iPHlfAS+74d97kI7kwfNXSG/QU
         uOdGMlUZdMWWqvPW9fqfK1fObugqCa1IVv+FCNHA7095gC+XoIdPNE31QXkcGc5kbNTP
         xWLQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=DB/sloEYmz7VRvujZiwTWQcY6o1S+cvefBjxUT4Goqw=;
        b=yFlqTSKW/sH/m7Pe2KX6qjsq7qUr8veVnHM6ONNOghXE1Kc/crEVBWKDV/YQ7cAnCA
         2BfAB8Q5CiqB62uGxSn4dbkqXdvirxQHX3vE+t6a4WNKEOTBz3OBw2xdktKSkDau1+Zf
         tPzvpOYaQAGGp8TXi4m0tPSHJ+2ZBAHQ0sbK2eqBylPSW9c9ftNvrTxOO/121QfTXUUG
         v+ieoeoUJIOfSNhggGowD/q/fZ29mMavWLk7OrH8HO2wEABOMlpjuLt9/tpHZYMEAseO
         Pwj+tRbu+/3ypRJHSCprCwVNfrxlN2cM1NLZjd0leQjQxB8TZAnuGgDn77GAgyuFYFn3
         T6tQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mail.ustc.edu.cn header.s=dkim header.b=JHPuSark;
       spf=pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) smtp.mailfrom=jszhang3@mail.ustc.edu.cn;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=mail.ustc.edu.cn
Received: from ustc.edu.cn (smtp2.ustc.edu.cn. [202.38.64.46])
        by gmr-mx.google.com with ESMTP id h28si1264759qkl.1.2021.03.29.11.27.24
        for <kasan-dev@googlegroups.com>;
        Mon, 29 Mar 2021 11:27:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of jszhang3@mail.ustc.edu.cn designates 202.38.64.46 as permitted sender) client-ip=202.38.64.46;
Received: from xhacker (unknown [101.86.19.180])
	by newmailweb.ustc.edu.cn (Coremail) with SMTP id LkAmygCnr08FHGJgFfNpAA--.35778S2;
	Tue, 30 Mar 2021 02:27:17 +0800 (CST)
Date: Tue, 30 Mar 2021 02:22:21 +0800
From: "'Jisheng Zhang' via kasan-dev" <kasan-dev@googlegroups.com>
To: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt
 <palmer@dabbelt.com>, Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin
 <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey
 Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, "
 =?UTF-8?B?QmrDtnJuIFTDtnBlbA==?=" <bjorn@kernel.org>, Alexei Starovoitov
 <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, Andrii Nakryiko
 <andrii@kernel.org>, Martin KaFai Lau <kafai@fb.com>, Song Liu
 <songliubraving@fb.com>, Yonghong Song <yhs@fb.com>, John Fastabend
 <john.fastabend@gmail.com>, KP Singh <kpsingh@kernel.org>, Luke Nelson
 <luke.r.nels@gmail.com>, Xi Wang <xi.wang@gmail.com>
Cc: linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
 kasan-dev@googlegroups.com, netdev@vger.kernel.org, bpf@vger.kernel.org
Subject: [PATCH 1/9] riscv: add __init section marker to some functions
Message-ID: <20210330022221.174d2721@xhacker>
In-Reply-To: <20210330022144.150edc6e@xhacker>
References: <20210330022144.150edc6e@xhacker>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-CM-TRANSID: LkAmygCnr08FHGJgFfNpAA--.35778S2
X-Coremail-Antispam: 1UD129KBjvJXoWxuryfXrWUJry5ur48ur4xtFb_yoW5KFyUpr
	WkKa1kZFWYkFWvga9rAry8ur1UJ3Zaka43trsFkas8XF17ur45X34kW3yqvr1UJFWkuayr
	A34rAry5Aw4DAa7anT9S1TB71UUUUUUqnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUklb7Iv0xC_tr1lb4IE77IF4wAFF20E14v26ryj6rWUM7CY07I2
	0VC2zVCF04k26cxKx2IYs7xG6rWj6s0DM7CIcVAFz4kK6r1j6r18M28lY4IEw2IIxxk0rw
	A2F7IY1VAKz4vEj48ve4kI8wA2z4x0Y4vE2Ix0cI8IcVAFwI0_Gr0_Xr1l84ACjcxK6xII
	jxv20xvEc7CjxVAFwI0_Cr0_Gr1UM28EF7xvwVC2z280aVAFwI0_Gr1j6F4UJwA2z4x0Y4
	vEx4A2jsIEc7CjxVAFwI0_Cr1j6rxdM2AIxVAIcxkEcVAq07x20xvEncxIr21l5I8CrVAC
	Y4xI64kE6c02F40Ex7xfMcIj6xIIjxv20xvE14v26r126r1DMcIj6I8E87Iv67AKxVWUJV
	W8JwAm72CE4IkC6x0Yz7v_Jr0_Gr1lF7xvr2IY64vIr41lFIxGxcIEc7CjxVA2Y2ka0xkI
	wI1l42xK82IYc2Ij64vIr41l4I8I3I0E4IkC6x0Yz7v_Jr0_Gr1lx2IqxVAqx4xG67AKxV
	WUJVWUGwC20s026x8GjcxK67AKxVWUGVWUWwC2zVAF1VAY17CE14v26r4a6rW5MIIYrxkI
	7VAKI48JMIIF0xvE2Ix0cI8IcVAFwI0_JFI_Gr1lIxAIcVC0I7IYx2IY6xkF7I0E14v26F
	4j6r4UJwCI42IY6xAIw20EY4v20xvaj40_Gr0_Zr1lIxAIcVC2z280aVAFwI0_Jr0_Gr1l
	IxAIcVC2z280aVCY1x0267AKxVW8JVW8JrUvcSsGvfC2KfnxnUUI43ZEXa7IU84KZJUUUU
	U==
X-CM-SenderInfo: xmv2xttqjtqzxdloh3xvwfhvlgxou0/
X-Original-Sender: jszhang3@mail.ustc.edu.cn
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mail.ustc.edu.cn header.s=dkim header.b=JHPuSark;       spf=pass
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210330022221.174d2721%40xhacker.
