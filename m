Return-Path: <kasan-dev+bncBDFJHU6GRMBBBLVRTKBQMGQE3STL2AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id A0B6E3525F0
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Apr 2021 06:08:15 +0200 (CEST)
Received: by mail-lj1-x23e.google.com with SMTP id i26sf2657705ljn.13
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Apr 2021 21:08:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617336495; cv=pass;
        d=google.com; s=arc-20160816;
        b=cTWHkPzEEUPT0VoXsYIxBJkudYpvjYPNmIeTy/FkST2taGXvjnL/9VeJDVavuy3A5+
         RMw9FtI0gVoOZtPv4tN9oPdPSXqIbG3OxgMLd3P53q0YIKxtLHFMQ0Szy1g3aq+UpP3a
         btcXI+wdbV0+Tp1n8rNS8Y/ieQSs4g8AuhgwV09lgq1Kgs7bI5Hg+A6/xbIbQk4Syjzg
         GCmXPMgt6TzEiuKsThgf/BnnocnLlGTAAxBvufC8KAiTprR/sNGRG8T8Bys8egrIKcJh
         +VcWaKQrpAgE3WD2/ro6jbRgHjbDn5GvaFw27crpvCXh6VXlXl2OSiEAJVFYMJKfJ3lU
         k13Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=HJ1bBNcJ8fE4RQNk5auC+nn670mHxx4WcDic7+cNdpg=;
        b=QwDBaHWHHtlE66I8qXuXGYxA78JDEfHrBpxH/tuorWkD1BFr0s4GA+JQi3FqPG3oJn
         yei1NXpeKJV8NgO6TFF58yFvHnkUltFRmd8P8oPUTbnTIO2gqhPSw9iOKzHBAiHoRlub
         l5upwbIM1JNXYTg4t60bbMjECUT54uyzgjqDgGBzE63yrzc9Z/NOw/fUnyPGtUvi7uTo
         bfyn7m0bvZOsM4aDQdiiamgtHv++7RLBfpzJJLBI1bq4NpeuRgpjlqybaDg6iGwMbhkx
         b4hFPyzfBSQH5wOShEMiXNxmqVrok9YFUMizs5REaK/hqVpQ/K4tV/v1aCVEWiRvprUC
         wBvA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623 header.b=uO9cVaFb;
       spf=neutral (google.com: 2a00:1450:4864:20::336 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HJ1bBNcJ8fE4RQNk5auC+nn670mHxx4WcDic7+cNdpg=;
        b=jiIJGvJ5/bUVpcp62BNobZjEnkPG8xeHToFCzDB/bQEnqq9nbs4meSn58XSWj31Eda
         qbOvICRHFnEvR9uYpJjjsyHdqrzyyeqThnDR8s+kXJE/yRBq+ZIJBnBxNX7mYdEYdLa0
         VJ+wTmuXjFQ3NZCDmV8Y2hiFelQpRpvKsSxfuvpCxjAkIN5SEm0jsc5qKlEBeRGCqqoF
         q6ZMKzn3jXArETX3/NctJytZG6/POYEvaRue+jMgjBZl712lI2AHmutspioFvVgp47kY
         XdAz/kx20h39BkR428zy2e0BKjmjS6xhYwHVHvFUjonfV88SLarH8D+LgEpfoFm4/DUs
         r+MQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=HJ1bBNcJ8fE4RQNk5auC+nn670mHxx4WcDic7+cNdpg=;
        b=C6z/bxM/u2cmTQp6cxSDoFunnq13o8eHQ7Jo4pcpzU4T60dNZaBNgMQaeca16Kb2w9
         F/c/b6nzv8XG2JZ9brKf8CeaJXqaWhMoV320N9DP8oYFFybpBzmLf9Cyi9dILfQMkwSW
         pDCCr3nNkaW5CKRnQB08xZXAkj27pi/MFC5F7Z6ZBwEY39LrcKK6hKTUnx1mUVOMq7bf
         bRmUHuWeXXGZTXoxWudxaQ39XZxl5yohEZFSPb03SYse+CIZ8JySYp7HLHTWOne/7urn
         phopCXuLh29dJaVS+qxAhYdQS2VLcQkaE2YDmfaQgnMSSnOjJFvC2HyyWBuu/tNMvyj9
         CS/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530CnIw7eK8/QesnXKnxw4Gb2vh5o0kQ+JIOapxCN6RytpXpoLg0
	FayJ6MCGdYYlPevkklYSYxI=
X-Google-Smtp-Source: ABdhPJwZHKU6xESUSXiGI9KvsT812Z09Unf0S+KTk/DsI1Qt2Bp8ph9fUcAsVAzXXGa8dCP82TUf6Q==
X-Received: by 2002:a2e:9151:: with SMTP id q17mr7081933ljg.107.1617336495185;
        Thu, 01 Apr 2021 21:08:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:2050:: with SMTP id t16ls1760366ljo.4.gmail; Thu,
 01 Apr 2021 21:08:14 -0700 (PDT)
X-Received: by 2002:a2e:b817:: with SMTP id u23mr6969300ljo.44.1617336494123;
        Thu, 01 Apr 2021 21:08:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617336494; cv=none;
        d=google.com; s=arc-20160816;
        b=HL4P3ldOHZWT3pm6jQwHj0nEAukxUdouOWs/mSv52jRvvpjdBkB0iPOQZZjU0hgtwI
         FR2iFdrVlYfZ4da1x/lSwISJAphKj9VAnwHySfKptGJ+U++PB4L+iX0PFxoYU06L55aO
         5+Ny7ytnwB3fTe8X7/O1YQQ3DcFWtHiu2OD9mYgLjoQmndB2VHkigN0tIaTk9MUkXNtP
         yAXmZorQLT1g8/SkrcYocXSWS54IPUQx3eZMn7yDBh7T0ll1U1P+vRNvINlW7LlyGt9A
         OO5pnRRtAvzZxgrsKmBxpaLWfG3K6fJI9UWXfh9soWjkJqjqFnYA2uRnD/dwsuqmoibM
         XtaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=r29s2NuB4h8xDuoc4V2TUkw3k2SQOmwLpoFzxMpsSfU=;
        b=KiTjO7tHfY/k0av/dJij3P+yyVWRHVaUe2EZC0gI6qocEab4ol56qit/oDt1GeF8BY
         q/eMpUSILhxTbh5BspIxV5DPkaBd72qM0m1tC5KKkUnmFxHVpPgiWvJef4UW5lkiIlzz
         DihHAQn0y/kjpQ0WvX60sDmlN9OPeUIZ1/I3yYYruHlb5D9/ysdIqZ0PWidtQWl8O6F3
         qKImjExu3vYELZPrNQCYbgnGNK5W+F1uNwhXFumaKZ0dsfIz5afosyHgG5lMJvtENc5J
         cNiy7QABKIK1/DINAMRNQx6L4nVtppfT888oolmtv//jFmaJsAIthaDgbCyb9tOZ2wEm
         fWdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623 header.b=uO9cVaFb;
       spf=neutral (google.com: 2a00:1450:4864:20::336 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
Received: from mail-wm1-x336.google.com (mail-wm1-x336.google.com. [2a00:1450:4864:20::336])
        by gmr-mx.google.com with ESMTPS id v203si567123lfa.10.2021.04.01.21.08.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Apr 2021 21:08:14 -0700 (PDT)
Received-SPF: neutral (google.com: 2a00:1450:4864:20::336 is neither permitted nor denied by best guess record for domain of anup@brainfault.org) client-ip=2a00:1450:4864:20::336;
Received: by mail-wm1-x336.google.com with SMTP id y124-20020a1c32820000b029010c93864955so3748723wmy.5
        for <kasan-dev@googlegroups.com>; Thu, 01 Apr 2021 21:08:13 -0700 (PDT)
X-Received: by 2002:a05:600c:9:: with SMTP id g9mr11022806wmc.134.1617336493632;
 Thu, 01 Apr 2021 21:08:13 -0700 (PDT)
MIME-Version: 1.0
References: <20210401002442.2fe56b88@xhacker> <20210401002518.5cf48e91@xhacker>
In-Reply-To: <20210401002518.5cf48e91@xhacker>
From: Anup Patel <anup@brainfault.org>
Date: Fri, 2 Apr 2021 09:38:02 +0530
Message-ID: <CAAhSdy0CgxZj14Jx62CS=gRVzZs9c9NUysWi1iTTZ3BJvAOjPQ@mail.gmail.com>
Subject: Re: [PATCH v2 1/9] riscv: add __init section marker to some functions
To: Jisheng Zhang <jszhang3@mail.ustc.edu.cn>
Cc: Paul Walmsley <paul.walmsley@sifive.com>, Palmer Dabbelt <palmer@dabbelt.com>, 
	Albert Ou <aou@eecs.berkeley.edu>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, =?UTF-8?B?QmrDtnJuIFTDtnBlbA==?= <bjorn@kernel.org>, 
	Alexei Starovoitov <ast@kernel.org>, Daniel Borkmann <daniel@iogearbox.net>, 
	Andrii Nakryiko <andrii@kernel.org>, Song Liu <songliubraving@fb.com>, Yonghong Song <yhs@fb.com>, 
	John Fastabend <john.fastabend@gmail.com>, KP Singh <kpsingh@kernel.org>, 
	Luke Nelson <luke.r.nels@gmail.com>, Xi Wang <xi.wang@gmail.com>, 
	linux-riscv <linux-riscv@lists.infradead.org>, 
	"linux-kernel@vger.kernel.org List" <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com, 
	netdev@vger.kernel.org, bpf@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: anup@brainfault.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@brainfault-org.20150623.gappssmtp.com header.s=20150623
 header.b=uO9cVaFb;       spf=neutral (google.com: 2a00:1450:4864:20::336 is
 neither permitted nor denied by best guess record for domain of
 anup@brainfault.org) smtp.mailfrom=anup@brainfault.org
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

On Wed, Mar 31, 2021 at 10:00 PM Jisheng Zhang
<jszhang3@mail.ustc.edu.cn> wrote:
>
> From: Jisheng Zhang <jszhang@kernel.org>
>
> They are not needed after booting, so mark them as __init to move them
> to the __init section.
>
> Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
> ---
>  arch/riscv/kernel/traps.c  | 2 +-
>  arch/riscv/mm/init.c       | 6 +++---
>  arch/riscv/mm/kasan_init.c | 6 +++---
>  arch/riscv/mm/ptdump.c     | 2 +-
>  4 files changed, 8 insertions(+), 8 deletions(-)
>
> diff --git a/arch/riscv/kernel/traps.c b/arch/riscv/kernel/traps.c
> index 1357abf79570..07fdded10c21 100644
> --- a/arch/riscv/kernel/traps.c
> +++ b/arch/riscv/kernel/traps.c
> @@ -197,6 +197,6 @@ int is_valid_bugaddr(unsigned long pc)
>  #endif /* CONFIG_GENERIC_BUG */
>
>  /* stvec & scratch is already set from head.S */
> -void trap_init(void)
> +void __init trap_init(void)
>  {
>  }

The trap_init() is unused currently so you can drop this change
and remove trap_init() as a separate patch.

> diff --git a/arch/riscv/mm/init.c b/arch/riscv/mm/init.c
> index 067583ab1bd7..76bf2de8aa59 100644
> --- a/arch/riscv/mm/init.c
> +++ b/arch/riscv/mm/init.c
> @@ -57,7 +57,7 @@ static void __init zone_sizes_init(void)
>         free_area_init(max_zone_pfns);
>  }
>
> -static void setup_zero_page(void)
> +static void __init setup_zero_page(void)
>  {
>         memset((void *)empty_zero_page, 0, PAGE_SIZE);
>  }
> @@ -75,7 +75,7 @@ static inline void print_mlm(char *name, unsigned long b, unsigned long t)
>                   (((t) - (b)) >> 20));
>  }
>
> -static void print_vm_layout(void)
> +static void __init print_vm_layout(void)
>  {
>         pr_notice("Virtual kernel memory layout:\n");
>         print_mlk("fixmap", (unsigned long)FIXADDR_START,
> @@ -557,7 +557,7 @@ static inline void setup_vm_final(void)
>  #endif /* CONFIG_MMU */
>
>  #ifdef CONFIG_STRICT_KERNEL_RWX
> -void protect_kernel_text_data(void)
> +void __init protect_kernel_text_data(void)
>  {
>         unsigned long text_start = (unsigned long)_start;
>         unsigned long init_text_start = (unsigned long)__init_text_begin;
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> index 4f85c6d0ddf8..e1d041ac1534 100644
> --- a/arch/riscv/mm/kasan_init.c
> +++ b/arch/riscv/mm/kasan_init.c
> @@ -60,7 +60,7 @@ asmlinkage void __init kasan_early_init(void)
>         local_flush_tlb_all();
>  }
>
> -static void kasan_populate_pte(pmd_t *pmd, unsigned long vaddr, unsigned long end)
> +static void __init kasan_populate_pte(pmd_t *pmd, unsigned long vaddr, unsigned long end)
>  {
>         phys_addr_t phys_addr;
>         pte_t *ptep, *base_pte;
> @@ -82,7 +82,7 @@ static void kasan_populate_pte(pmd_t *pmd, unsigned long vaddr, unsigned long en
>         set_pmd(pmd, pfn_pmd(PFN_DOWN(__pa(base_pte)), PAGE_TABLE));
>  }
>
> -static void kasan_populate_pmd(pgd_t *pgd, unsigned long vaddr, unsigned long end)
> +static void __init kasan_populate_pmd(pgd_t *pgd, unsigned long vaddr, unsigned long end)
>  {
>         phys_addr_t phys_addr;
>         pmd_t *pmdp, *base_pmd;
> @@ -117,7 +117,7 @@ static void kasan_populate_pmd(pgd_t *pgd, unsigned long vaddr, unsigned long en
>         set_pgd(pgd, pfn_pgd(PFN_DOWN(__pa(base_pmd)), PAGE_TABLE));
>  }
>
> -static void kasan_populate_pgd(unsigned long vaddr, unsigned long end)
> +static void __init kasan_populate_pgd(unsigned long vaddr, unsigned long end)
>  {
>         phys_addr_t phys_addr;
>         pgd_t *pgdp = pgd_offset_k(vaddr);
> diff --git a/arch/riscv/mm/ptdump.c b/arch/riscv/mm/ptdump.c
> index ace74dec7492..3b7b6e4d025e 100644
> --- a/arch/riscv/mm/ptdump.c
> +++ b/arch/riscv/mm/ptdump.c
> @@ -331,7 +331,7 @@ static int ptdump_show(struct seq_file *m, void *v)
>
>  DEFINE_SHOW_ATTRIBUTE(ptdump);
>
> -static int ptdump_init(void)
> +static int __init ptdump_init(void)
>  {
>         unsigned int i, j;
>
> --
> 2.31.0
>
>
>
> _______________________________________________
> linux-riscv mailing list
> linux-riscv@lists.infradead.org
> http://lists.infradead.org/mailman/listinfo/linux-riscv

Apart from above, looks good to me.

Reviewed-by: Anup Patel <anup@brainfault.org>

Regards,
Anup

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAhSdy0CgxZj14Jx62CS%3DgRVzZs9c9NUysWi1iTTZ3BJvAOjPQ%40mail.gmail.com.
