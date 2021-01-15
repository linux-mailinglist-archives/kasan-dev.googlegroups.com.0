Return-Path: <kasan-dev+bncBCRKNY4WZECBBV7ZQOAAMGQECICHFLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vs1-xe3c.google.com (mail-vs1-xe3c.google.com [IPv6:2607:f8b0:4864:20::e3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 4ED382F708B
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 03:24:25 +0100 (CET)
Received: by mail-vs1-xe3c.google.com with SMTP id g3sf1237715vso.1
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 18:24:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610677464; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZdM7Jd9GYQEBgjMO9nCUir4mPoZz9Cdfm16yNdqiAvCjitXpty4rF3i1nRp6tVdf7G
         9+BT39NefjNhhJckskiDvXM0aNHUGpBlZOFy/ROOaWOMTuLzLM6FDNwv4WmFvtZDlUU6
         NirnjI/yqaOTGM4NXyQvPH4w/GTI2GMH4qScrwRG30SyZUUZ3gkM9ElINxD9lepN3PZk
         4NegdbWm7faggR1ntuRtL6tMiVabRro09nD/fTvC9Lx2vuNQNMghA6t85jJRixKNTv6b
         flBIR12Edqn2ZCCf079hgEEzUZkuWbN3HTbBByPwmyGLDPprHNHx1Tw3WWgLMdAU1uGS
         O3TA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=S6zAlfc0wpCAeIvPjjpuG36ige3XV8tPw1FK4dwV1fg=;
        b=Pd6ylbhFeHamDfbvO8vTd8Ft/tuQGlOI5+mPZCQu//lWSg5/YZTQDrcZJ4493yLMT1
         U71jnDSn7I+JcRAm5twXjNIYQwm6emV81ZdI/jWNJinoxYq3ae87JEEkFzwueQkyhblR
         g+mxTbpVDs/2Opi8qZWzhfITy7bCRcywVubExOLKZialUB4vIjQM1AfUHhOkQSob2FA7
         DB1QpG4n0RrRktNbQQO8fJd8r+AQNi1BD3v4hxh0seHhvjGkeaMeFsCUMHgm+k4UxYPQ
         u6leropKH6OPTtzZJDN36lBbxuZoQ8ad/NvhHulDN6UNxOVyQNaCGQ1x54bXmQPDZmPQ
         M/PQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=Zud2h77Q;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S6zAlfc0wpCAeIvPjjpuG36ige3XV8tPw1FK4dwV1fg=;
        b=dDBy+86/jIfQy1iVUhgJR8aPkJXdEma67O0LZ8qGCDh4lZscMr0Nffi3KJ3VwAPx2Y
         /NKSZrQvbMn3Pu8MnAJL9fQ8I0l8J3BsM4pEmpf2YYDhOWegUMqB5dgk8TRrgOYrTPtr
         ZL007MasL6ob6+JHCE01wNiyTNPkzXnxlpP5ymS8xZRIpVYX6UJjXDhirj5vLV8nIAJd
         4bceopzIiyUYVdzrwfMm1oxIBG37pKFJWMYLVihef9rnZQNopE3L3pR1z611iQOIIyM7
         yEMSf7coP0Rak4H6b0Q1qX9uRvorycGvEs/A/lCVY/vgvXzRr9oqV9CNdNRdzAMijY0K
         L87Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=S6zAlfc0wpCAeIvPjjpuG36ige3XV8tPw1FK4dwV1fg=;
        b=N5dky+FKS6HRl7zeLS7ftSeIUliDyCzZEgrivfNcrhdyPkI2I2Dpz7DmHFLN+EYlkU
         F1ZQbqskhNm3CWsRGUblUpoiYxQXWQ/P4zo9gwX5q5bnPqF4r3tJ8EXIw3yjHw8Ymaqo
         CWDX3JkDjgygiEEgayQaTbZJ16aMzPvMsebZxhn0j1+kCwJuBq+DhYEzFUo5+jddrkWv
         TgGw/DkPT9EUXxFm+0MXzZrbhaRqM//NWdzeHeEY2alw6Ru6rSHiWsWpfor7GMCfEOTR
         Pzt4/bjIbHR2ydq0q3EzbVR3EVe34A7k183D12zqhpxdcHrSNwg5EcZpTqz3LOF2/Heb
         +RuQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532/2G/0Mg1uVe1y73k1A8aot5cfm40teCsCI4aDUsbal9WBJ0FV
	CKsZxMKmYMi9J+QUgZuoZxc=
X-Google-Smtp-Source: ABdhPJyFGjga44JV44W3GEPT+6u+MVp4mMJ1kU6nK1ytMoVeOCaDXu+0VoQaLZhBokhgalYDdoe7EQ==
X-Received: by 2002:a1f:22d7:: with SMTP id i206mr8900085vki.4.1610677463996;
        Thu, 14 Jan 2021 18:24:23 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a67:e287:: with SMTP id g7ls995769vsf.5.gmail; Thu, 14 Jan
 2021 18:24:23 -0800 (PST)
X-Received: by 2002:a67:5c03:: with SMTP id q3mr9008980vsb.47.1610677463455;
        Thu, 14 Jan 2021 18:24:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610677463; cv=none;
        d=google.com; s=arc-20160816;
        b=F++C5Dok8VobA5nLsqnB9Yrv8YxtOM1ZZi7ZzrLck98vdJIGrdrw3zpbXNxjQLbfEl
         WEvaHk740wQlnX8UVsOgWbJAh1sNS8NKUfPO7eVjZ4I4dhvTJPBjwZj2uqoJf6/Cbxvk
         uno3yjeTNrV7IDV0HOCXeXp6uOk+hwL+FmbWBU7nnXpD+7t7yqC8hKAwh8t7eYKOd4nU
         4vaC0O3il/XHcP4oEJSyUzgFQjdwpvZqFrUf3mMyQE8HqQA6VDGRePWz18/z0F4QXQqT
         x3jKUtTJedbgrlo8a29U8Y0c4dX8l0rRRjHA9SJQ2ieyIUnaEsEXg2r38pqnduK/BJHd
         urTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=Cu1r4kHEpk1ipx1WHIOmDfUVLP4Os78haqvXs5XVFiU=;
        b=n1qSRb1Szx5hRTEImqsUeBW8ah5gvngvpTgtzH5qdPDdb0hcSvZVHnSdOMADMW1FXl
         ya3KqyXvptVJema5adDnoHCOCdle6f/TfWJE1SAxBirGEI4HMTgClZr+FVV8wWCfRQrL
         +/qWIH+KT7O+3///slVnAOFPcTvzK7RTOINAW+XcqDLZsTSBSyvJVexME1bOfHcg5Qa4
         GjQ+g8ZTumG2rTeVR8AL5a+dxtIkiBgKsy/lXY4QQF+13dFweMbrm2sOgVEr1Yv+3xQD
         a0FMya6Q1kirktCUf8P4cYXjISvJ6RoRPWP12GOQSs/wmmQgDw0ae/FYrPONxlB+dzW3
         XWQQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=Zud2h77Q;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pl1-x62d.google.com (mail-pl1-x62d.google.com. [2607:f8b0:4864:20::62d])
        by gmr-mx.google.com with ESMTPS id y127si424102vsc.0.2021.01.14.18.24.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 18:24:23 -0800 (PST)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::62d as permitted sender) client-ip=2607:f8b0:4864:20::62d;
Received: by mail-pl1-x62d.google.com with SMTP id b8so3937772plx.0
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 18:24:23 -0800 (PST)
X-Received: by 2002:a17:90b:a47:: with SMTP id gw7mr8102445pjb.1.1610677462419;
        Thu, 14 Jan 2021 18:24:22 -0800 (PST)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id x12sm6401588pfj.25.2021.01.14.18.24.21
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 14 Jan 2021 18:24:21 -0800 (PST)
Date: Thu, 14 Jan 2021 18:24:21 -0800 (PST)
Subject: Re: [PATCH 1/1] riscv/kasan: add KASAN_VMALLOC support
In-Reply-To: <20210113022822.9230-2-nylon7@andestech.com>
CC: linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
  kasan-dev@googlegroups.com, aou@eecs.berkeley.edu, Paul Walmsley <paul.walmsley@sifive.com>,
  dvyukov@google.com, glider@google.com, aryabinin@virtuozzo.com, alankao@andestech.com,
  nickhu@andestech.com, nylon7@andestech.com, nylon7717@gmail.com
From: Palmer Dabbelt <palmer@dabbelt.com>
To: nylon7@andestech.com
Message-ID: <mhng-681abd1f-506e-4e1a-88e7-f48af7e6cc0e@penguin>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=Zud2h77Q;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::62d as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Tue, 12 Jan 2021 18:28:22 PST (-0800), nylon7@andestech.com wrote:
> It's reference x86/s390 architecture.
>
> So, it's don't map the early shadow page to cover VMALLOC space.
>
> Prepopulate top level page table for the range that would otherwise be
> empty.
>
> lower levels are filled dynamically upon memory allocation while
> booting.
>
> Signed-off-by: Nylon Chen <nylon7@andestech.com>
> Signed-off-by: Nick Hu <nickhu@andestech.com>
> ---
>  arch/riscv/Kconfig         |  1 +
>  arch/riscv/mm/kasan_init.c | 66 +++++++++++++++++++++++++++++++++++++-
>  2 files changed, 66 insertions(+), 1 deletion(-)
>
> diff --git a/arch/riscv/Kconfig b/arch/riscv/Kconfig
> index 81b76d44725d..15a2c8088bbe 100644
> --- a/arch/riscv/Kconfig
> +++ b/arch/riscv/Kconfig
> @@ -57,6 +57,7 @@ config RISCV
>  	select HAVE_ARCH_JUMP_LABEL
>  	select HAVE_ARCH_JUMP_LABEL_RELATIVE
>  	select HAVE_ARCH_KASAN if MMU && 64BIT
> +	select HAVE_ARCH_KASAN_VMALLOC if MMU && 64BIT
>  	select HAVE_ARCH_KGDB
>  	select HAVE_ARCH_KGDB_QXFER_PKT
>  	select HAVE_ARCH_MMAP_RND_BITS if MMU
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> index 12ddd1f6bf70..ee332513d728 100644
> --- a/arch/riscv/mm/kasan_init.c
> +++ b/arch/riscv/mm/kasan_init.c
> @@ -9,6 +9,19 @@
>  #include <linux/pgtable.h>
>  #include <asm/tlbflush.h>
>  #include <asm/fixmap.h>
> +#include <asm/pgalloc.h>
> +
> +static __init void *early_alloc(size_t size, int node)
> +{
> +        void *ptr = memblock_alloc_try_nid(size, size,
> +                        __pa(MAX_DMA_ADDRESS), MEMBLOCK_ALLOC_ACCESSIBLE, node);
> +
> +        if (!ptr)
> +                panic("%pS: Failed to allocate %zu bytes align=%zx nid=%d from=%llx\n",
> +                      __func__, size, size, node, (u64)__pa(MAX_DMA_ADDRESS));
> +
> +        return ptr;
> +}
>
>  extern pgd_t early_pg_dir[PTRS_PER_PGD];
>  asmlinkage void __init kasan_early_init(void)
> @@ -83,6 +96,49 @@ static void __init populate(void *start, void *end)
>  	memset(start, 0, end - start);
>  }
>
> +void __init kasan_shallow_populate(void *start, void *end)
> +{
> +	unsigned long vaddr = (unsigned long)start & PAGE_MASK;
> +	unsigned long vend = PAGE_ALIGN((unsigned long)end);
> +	unsigned long pfn;
> +	int index;
> +	void *p;
> +	pud_t *pud_dir, *pud_k;
> +	pmd_t *pmd_dir, *pmd_k;
> +	pgd_t *pgd_dir, *pgd_k;
> +	p4d_t *p4d_dir, *p4d_k;
> +
> +	while (vaddr < vend) {
> +		index = pgd_index(vaddr);
> +		pfn = csr_read(CSR_SATP) & SATP_PPN;
> +		pgd_dir = (pgd_t *)pfn_to_virt(pfn) + index;
> +		pgd_k = init_mm.pgd + index;
> +		pgd_dir = pgd_offset_k(vaddr);
> +		set_pgd(pgd_dir, *pgd_k);
> +
> +		p4d_dir = p4d_offset(pgd_dir, vaddr);
> +		p4d_k  = p4d_offset(pgd_k,vaddr);
> +
> +		vaddr = (vaddr + PUD_SIZE) & PUD_MASK;
> +		pud_dir = pud_offset(p4d_dir, vaddr);
> +		pud_k = pud_offset(p4d_k,vaddr);
> +
> +		if (pud_present(*pud_dir)) {
> +			p = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
> +			pud_populate(&init_mm, pud_dir, p);
> +		}
> +
> +		pmd_dir = pmd_offset(pud_dir, vaddr);
> +		pmd_k = pmd_offset(pud_k,vaddr);
> +		set_pmd(pmd_dir, *pmd_k);
> +		if (pmd_present(*pmd_dir)) {
> +			p = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
> +			pmd_populate(&init_mm, pmd_dir, p);
> +		}
> +		vaddr += PAGE_SIZE;
> +	}
> +}
> +
>  void __init kasan_init(void)
>  {
>  	phys_addr_t _start, _end;
> @@ -90,7 +146,15 @@ void __init kasan_init(void)
>
>  	kasan_populate_early_shadow((void *)KASAN_SHADOW_START,
>  				    (void *)kasan_mem_to_shadow((void *)
> -								VMALLOC_END));
> +								VMEMMAP_END));
> +	if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
> +		kasan_shallow_populate(
> +			(void *)kasan_mem_to_shadow((void *)VMALLOC_START),
> +			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
> +	else
> +		kasan_populate_early_shadow(
> +			(void *)kasan_mem_to_shadow((void *)VMALLOC_START),
> +			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
>
>  	for_each_mem_range(i, &_start, &_end) {
>  		void *start = (void *)_start;

There are a bunch of checkpatch issues here.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-681abd1f-506e-4e1a-88e7-f48af7e6cc0e%40penguin.
