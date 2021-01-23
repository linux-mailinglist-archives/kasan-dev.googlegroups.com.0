Return-Path: <kasan-dev+bncBCRKNY4WZECBB654V2AAMGQEVRBKWHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33b.google.com (mail-ot1-x33b.google.com [IPv6:2607:f8b0:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id B86C83012E4
	for <lists+kasan-dev@lfdr.de>; Sat, 23 Jan 2021 04:56:44 +0100 (CET)
Received: by mail-ot1-x33b.google.com with SMTP id q8sf3262865otk.6
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Jan 2021 19:56:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1611374203; cv=pass;
        d=google.com; s=arc-20160816;
        b=jfh+a0HSyhUc+hgXBE33OH8Z1ygk16lrbQg+LkdVKAQkW/XFBq0mjne1pBtUD6B0O+
         PLzs8sMSGry+bjEnyhG9nqlkxA6ndqDPgQOCgJGvWfROukAfmDGYx3W4iwIoDjoQU2WI
         DCUXny85fZ11SLbPaQqzSyRT/tM6E4EBMfrsNCUAV7amgHP6PCG+SB7khJgKVD3U3WPE
         zX1LZRp24s0RhqO66Q5YKLfVwT6XCPl4/cTePa4MXog3YEdYdFebJRdf2PKbllKP77tE
         PvxVnVjDd82w7szxEPvkU8cAQsZJGeogRkR4klWxxUbQIlJnW26tzPuIkJPeCwj7mXOP
         mjVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=u6tvjZOPmy96Za7PLMCOSXqUbDyxeXxp+urej421dOc=;
        b=PgCe7dz+7RD/Mgud/oRoWr7KNz8kHNQPFik1F/1p7HorqaYxMt7EyTbj7nQCgubYXa
         kZWOrQPFkPnGNwbxmx9POlG4i6d9tvQ02OMshhRhfdTn4CUR58qR3HXRZ/oE0+9R1vIm
         Q9GMAq3F7Ynhyblc0dehYw/C9QcdCHLkL1k/7xeGGE6KMwls8Za8vmimDcaGFXydPbJo
         VqLlDMYlZvqR0TpWQBqkChlQskCII4trAvnh0x33EA2nFISlGxYfocYXKfLi5je8CliS
         NTVPXP7Q3LXvZ0ulKlCYLyQAG/TNirg9AcJUkTOt8slfqdnNsDmQUaU+rz6GHjdlyj3o
         br/Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=xk8eS4U0;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=u6tvjZOPmy96Za7PLMCOSXqUbDyxeXxp+urej421dOc=;
        b=hfpXLJmwrDf2sefW3j0Utu0Agkm+zSRN1XI8gJCp5IW/Pjp/FFuUO0vhLnAdsL177q
         LRYEnG4PZa7qsSqGwd7wGZf2DaYs7kUf/WVSRRaUMKTB9KKOoM+rYc8zxFiVkCVoDDkU
         4rEmSN0C82uyQtPSRr1vdEyF6930npEDGiG47VcbxkExpP4YdmpL0t1JIkhSsGOocCQb
         BJLPNnvF7w/tEDEtBGmz9V8TpG6MZt0BGRpb9xzEguFuaqGXoDn/W+8sozxTu7Mk7kog
         PPre8jB9/vnvkwwEWOYfUfhbDz5KcpPEayMgKWyo/HOeEkJIZzP/v1c756Q4YxQEzU0q
         HvoQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=u6tvjZOPmy96Za7PLMCOSXqUbDyxeXxp+urej421dOc=;
        b=JIenK1AguI9nhN5fgk9WK4bFv9i1nE7El6xC+bpUOpkZLxcNbjI7GP/tlcWZLLYark
         LRcKcv9Jev0dcDAtaYbM/slhxJ3GFhXFzzmPmj/x5UNQyIybWudJ7+HjDzvS8PJv8Btw
         KsemC/4VksRRxqzZFCcSKbutuSweQUPDsgr0Rj6CqaYAw2Jrgon/RPW5oJwWJpHv1DHa
         CKwoZ7AFXrBX7fBtya7YAFZoHlc5mrG4W9X1UG0dISq/Dr2HPO5pBhD7k0/HdSPB7wXM
         PhBUfwNNOcVwYu4c9PKEPfHuE9d0J30Ki8z6wfJWN+ud1BXCv5TEg7+3eYP1r8bVR4EW
         xnjg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532Q1HbkJ01EOKiLzw5Aixpm/MMU8H0UgnwEGkVtUt5flXkWoUfU
	twHkQaaTFqzmHuy7q97i8BE=
X-Google-Smtp-Source: ABdhPJwAdGL11/as4XBOE8wgw5oo3ULSYMbVHaYV4JY6eb7AfKDG2tDQm3hXGi2mpkq/QWRVj9IMMg==
X-Received: by 2002:a9d:222d:: with SMTP id o42mr5708494ota.102.1611374203745;
        Fri, 22 Jan 2021 19:56:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:9b8e:: with SMTP id x14ls38251ooj.1.gmail; Fri, 22 Jan
 2021 19:56:43 -0800 (PST)
X-Received: by 2002:a4a:3150:: with SMTP id v16mr4441236oog.71.1611374203395;
        Fri, 22 Jan 2021 19:56:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1611374203; cv=none;
        d=google.com; s=arc-20160816;
        b=QAznQpoHfI4kYeqtUXbVWAVd9sgyWEZn/79euLUVIMkid0XstwRW8wX4/l2ZEE0nzT
         bnkYykr7AFoyZvURpM+r4hCRWwN40OWFssHVRmokjk49TkeQZHbNEGsC9dBsHlalSgiP
         UiEUtz4pBuz1xdhP1g29vEafbGfmVvHEnc3IVa3Gn7ntlzU8lyqqiemO6UtchfTTrlHn
         gkJ0uk0fXUEu+PTcvQB4++s6iFmds2Ao5BALBnEXqx9Ljr01725Ayfp9xTvDcGpq/RL/
         JgHpYhWttN2bqXfA4uuIZc0e2sclYW+J7ofmfF6jW3ZPAz2Xw2AkILEx74AaMJUfOxWB
         Kqpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=ZFKvUjQEqDP7dqlPLI+l3jxa5NuIGx5+bmxfTHNs2ZM=;
        b=HH84j77C5rkTmvoHSCPtq69ggoZwEJKDIxlWWxzBDEyL+GogNElSGyCtys3gwOq3j4
         cuqtTGOZSosfKOJjCvYOXsGq9WoyjrV64/rAsmSxjKda0ChZsmgW92DPyO2XXf2SFv3A
         0AjSrx2ThirkoKYPIHdCG8RZp2I3DWuctWZlwKvMnxV19pYrA++7mpF+CbQyMteP+Wsv
         WveidulmKz3AcDtDK3hNyEATPNGCSi++F1cM2qJLRNVOYJ9Whh7nBllkUOMJs4xCSwyY
         5dOCX+macx3ugRCN5R7w6wgsOYFnCupJqULu9z03WFrcCYLcmBywDIr2EnAJCTTOUGT1
         cdbg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=xk8eS4U0;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pj1-x1032.google.com (mail-pj1-x1032.google.com. [2607:f8b0:4864:20::1032])
        by gmr-mx.google.com with ESMTPS id i2si1029047otk.1.2021.01.22.19.56.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 22 Jan 2021 19:56:43 -0800 (PST)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1032 as permitted sender) client-ip=2607:f8b0:4864:20::1032;
Received: by mail-pj1-x1032.google.com with SMTP id g15so5110969pjd.2
        for <kasan-dev@googlegroups.com>; Fri, 22 Jan 2021 19:56:43 -0800 (PST)
X-Received: by 2002:a17:902:7596:b029:da:b7a3:cdd0 with SMTP id j22-20020a1709027596b02900dab7a3cdd0mr7837480pll.14.1611374202834;
        Fri, 22 Jan 2021 19:56:42 -0800 (PST)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id c5sm10690982pjo.4.2021.01.22.19.56.41
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Jan 2021 19:56:41 -0800 (PST)
Date: Fri, 22 Jan 2021 19:56:41 -0800 (PST)
Subject: Re: [PATCH v2 1/1] riscv/kasan: add KASAN_VMALLOC support
In-Reply-To: <20210116055836.22366-2-nylon7@andestech.com>
CC: linux-kernel@vger.kernel.org, linux-riscv@lists.infradead.org,
  kasan-dev@googlegroups.com, Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  aryabinin@virtuozzo.com, glider@google.com, dvyukov@google.com, nylon7717@gmail.com,
  alankao@andestech.com, nickhu@andestech.com, nylon7@andestech.com
From: Palmer Dabbelt <palmer@dabbelt.com>
To: nylon7@andestech.com
Message-ID: <mhng-443fd141-b9a3-4be6-a056-416877f99ea4@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=xk8eS4U0;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::1032 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Fri, 15 Jan 2021 21:58:35 PST (-0800), nylon7@andestech.com wrote:
> It references to x86/s390 architecture.
>
> So, it doesn't map the early shadow page to cover VMALLOC space.
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
>  arch/riscv/mm/kasan_init.c | 57 +++++++++++++++++++++++++++++++++++++-
>  2 files changed, 57 insertions(+), 1 deletion(-)
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
> index 12ddd1f6bf70..4b9149f963d3 100644
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
> +	void *ptr = memblock_alloc_try_nid(size, size,
> +		__pa(MAX_DMA_ADDRESS), MEMBLOCK_ALLOC_ACCESSIBLE, node);
> +
> +	if (!ptr)
> +		panic("%pS: Failed to allocate %zu bytes align=%zx nid=%d from=%llx\n",
> +			__func__, size, size, node, (u64)__pa(MAX_DMA_ADDRESS));
> +
> +	return ptr;
> +}
>
>  extern pgd_t early_pg_dir[PTRS_PER_PGD];
>  asmlinkage void __init kasan_early_init(void)
> @@ -83,6 +96,40 @@ static void __init populate(void *start, void *end)
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
> +		p4d_k  = p4d_offset(pgd_k, vaddr);
> +
> +		vaddr = (vaddr + PUD_SIZE) & PUD_MASK;
> +		pud_dir = pud_offset(p4d_dir, vaddr);
> +		pud_k = pud_offset(p4d_k, vaddr);
> +
> +		if (pud_present(*pud_dir)) {
> +			p = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
> +			pud_populate(&init_mm, pud_dir, p);
> +		}
> +		vaddr += PAGE_SIZE;
> +	}
> +}
> +
>  void __init kasan_init(void)
>  {
>  	phys_addr_t _start, _end;
> @@ -90,7 +137,15 @@ void __init kasan_init(void)
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

Thanks, this is on for-next.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-443fd141-b9a3-4be6-a056-416877f99ea4%40palmerdabbelt-glaptop.
