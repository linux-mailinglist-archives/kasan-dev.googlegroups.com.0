Return-Path: <kasan-dev+bncBCRKNY4WZECBB6HBUCBAMGQEITJWBTI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3b.google.com (mail-oo1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 551E9333336
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Mar 2021 03:37:46 +0100 (CET)
Received: by mail-oo1-xc3b.google.com with SMTP id k19sf7968907ook.13
        for <lists+kasan-dev@lfdr.de>; Tue, 09 Mar 2021 18:37:46 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615343865; cv=pass;
        d=google.com; s=arc-20160816;
        b=aQnQAbuiXjpjMShB+a/xN4J2dteZZObNZ3DlmQ9ZMpWeGiw0MI/sdIDwovqQdstDKk
         s1form5/bqwcxCaZBup1dzUFDEwRa8Y17+nmrIJ3lBgyES5viWAstQfjILvhrf1uoM8v
         t8rCgzN9NKukJBitkNnxUgzLk8zxsJR8QdfoptCNlcm8CkS7mOynuppCcKoFjExod8rx
         W1b6V+PIQfYyVu4FpcvEXSh2dw6fd7CWnSKyCXgfGRoVME6kzT358PgtNG5t/jITkatL
         toVUrXuAVquIrK1hCFv/2jlYjN1SVlVABZz+PG5mOLwQ+fwf9I4DubF5r1ERIlusypSr
         Ib7w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=9KdKPz0ZhpWgDq7H0fxWK2gJvVXiQrH70ouliGTx0fQ=;
        b=aCSvn88/kFbdocSBpN2sJmpxrnBwpiPbU7HSmVAyqHJApQGM91jGTirekUCYCl6HY3
         nO9weYJ3UZVa1QK+LXDQwz0pKXVjL7kkUvU/SkJbyecryqtqjLzhYV4lptRhlA9KacEM
         xpYXBkZtMkIa1Ewckrv80apjtXIme4Pm3F6Od4L7iF/4+8rhMi7hLkzhUHU+hHZK1bXL
         V+ljIebQUupxB4pYJOWMOeJo/7ocKZ57qg7ZGDeHYcRweqL6KRJnsRhXU1qkpzL4+A6T
         ReP0n0uN30TuxdcE8Cos4o++evfErYrySpsV0/he0bInFf0T+PtnD11oL29MGrmB93up
         6/4Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=S7p9K2Sy;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9KdKPz0ZhpWgDq7H0fxWK2gJvVXiQrH70ouliGTx0fQ=;
        b=ShJKd1D1NH8xR23rBCkX2gBjk1MgrNNWnK62Y7JgUpbMiy4drjJ770kTb/gZ4qRg2k
         C3Yitmjl7D9ZJ8yFEMG9rYV90MIeSS/p7JpN7Ezt8kSCWk/b8/xzPVdfs6C0WoOtJhoL
         VTeg7sT0xT6f027nzH7dPLey2tIli/qlMAgFZ3KtMovPwhqasiQ3d3P0st8DekrgJLrU
         H4dvihvFteqCKU6KL4/77xA26clGjV0vagYNw+srIBNw0Oddls1P6NVQCWGT3T6neR/U
         QEDeViBiqx7LKBx3bxdpKNx84dgYWzStiuvpHVdbJ1cJeaM7KdyLHTNjwULVbgqkATpa
         Ssyg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=9KdKPz0ZhpWgDq7H0fxWK2gJvVXiQrH70ouliGTx0fQ=;
        b=Sth8YSX6cotbcODzoj6XU7iJ3MCIIcedpzMxdVpb4fw0l7QPgSb/10EwNSnmvA8B1x
         gttDoXjmDcVQFpZkNiJhE3zDR6Ny96cbBArfEl/KyDjphnX/3Dd+S43p0blxd+5f07Ik
         Xsd/fPi5T6pNFwAnyBUHUettBpExjuPuM5qcQKOhMRpEkodZy8uaqKLWgezSEhYNAhmf
         3OL0HB4HBRjAqnbVjldsvJizo4ugLkvybDJd2wh+JdX5X2uHNMYoneJ4PQlXXdhAYJ8X
         lbMQ6FLxoAXDBtA+rW9jk+YcNI4hLY+CRnquHP5AsofQHDGEi7JU4wkyJt+6k24BAumH
         7Rpg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532dkbOQ7yeBURFUk7Ob1O6n7s7vShgB7146Aklc7H+IfQ73hs3A
	lY5bW+Una33AKJRavsA/72E=
X-Google-Smtp-Source: ABdhPJzpv40dUb69+0o2pt8qWxvS2B1pUIRT4Rl0x2sL4NuCKKjAJ2L+v9HhhMu3kLHvMm9/J6VLfw==
X-Received: by 2002:aca:170a:: with SMTP id j10mr925409oii.128.1615343864965;
        Tue, 09 Mar 2021 18:37:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c650:: with SMTP id w77ls118542oif.1.gmail; Tue, 09 Mar
 2021 18:37:44 -0800 (PST)
X-Received: by 2002:a54:4e84:: with SMTP id c4mr935931oiy.20.1615343864588;
        Tue, 09 Mar 2021 18:37:44 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615343864; cv=none;
        d=google.com; s=arc-20160816;
        b=rAZYXlOKBgVJtXKg0SBSWluGCmoe1z/GwI22CwftCbYwGiyyNFZYVkzmUTGZ/CPoAJ
         IrbLP1P2Q8LjLYm9v1vXbpEq9bFAMv2dpj4qhqE9h2Phm4zEJkDqCNR6wMlGbgma6BST
         HdBNvYTCtfPurcbM/exq4wqNtEiaEimrJKomyj+vQBliR8qTPqkKidham2q0mGv7I5gc
         F8kVw/yy2Fg8zUWZGgUqbgfYUGMGtkqMlTIHlUHzAKa9kIiEIxDTTpEGA9bmfsRVXLmt
         DNGxnf3Cgok5tLAsXcUkOzYI6oSnWQKxI9KAXwxrwX+BtVscvIAxTUryKCFXIKITXJl/
         Mm0A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=UzABH8OfIDY+zUaaqIGMBSk5x3QjktoUn2udOPEAyJA=;
        b=UDJeA8Eb44uYUZXDE9IpexlNiyk5ngGv37sQ0XKh0lgUzbyZgveOGZwr6yKmbQjJ94
         rpAHDVrKEXlCTSmdX9Hrk6HxL/LA1T5XopODxsX3tGPIcpVhtYNR5TEZbbJYP1LNeP8V
         H9Xz8yby5pJyhrypNdK45jYnKlRURdB6Vvpa0GTeHYTwS/rE40jzmMwfujxJ0KXZ/MzQ
         pJ7i05yg4Ke3WO+e/35kGlc2e6/9OdlroI0ITOYoNZ6+a89KNQoustmLG3Oax5FoOwdx
         PnqCO1tBHmcfhz22dsRnkz2aJDDTB6/63qn/MDiJ/HQSuWoke+QVK8YN0WIgrYCytQMV
         zhZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=S7p9K2Sy;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pj1-x102a.google.com (mail-pj1-x102a.google.com. [2607:f8b0:4864:20::102a])
        by gmr-mx.google.com with ESMTPS id x38si470813otr.3.2021.03.09.18.37.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 09 Mar 2021 18:37:44 -0800 (PST)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::102a as permitted sender) client-ip=2607:f8b0:4864:20::102a;
Received: by mail-pj1-x102a.google.com with SMTP id gb6so723018pjb.0
        for <kasan-dev@googlegroups.com>; Tue, 09 Mar 2021 18:37:44 -0800 (PST)
X-Received: by 2002:a17:902:9001:b029:e6:2e56:8b0d with SMTP id a1-20020a1709029001b02900e62e568b0dmr1038347plp.31.1615343863808;
        Tue, 09 Mar 2021 18:37:43 -0800 (PST)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id s194sm14383714pfs.57.2021.03.09.18.37.42
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 09 Mar 2021 18:37:43 -0800 (PST)
Date: Tue, 09 Mar 2021 18:37:43 -0800 (PST)
Subject: Re: [PATCH v2] riscv: Improve KASAN_VMALLOC support
In-Reply-To: <20210226180154.31533-1-alex@ghiti.fr>
CC: Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  nylon7@andestech.com, nickhu@andestech.com, aryabinin@virtuozzo.com, glider@google.com,
  dvyukov@google.com, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
  kasan-dev@googlegroups.com, alex@ghiti.fr
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alex@ghiti.fr
Message-ID: <mhng-a1ab9e7a-d992-4432-badc-02cc788b1ace@penguin>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=S7p9K2Sy;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::102a as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Fri, 26 Feb 2021 10:01:54 PST (-0800), alex@ghiti.fr wrote:
> When KASAN vmalloc region is populated, there is no userspace process and
> the page table in use is swapper_pg_dir, so there is no need to read
> SATP. Then we can use the same scheme used by kasan_populate_p*d
> functions to go through the page table, which harmonizes the code.
>
> In addition, make use of set_pgd that goes through all unused page table
> levels, contrary to p*d_populate functions, which makes this function work
> whatever the number of page table levels.
>
> And finally, make sure the writes to swapper_pg_dir are visible using
> an sfence.vma.

So I think this is actually a bug: without the fence we could get a 
kasan-related fault at any point (as the mappings might not be visible yet), 
and if we get one when inside do_page_fault() (or while holding a lock it 
wants) we'll end up deadlocking against ourselves.  That'll probably never 
happen in practice, but it'd still be good to get the fence onto fixes.  The 
rest are cleanups, they're for for-next (and should probably be part of your 
sv48 series, if you need to re-spin it -- I'll look at that next).

LMK if you want to split this up, or if you want me to do it.  Either way,

Reviewed-by: Palmer Dabbelt <palmerdabbelt@google.com>

Thanks!

> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
> ---
>
> Changes in v2:
> - Quiet kernel test robot warnings about missing prototypes by declaring
>   the introduced functions as static.
>
>  arch/riscv/mm/kasan_init.c | 61 +++++++++++++-------------------------
>  1 file changed, 20 insertions(+), 41 deletions(-)
>
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> index e3d91f334b57..aaa3bdc0ffc0 100644
> --- a/arch/riscv/mm/kasan_init.c
> +++ b/arch/riscv/mm/kasan_init.c
> @@ -11,18 +11,6 @@
>  #include <asm/fixmap.h>
>  #include <asm/pgalloc.h>
>
> -static __init void *early_alloc(size_t size, int node)
> -{
> -	void *ptr = memblock_alloc_try_nid(size, size,
> -		__pa(MAX_DMA_ADDRESS), MEMBLOCK_ALLOC_ACCESSIBLE, node);
> -
> -	if (!ptr)
> -		panic("%pS: Failed to allocate %zu bytes align=%zx nid=%d from=%llx\n",
> -			__func__, size, size, node, (u64)__pa(MAX_DMA_ADDRESS));
> -
> -	return ptr;
> -}
> -
>  extern pgd_t early_pg_dir[PTRS_PER_PGD];
>  asmlinkage void __init kasan_early_init(void)
>  {
> @@ -155,38 +143,29 @@ static void __init kasan_populate(void *start, void *end)
>  	memset(start, KASAN_SHADOW_INIT, end - start);
>  }
>
> -void __init kasan_shallow_populate(void *start, void *end)
> +static void __init kasan_shallow_populate_pgd(unsigned long vaddr, unsigned long end)
>  {
> -	unsigned long vaddr = (unsigned long)start & PAGE_MASK;
> -	unsigned long vend = PAGE_ALIGN((unsigned long)end);
> -	unsigned long pfn;
> -	int index;
> +	unsigned long next;
>  	void *p;
> -	pud_t *pud_dir, *pud_k;
> -	pgd_t *pgd_dir, *pgd_k;
> -	p4d_t *p4d_dir, *p4d_k;
> -
> -	while (vaddr < vend) {
> -		index = pgd_index(vaddr);
> -		pfn = csr_read(CSR_SATP) & SATP_PPN;
> -		pgd_dir = (pgd_t *)pfn_to_virt(pfn) + index;
> -		pgd_k = init_mm.pgd + index;
> -		pgd_dir = pgd_offset_k(vaddr);
> -		set_pgd(pgd_dir, *pgd_k);
> -
> -		p4d_dir = p4d_offset(pgd_dir, vaddr);
> -		p4d_k  = p4d_offset(pgd_k, vaddr);
> -
> -		vaddr = (vaddr + PUD_SIZE) & PUD_MASK;
> -		pud_dir = pud_offset(p4d_dir, vaddr);
> -		pud_k = pud_offset(p4d_k, vaddr);
> -
> -		if (pud_present(*pud_dir)) {
> -			p = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
> -			pud_populate(&init_mm, pud_dir, p);
> +	pgd_t *pgd_k = pgd_offset_k(vaddr);
> +
> +	do {
> +		next = pgd_addr_end(vaddr, end);
> +		if (pgd_page_vaddr(*pgd_k) == (unsigned long)lm_alias(kasan_early_shadow_pmd)) {
> +			p = memblock_alloc(PAGE_SIZE, PAGE_SIZE);
> +			set_pgd(pgd_k, pfn_pgd(PFN_DOWN(__pa(p)), PAGE_TABLE));
>  		}
> -		vaddr += PAGE_SIZE;
> -	}
> +	} while (pgd_k++, vaddr = next, vaddr != end);
> +}
> +
> +static void __init kasan_shallow_populate(void *start, void *end)
> +{
> +	unsigned long vaddr = (unsigned long)start & PAGE_MASK;
> +	unsigned long vend = PAGE_ALIGN((unsigned long)end);
> +
> +	kasan_shallow_populate_pgd(vaddr, vend);
> +
> +	local_flush_tlb_all();
>  }
>
>  void __init kasan_init(void)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-a1ab9e7a-d992-4432-badc-02cc788b1ace%40penguin.
