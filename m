Return-Path: <kasan-dev+bncBCRKNY4WZECBBV7DRKBQMGQEDTNN42I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id C5B6334E087
	for <lists+kasan-dev@lfdr.de>; Tue, 30 Mar 2021 07:06:32 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id h4sf6666289plf.3
        for <lists+kasan-dev@lfdr.de>; Mon, 29 Mar 2021 22:06:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617080791; cv=pass;
        d=google.com; s=arc-20160816;
        b=TVgOWwnyg4tmaiYFDhpcctitC9YUAn72crsZGfTZFxNn/LUy93j4jho+jhKeg0v+KE
         C06EVswShDImVgRWtFOA3c36+NfA7tjr80zq/ibLErvCj3DatRnCgWpFomw2ycviMX7o
         s/yCFgs0coaVWZyk0YLFP14RubAFCwf8SkQ4xFi59wC91MsfVU0oiBXMGG77t5kYPORI
         WRoZTlhG1UgJmtX5ZTp0LMrK0iKT4R6ELRW4amkfeiYkugR3AeJscsR3y7T/ZGSIL6nA
         VauCocpqZWPsHoLWPfSNEJmuxIWXlm5BVIFLYT6Gyl1/41jqnBcdHsKQ/97A2aVD45l3
         7Byg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=qY8QMazCKdLhYr2c9DBbQp11M9k0jh8sRC1ebNv/DUk=;
        b=GDN8rRNziyvsSAjKzbtjhX4wG6OaQFG0LAK6r+IgODlvcDAeS2Ruwx+18mDkrKjGjb
         BtjiaMkv4in0G2DE9T1BBiuDfEJEGxzXU0gbMXo5zhRuQbkTUxznVZY+SLjmHkvYUu3/
         5YxWxRs6K/+M1gtxyk2PjzfDyRcanZFykQv1ij/o0szhQihltayoWX9VphPTrxwT8d9v
         1UceOcQmnJzmjiL8LPhkkg0qtLirC4YcoPLzG++4w93+gY1vv4NAllsPODZPb8GtoFg4
         EiZXhk8HaNDAuPoCYDmvwrSvgl0I00b9WwI4D3AB1clGWgMsAlZVyJOP+Ddcjz0GmALv
         hpDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=vm+D9PSK;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qY8QMazCKdLhYr2c9DBbQp11M9k0jh8sRC1ebNv/DUk=;
        b=UNpT20dPSpIBIARzQ/pw2De0g7rs5oees+0rG3+BBs8Bc4j0rJ++5p0sDA99/++6xt
         M7WhYHbQivqwFwddfR0tUvQvQrHMuqu/6W8Qn6Q2adllR3RhdAc8ochbGnQGde2uEBBb
         SbfLuf37hK8g8WJ790D+6XsX6X9++2z4mbEzYGZvwPghEf9Lv2U1uaQueBpInRiacfN6
         IqxksucIyxUUpttrUKlVLVE6lZ2Ffx2VBRTa6fd/qyaL26Ka1+GDVQb1Fpga1JwBbzsv
         KAEecGFAu2tZqFjupmiBg33BSUyNFauRP/BjukNxpgc6eTqiwXWCg1ysD5C0ejXE8FH4
         XPpQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qY8QMazCKdLhYr2c9DBbQp11M9k0jh8sRC1ebNv/DUk=;
        b=F8GNu5xvc2SM+6yP8cxSFeCDmd0V14fBd6ckCESjpm1u4Ijra4+vdP5X4KupnZgGxP
         6SzsCi11AZOCRVW53vtfBmtdJ/mU8yD6QJVEIEjb0hixoKSm6hg6EzjgI/edg7IBNqF3
         uWdDgKa70IRLMyNxymBvi8GvKP7fyCorvUPtbyfaI4kEKLitM1MODtMk9Brq0Ok8pDZP
         djbneiuTMh9zVC9YYo10HVjy9uwLluaB3hWDtqjQpMdABiRNQcf0b1DeQpTZf7T1o8VG
         Hju8VHlz009LpkeOGlPbbErQAz8H2vmBmdtgSUog7Avi7dgE9jHXnfj2VzFyerfEfEeT
         G9xw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533D/JU5T5S4sOiFLnL3UrrSsCBF/iF69sMmMA7tRPPDnT/TwGOX
	J5O/V2RU70x2Xn7klI22W34=
X-Google-Smtp-Source: ABdhPJz5uvCXgvAKDOY8MvPl+VSzVPDsstxAff12v9WADsZ8FREOYUE2NtLOzsnZHM1PZ3KrFdBnAQ==
X-Received: by 2002:a17:903:31d7:b029:e7:1dfd:4213 with SMTP id v23-20020a17090331d7b02900e71dfd4213mr20166478ple.26.1617080791424;
        Mon, 29 Mar 2021 22:06:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:bd8b:: with SMTP id z11ls899075pjr.1.gmail; Mon, 29
 Mar 2021 22:06:31 -0700 (PDT)
X-Received: by 2002:a17:902:edc2:b029:e4:3738:9b23 with SMTP id q2-20020a170902edc2b02900e437389b23mr31852398plk.37.1617080790901;
        Mon, 29 Mar 2021 22:06:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617080790; cv=none;
        d=google.com; s=arc-20160816;
        b=TyBCn8p98YrxzwrgvPVG9KlfBE0Qa+8zHoVEcj3KchY4P3Rle6cEQ6KkfgZ0/qjiG8
         P70bnhcr5dLVOQAaYvE2r++HB7BnGvlJmgcE7FrUnwMpnvoFHj8uIj5fQ5bvcA9Bek9r
         T1mNfee8ilJbp0ODhTkdmTiyxUasxSUidPCqPoP7mO2ZsBrJTIU5nIK4gVdvSUY8ERW6
         rmNK9WY/0/9gr1iEbTiV5ZOxMPKDbHwqwfu7Do3Tkw6Lx8LyekrDJEndPlEHTgUWeMC4
         hU4vBKxza1sWjg1IKoX9OHbU9JZYH6RKJDqajMYahmInlYmNIvSjQkqdO1znr9XQx5gY
         Ffeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=vUHPJZsD1HsjvzEusIUyaB/CqNpQTfUUNzEFAb1GBPs=;
        b=xg2twg6lgtxUh/TUVnOEvnY9wVFVwvOt/6nTwwAaQbvQV/UkwloanpZk/s42mPMfCs
         DKx6acab8NwftNMC85+06cv7ln/eZ38cNKIXeoO5+PLu1PN0VVHpfNQusbXrbt5FM5uo
         tp4XKht0GCf3lLpGbEb3f9qQsJxoG3YmUQ0DV8/wAoQhAhBeQZCBiySvADMZR2qOnQsE
         reznXfcrs1J/WesS0SEYHzW7AbxqQ1+eyS+S7OM1yn4ASVZR/jpaS4HEvUcCig8ERmaQ
         HceoM7juln7nfBC0BRqCLpINpUk8EePUs7ncMgWCUDam+fwVoiIGztvEJbBvdk3S/wxT
         vYrw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=vm+D9PSK;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pj1-x1030.google.com (mail-pj1-x1030.google.com. [2607:f8b0:4864:20::1030])
        by gmr-mx.google.com with ESMTPS id e200si803774pfh.3.2021.03.29.22.06.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 29 Mar 2021 22:06:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::1030 as permitted sender) client-ip=2607:f8b0:4864:20::1030;
Received: by mail-pj1-x1030.google.com with SMTP id il9-20020a17090b1649b0290114bcb0d6c2so8852977pjb.0
        for <kasan-dev@googlegroups.com>; Mon, 29 Mar 2021 22:06:30 -0700 (PDT)
X-Received: by 2002:a17:90b:16cd:: with SMTP id iy13mr2671264pjb.46.1617080790431;
        Mon, 29 Mar 2021 22:06:30 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id i14sm1341926pjh.17.2021.03.29.22.06.29
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 29 Mar 2021 22:06:30 -0700 (PDT)
Date: Mon, 29 Mar 2021 22:06:30 -0700 (PDT)
Subject: Re: [PATCH v3 2/2] riscv: Cleanup KASAN_VMALLOC support
In-Reply-To: <20210313084505.16132-3-alex@ghiti.fr>
CC: Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu,
  nylon7@andestech.com, nickhu@andestech.com, aryabinin@virtuozzo.com, glider@google.com,
  dvyukov@google.com, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
  kasan-dev@googlegroups.com, alex@ghiti.fr
From: Palmer Dabbelt <palmer@dabbelt.com>
To: alex@ghiti.fr
Message-ID: <mhng-1a492a0c-049e-495e-8258-7513a4fa967a@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=vm+D9PSK;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::1030 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Sat, 13 Mar 2021 00:45:05 PST (-0800), alex@ghiti.fr wrote:
> When KASAN vmalloc region is populated, there is no userspace process and
> the page table in use is swapper_pg_dir, so there is no need to read
> SATP. Then we can use the same scheme used by kasan_populate_p*d
> functions to go through the page table, which harmonizes the code.
>
> In addition, make use of set_pgd that goes through all unused page table
> levels, contrary to p*d_populate functions, which makes this function work
> whatever the number of page table levels.
>
> Signed-off-by: Alexandre Ghiti <alex@ghiti.fr>
> Reviewed-by: Palmer Dabbelt <palmerdabbelt@google.com>
> ---
>  arch/riscv/mm/kasan_init.c | 59 ++++++++++++--------------------------
>  1 file changed, 18 insertions(+), 41 deletions(-)
>
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> index 57bf4ae09361..c16178918239 100644
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
> @@ -155,38 +143,27 @@ static void __init kasan_populate(void *start, void *end)
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
>
>  	local_flush_tlb_all();
>  }

Thanks, this is on for-next.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-1a492a0c-049e-495e-8258-7513a4fa967a%40palmerdabbelt-glaptop.
