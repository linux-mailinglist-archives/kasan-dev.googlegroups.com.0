Return-Path: <kasan-dev+bncBCRKNY4WZECBBJNLW2DAMGQEYPBO4KA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id CEA203AD84B
	for <lists+kasan-dev@lfdr.de>; Sat, 19 Jun 2021 08:58:46 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id gp23-20020a17090adf17b029016f3623a819sf4951420pjb.5
        for <lists+kasan-dev@lfdr.de>; Fri, 18 Jun 2021 23:58:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1624085925; cv=pass;
        d=google.com; s=arc-20160816;
        b=ORyu2ora73RyyP5S2egW+UiwK31UNanUWLcGdn0WQ/QDrzwM/VfTyDgdKXzq+9wR98
         w3xrA23L8kBZJD1h6C6CkylMgBA3DkWTeYJq99KzSWp1/4oAGRyqD83/g/2H0qEe2KPd
         DQHHyjh/mbFr8e45vtc5RiVrPkGfgJW7C63wBC88yTp0lggaHUuEGUwBmAgXFtuufcHv
         9uS1Ds5jn74pZiagNqtT/p38UgwG6Kyq1YKcX1atWn0O/RGbOpchDewh1bxnD8A7mEhC
         oh48yRNzBa9SX2SdsGrqaVpIREFUkhGiqWW0POefqld2wsWfwOOY+Kse+irGFi4b0ps2
         t0Uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:sender:dkim-signature;
        bh=YiAcnKPCLXAzsMOdkr+u9Fc8WT0uM9a7pCB11Oz/bZk=;
        b=Mf2uUtgLVn2e/4LDqssEkkI5TE/XRHA4YzUuvuoLAh0AEbjiz4kfFcvxgPwNrY6LMx
         gcgeK7C6yt39cnKODDa1ML0ehq8MY9MEcxkdTwUpsCbENdw9SFnUloNTnGz6IAmRee2O
         K7Fka3vSOwKuwNCxvWLDJLqcpvLueXBx0vqWZQSCaDIcopTRCDobDRdPcOr6xHjiGOr9
         5Oc0ZWo4nXz0I3yIFjayHMYpuaQe0ad2+JjtCJdnPfRkGVcc+8ouUBoIDmOw7Ju1OkU1
         Tpr4GKyd5X/0yXKDjAcL9HXP8ketTqkRke6ClToTOISOy1DFOMA42ZsKMXTaSAI7dcG8
         jdGQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=rep5NbXI;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:subject:in-reply-to:cc:from:to:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YiAcnKPCLXAzsMOdkr+u9Fc8WT0uM9a7pCB11Oz/bZk=;
        b=KSYvFCRHZ6nZwgTkQO4lThvLiKBGHs5KQP91d+F8IEx882fEpqdj3+JqYwSb9E2cMT
         bWwvW+DiFz2o/9zMd4uK+7keWmp+qUUYvG5OJdcG5wDAYiqu8zdeXMYpnI5rRVTk6Tm5
         Apo44fVxd3S0IVLNl8VzoIBLn1uks4JkCD3TQXJMTJ64F2w4YI8iT6lgHUmopieDmZUT
         VeZG+20rgkoCaK7UBJvcWdtPI7KL8bHQR6Upc+HeV1c1IxNmQC2p/2fbDwB4K9TUx5pv
         +Jtsz7ZgCcI4GySUJ3JDZd3Aqgw7nK/pYM5BKA1MJLbAqyo1REVPjhPjMoW1TghG7b8J
         62iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:subject:in-reply-to:cc:from:to
         :message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YiAcnKPCLXAzsMOdkr+u9Fc8WT0uM9a7pCB11Oz/bZk=;
        b=aUQbFNvGt6PHUMVZmdlCKUk+hoQ4TeIcwSOYlXrXPrc/G7rmfQlKUNkDLJr68F22ab
         RybD6qRB13Un/mvIpN+YZ9+LGWTod6lFacNre1QkEalztWidSNu/x2w8kgZAb7m2dfxv
         xDbbDowZP2NUAWyPVJH+2/7JgETwUA+rTCQYXJN+Nu5J+23TxZ1yi75dDN9elMv3K/tm
         B9NHIsVwIDp1sw9MpkdWIIl3U2ET2Zw7IUOuoHELWC47ZKYxvnTEAOZmrbmFH8KkCjVM
         Me3tW2v9HCPBqPwMCZ9BqcX23TAexba2LoUZfRo6gLpGdldUzNPNmfrW/INtQL9CoH2c
         iQrg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533OqHpEbBEba02L1MmVUn/frvu1jyPr9VZJzLqZsL7/6igp52Ra
	pg0tLZIg5gjIWL2kt8UYpVU=
X-Google-Smtp-Source: ABdhPJx1Mwxz9Slm+19tXMm/RWhcxdiN1nXtFxphRP0b2Ds6lAAEVcb/0jki/xaYQI7bjG0jEKcKmg==
X-Received: by 2002:a63:5057:: with SMTP id q23mr13630781pgl.271.1624085925307;
        Fri, 18 Jun 2021 23:58:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:6445:: with SMTP id y66ls5313810pfb.7.gmail; Fri, 18 Jun
 2021 23:58:44 -0700 (PDT)
X-Received: by 2002:a62:d451:0:b029:2ff:4da3:5330 with SMTP id u17-20020a62d4510000b02902ff4da35330mr9083751pfl.6.1624085924758;
        Fri, 18 Jun 2021 23:58:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1624085924; cv=none;
        d=google.com; s=arc-20160816;
        b=HSUqF56FsJxsKy5Nytvxjna7uVsYEJ5Lym2Zn1M/bXNBhkee+GgX15QrzptFf3YZws
         upfbBARoFWGyqJiWYv5QtmKwViKCNTeixXttR0VrctqsAW8g4AA/JDjLCE03kGwMMBu2
         0UR6N3lYDSSPuQmaBFAGErVcaVd1t8Uhce+AnggHUvP/pI7Me3+HyOUaNLMty2SrdAVt
         DQvMAp30LPD9iOxcfKh6ZRkhILrJHHuyDJ/bvXQJ8OyxdzXsehfz6p9duX4xRQATWMBu
         EmNU/rFZ/enTBtIGDWa2K9WKsiL/5kIHG0MXXbtxbEZHiaOMUIlb9CmMjEq/ReuZ5b2K
         JiLw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:to:from:cc
         :in-reply-to:subject:date:dkim-signature;
        bh=6G6cPxZO1wJYjwHrbxpVxaAvSGtra3d9/Cgmg5fS0ec=;
        b=pNc+G+jMO7CKQ+jPfBOto4yAHAeVN/dixMP6sd5U+O6JvEkoTuVfIz3gVz1iQet7hP
         j06hTm7RXsZtj+1ryiA/H8E/w83d09nwNfolzbHfiA64Auov+egtx+gaYUHyrUP2KkXZ
         5YrhGc2A/UzlnwinxnKmSXm1vDyHfcbMYqlzPhptiaTodaDAUcH8tLiExnAA9uxb/hjO
         CpNu5W+rI5gSBL3adaGdbN/pbB/lDGHYXkGO6RfkzZ8E3/ZL0z0i8Uf/1iKxf5UAgHmt
         1QJ8PTDPTIzzr/WAP4m5A83t1rP0u/GfVmjsZE3lc1l/yB8oHH9a/YdzFIQb8XamXn1a
         6oHQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623 header.b=rep5NbXI;
       spf=pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
Received: from mail-pf1-x434.google.com (mail-pf1-x434.google.com. [2607:f8b0:4864:20::434])
        by gmr-mx.google.com with ESMTPS id b3si1982351pjz.1.2021.06.18.23.58.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 18 Jun 2021 23:58:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of palmer@dabbelt.com designates 2607:f8b0:4864:20::434 as permitted sender) client-ip=2607:f8b0:4864:20::434;
Received: by mail-pf1-x434.google.com with SMTP id x73so9446671pfc.8
        for <kasan-dev@googlegroups.com>; Fri, 18 Jun 2021 23:58:44 -0700 (PDT)
X-Received: by 2002:a63:1011:: with SMTP id f17mr13865826pgl.274.1624085924245;
        Fri, 18 Jun 2021 23:58:44 -0700 (PDT)
Received: from localhost (76-210-143-223.lightspeed.sntcca.sbcglobal.net. [76.210.143.223])
        by smtp.gmail.com with ESMTPSA id z185sm10665908pgb.4.2021.06.18.23.58.43
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 18 Jun 2021 23:58:43 -0700 (PDT)
Date: Fri, 18 Jun 2021 23:58:43 -0700 (PDT)
Subject: Re: [PATCH] riscv: kasan: Fix MODULES_VADDR evaluation due to local variables' name
In-Reply-To: <20210618220136.21f32b98@xhacker>
CC: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
  dvyukov@google.com, Paul Walmsley <paul.walmsley@sifive.com>, aou@eecs.berkeley.edu, alex@ghiti.fr,
  kasan-dev@googlegroups.com, linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org
From: Palmer Dabbelt <palmer@dabbelt.com>
To: jszhang3@mail.ustc.edu.cn
Message-ID: <mhng-b491e8d5-d7dc-4f5e-8b96-84d47360d85d@palmerdabbelt-glaptop>
Mime-Version: 1.0 (MHng)
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: palmer@dabbelt.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@dabbelt-com.20150623.gappssmtp.com header.s=20150623
 header.b=rep5NbXI;       spf=pass (google.com: domain of palmer@dabbelt.com
 designates 2607:f8b0:4864:20::434 as permitted sender) smtp.mailfrom=palmer@dabbelt.com
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

On Fri, 18 Jun 2021 07:01:36 PDT (-0700), jszhang3@mail.ustc.edu.cn wrote:
> From: Jisheng Zhang <jszhang@kernel.org>
>
> commit 2bfc6cd81bd1 ("riscv: Move kernel mapping outside of linear
> mapping") makes use of MODULES_VADDR to populate kernel, BPF, modules
> mapping. Currently, MODULES_VADDR is defined as below for RV64:
>
> | #define MODULES_VADDR   (PFN_ALIGN((unsigned long)&_end) - SZ_2G)
>
> But kasan_init() has two local variables which are also named as _start,
> _end, so MODULES_VADDR is evaluated with the local variable _end
> rather than the global "_end" as we expected. Fix this issue by
> renaming the two local variables.
>
> Fixes: 2bfc6cd81bd1 ("riscv: Move kernel mapping outside of linear mapping")
> Signed-off-by: Jisheng Zhang <jszhang@kernel.org>
> ---
>  arch/riscv/mm/kasan_init.c | 8 ++++----
>  1 file changed, 4 insertions(+), 4 deletions(-)
>
> diff --git a/arch/riscv/mm/kasan_init.c b/arch/riscv/mm/kasan_init.c
> index 55c113345460..d7189c8714a9 100644
> --- a/arch/riscv/mm/kasan_init.c
> +++ b/arch/riscv/mm/kasan_init.c
> @@ -169,7 +169,7 @@ static void __init kasan_shallow_populate(void *start, void *end)
>
>  void __init kasan_init(void)
>  {
> -	phys_addr_t _start, _end;
> +	phys_addr_t p_start, p_end;
>  	u64 i;
>
>  	/*
> @@ -189,9 +189,9 @@ void __init kasan_init(void)
>  			(void *)kasan_mem_to_shadow((void *)VMALLOC_END));
>
>  	/* Populate the linear mapping */
> -	for_each_mem_range(i, &_start, &_end) {
> -		void *start = (void *)__va(_start);
> -		void *end = (void *)__va(_end);
> +	for_each_mem_range(i, &p_start, &p_end) {
> +		void *start = (void *)__va(p_start);
> +		void *end = (void *)__va(p_end);
>
>  		if (start >= end)
>  			break;

Thanks for this.  I'd prefer a cleaner fix for tihs (maybe more '_'s in 
_end?), but I don't think we can do that without touching a bunch of 
code.  Given that this is necessary to make the fix work for me, I'm 
just going to take it as-is.

This is on fixes.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/mhng-b491e8d5-d7dc-4f5e-8b96-84d47360d85d%40palmerdabbelt-glaptop.
