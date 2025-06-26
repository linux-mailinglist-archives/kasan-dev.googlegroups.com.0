Return-Path: <kasan-dev+bncBDBK55H2UQKRBV4W6XBAMGQEJNPAKZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x439.google.com (mail-wr1-x439.google.com [IPv6:2a00:1450:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 143A4AE9EC5
	for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 15:30:06 +0200 (CEST)
Received: by mail-wr1-x439.google.com with SMTP id ffacd0b85a97d-3a4f55ea44dsf417005f8f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 26 Jun 2025 06:30:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1750944602; cv=pass;
        d=google.com; s=arc-20240605;
        b=axvlMkN3LU4QksDToF46VRUb/MS84bRJAYhb9zoEQxIKj7mLGzFxTYFjFiFeu2+Juy
         FCRQ0GYU/lH0IGZQTmxd5jFttdV5lNuH5Vvc8xDfZajgNxOcyyGNxJ9DzYhNsv4MmZcm
         Yea85sMs4mcwda0n2+GiSjioFcIGDFx6zVQdAYRWcg8DJMgn7qK0JqbeNAvSWedTZuav
         vXrK5RTjTvn1m2G39Iz+jifMNKgbeCPo6PiAWLmFygqyypX3pVRmW5DFEwlrQgUOkX+B
         m9vSk5eDqEoRvDamWDicf29mw00nLMRIdxTZTD67Wba75YGX+83H745kU2OHXlmEB9WD
         pTVQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=QVCENZ9ak6b4dhC57in9MDuCnY1JuChC8l46KMYdLrI=;
        fh=bFFH6FintuBEziKOfOby7W5PltBZsUqup4w+G6Yx/F0=;
        b=Qc59ZhGG7D7iHKAFKc8kWoYmg3c1rksD28zj1zDMkJ4szGesAxxEQEDiFYFgMZpikp
         0eeCLH8O/ow7lmBQpo5hglUw5ee32V0dixdbvKESZsF2MhlZ2xeUJbGdVkec69lMH8oj
         yxyM2NiLZ4UmWi74+kvkK1E2LTFp5WAt2hRE/99gd1A/95v3/0QsPX/sXmzkY2kXid4r
         +oQw+BH53BAQR1gGyNd1Lh3BozczO04O9PzLdap8TJBsDaX6cg/IsQlLtMzGIjVHieTO
         Bv1oGWDFs19pIikfc7tspDrAhiDVOQZxaI59hLV+H3k+nzOWdiRSSEKnsstVtYH/kRQA
         bztQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=mBNUpeDF;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1750944602; x=1751549402; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QVCENZ9ak6b4dhC57in9MDuCnY1JuChC8l46KMYdLrI=;
        b=ajF0NgkEK7OtMAbQDWPnT4nUDhk7DhFw/rBDzLaAutMsPFNJ3QGJA3q7bw9ZMqWoru
         KKiQcuBjQpaGvV2zD2xIWM1XncdMpWqnaSuw8U//Cbp1MaCbjCHdVUfnyrVDi27ZMZ5c
         WvPMav5d+0wdSiXIXoz97TjNnFnn9IhtUpnsLl+1JU/UM+6vGLs5ZQToFg39CWqIYvLu
         c8l2+0wIE+4GnIm0w3C4LPub2eP1/0+ukzrzXa66BtrfgSNyYu7/CP75xNSJIFh4JAt0
         znjONCjJ+uzDXDCxreGQ/DQvUV0HPSgaoLDw6jOclMsrTF+I/Dk7knZqROHrS+EL8Gj/
         Bg0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1750944602; x=1751549402;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=QVCENZ9ak6b4dhC57in9MDuCnY1JuChC8l46KMYdLrI=;
        b=nMHYlJiyFiDqUOBfiWlT8K+zwexdO/yMLgoHHa8MBFaR6HvyPi2bZpEsYfRo3td2rf
         OcgDVF4UncHBx7XXd3sghYCa2EhAxdqFu5WxNUlpEVc/+WcbgYLCX60nlXVY0b+x97v5
         s/In1rx1f/F1Y9C3+XrQ9twbIwFmKOQITuLl2AnJOg0VWFS7HIgL0yXtzAFOavHp84Ma
         kLZROo9MkyO9aYvgduAWc5KQlZt8Acm7/hxxg4W8I7W72xKkrp4imWUT813BbZ523azg
         cEG8I4APEAz3QhgTCnVpe2NgCGSe/Fy6SJilqucH0k2r2Fnnm/NPwLSmLayOQX5m+BTE
         Em4A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUKl7rV3w8hFDbJJo1LXttWjp3YpUCTZsRVgy49GIs2I4dsQh2RhIc2msz2+YnM6BpwIPbAzg==@lfdr.de
X-Gm-Message-State: AOJu0YxgCbOf04CmIGYWZ5dvisNv1/7MzX8yfY6KyoI0dD9m+Di4QG/b
	X3k7WgKQhlUkptizEvoaf2Ncde6bcqoIvw4E4rMKWPfQpUkpenoOXuUn
X-Google-Smtp-Source: AGHT+IFNg6/XhGfT3LQggEhxVdH1+8t34ni2Z+DEJ5IZ9K2pNiLTZImZYGVy84Z6YbXg3XIw07dfrg==
X-Received: by 2002:a05:6000:40cf:b0:3a4:d02e:84af with SMTP id ffacd0b85a97d-3a6ed67b12bmr5811508f8f.58.1750944601304;
        Thu, 26 Jun 2025 06:30:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc63CjG+kj9mQzw+/zyniK9zZuwPuMcq/9bMnXd33NzLw==
Received: by 2002:a05:600c:1d1f:b0:453:f4b:a664 with SMTP id
 5b1f17b1804b1-4538b9f063cls3859895e9.1.-pod-prod-08-eu; Thu, 26 Jun 2025
 06:29:58 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW1UVXc1b1TxRlEhPtv0xb0alMBRHreNrnOPdL5Lx6rI5gF0U58pf2zX8ndOHcKxptdNljEJFUglzU=@googlegroups.com
X-Received: by 2002:a5d:5e8e:0:b0:3a4:f35b:d016 with SMTP id ffacd0b85a97d-3a6ed61a680mr5940254f8f.11.1750944597820;
        Thu, 26 Jun 2025 06:29:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1750944597; cv=none;
        d=google.com; s=arc-20240605;
        b=eTFshYRH9nwrfdfdzsjfeMXXs5VqEs1J6kSjsWBKS7wHVx+5QielsRXvwL35UwjseD
         EjlvjS8L3vcnvJRqf/+V7iQwkou1Zy7p4OVqM8sI6q/ylgLftyHtGEUpZmKuCn/kiSWa
         Vyh/bQ2gGDYKSVSysHSBHv4PplaayQe21GkghctDEMxpG4sAVfr4akvXN/SBts4kiB/C
         rALIiX0avX+I/nMEgdcvF8RBv/CjDMpfZkli5n5MeIgi7fWPZxI4YwMrjWLYgmRaMkiD
         C6v+psHOA14lNYtrAPGnY0Y5181CGs/0U/hW9izJmbiEn3oIgXHsPKWPqG054I97/Fc9
         dOZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=p1Vrlz3g9lucIoHJorqCas+zLBoRLvQnyL0+A+0WnpA=;
        fh=wLCz6RBe1kvcnRxcdH99TqGMpIg35JoKod5gMU/w/xA=;
        b=NrdXDgbHbFZUqqZQSiIwvMHNYEQUYzo5swvTW/T0uoI6NmQ856ZPQSvbWVJsNpJ4QR
         k4631DMNSFIwTa0LZONRoNnbQIIxsWZ1EMTHYPXyPB14nKbkEh3WCv7HE3zWYfXzm8iH
         vdHj4ra+dZFczKTXnEys+hiK5NcL21Tp5B5ktZmyrd1/tfRUuNzy4zxCL+2jFRnk4XHI
         bp5maUkzwth00XJDzOMxafZCO1hRJhMo1xyxyvajW4ydK6aDKXZbXyg+1FzWZvBABQn7
         lBxq1XULoaAcAdTw35vvexvfPhcuvfw/BhFJZ+XHRG6f1wdOcR1oxZI1l1Ws8a8wxFjR
         S7VA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=mBNUpeDF;
       spf=none (google.com: peterz@infradead.org does not designate permitted sender hosts) smtp.mailfrom=peterz@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3a6e80bffafsi106515f8f.5.2025.06.26.06.29.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 26 Jun 2025 06:29:57 -0700 (PDT)
Received-SPF: none (google.com: peterz@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from 77-249-17-252.cable.dynamic.v4.ziggo.nl ([77.249.17.252] helo=noisy.programming.kicks-ass.net)
	by casper.infradead.org with esmtpsa (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uUmfg-0000000Biam-20O3;
	Thu, 26 Jun 2025 13:29:44 +0000
Received: by noisy.programming.kicks-ass.net (Postfix, from userid 1000)
	id 5644930BDA9; Thu, 26 Jun 2025 15:29:43 +0200 (CEST)
Date: Thu, 26 Jun 2025 15:29:43 +0200
From: Peter Zijlstra <peterz@infradead.org>
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
Cc: ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com,
	dvyukov@google.com, vincenzo.frascino@arm.com,
	catalin.marinas@arm.com, will@kernel.org, chenhuacai@kernel.org,
	kernel@xen0n.name, maddy@linux.ibm.com, mpe@ellerman.id.au,
	npiggin@gmail.com, christophe.leroy@csgroup.eu, hca@linux.ibm.com,
	gor@linux.ibm.com, agordeev@linux.ibm.com,
	borntraeger@linux.ibm.com, svens@linux.ibm.com, richard@nod.at,
	anton.ivanov@cambridgegreys.com, johannes@sipsolutions.net,
	dave.hansen@linux.intel.com, luto@kernel.org, tglx@linutronix.de,
	mingo@redhat.com, bp@alien8.de, x86@kernel.org, hpa@zytor.com,
	chris@zankel.net, jcmvbkbc@gmail.com, akpm@linux-foundation.org,
	guoweikang.kernel@gmail.com, geert@linux-m68k.org, rppt@kernel.org,
	tiwei.btw@antgroup.com, richard.weiyang@gmail.com,
	benjamin.berg@intel.com, kevin.brodsky@arm.com,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	linux-kernel@vger.kernel.org, loongarch@lists.linux.dev,
	linuxppc-dev@lists.ozlabs.org, linux-s390@vger.kernel.org,
	linux-um@lists.infradead.org, linux-mm@kvack.org
Subject: Re: [PATCH 5/9] kasan/loongarch: call kasan_init_generic in
 kasan_init
Message-ID: <20250626132943.GJ1613200@noisy.programming.kicks-ass.net>
References: <20250625095224.118679-1-snovitoll@gmail.com>
 <20250625095224.118679-6-snovitoll@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250625095224.118679-6-snovitoll@gmail.com>
X-Original-Sender: peterz@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=mBNUpeDF;
       spf=none (google.com: peterz@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=peterz@infradead.org
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

On Wed, Jun 25, 2025 at 02:52:20PM +0500, Sabyrzhan Tasbolatov wrote:
> Call kasan_init_generic() which enables the static flag
> to mark generic KASAN initialized, otherwise it's an inline stub.
> 
> Replace `kasan_arch_is_ready` with `kasan_enabled`.
> Delete the flag `kasan_early_stage` in favor of the global static key
> enabled via kasan_enabled().
> 
> printk banner is printed earlier right where `kasan_early_stage`
> was flipped, just to keep the same flow.
> 
> Closes: https://bugzilla.kernel.org/show_bug.cgi?id=218315
> Signed-off-by: Sabyrzhan Tasbolatov <snovitoll@gmail.com>
> ---
>  arch/loongarch/include/asm/kasan.h | 7 -------
>  arch/loongarch/mm/kasan_init.c     | 7 ++-----
>  2 files changed, 2 insertions(+), 12 deletions(-)
> 
> diff --git a/arch/loongarch/include/asm/kasan.h b/arch/loongarch/include/asm/kasan.h
> index 7f52bd31b9d..b0b74871257 100644
> --- a/arch/loongarch/include/asm/kasan.h
> +++ b/arch/loongarch/include/asm/kasan.h
> @@ -66,7 +66,6 @@
>  #define XKPRANGE_WC_SHADOW_OFFSET	(KASAN_SHADOW_START + XKPRANGE_WC_KASAN_OFFSET)
>  #define XKVRANGE_VC_SHADOW_OFFSET	(KASAN_SHADOW_START + XKVRANGE_VC_KASAN_OFFSET)
>  
> -extern bool kasan_early_stage;
>  extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
>  
>  #define kasan_mem_to_shadow kasan_mem_to_shadow
> @@ -75,12 +74,6 @@ void *kasan_mem_to_shadow(const void *addr);
>  #define kasan_shadow_to_mem kasan_shadow_to_mem
>  const void *kasan_shadow_to_mem(const void *shadow_addr);
>  
> -#define kasan_arch_is_ready kasan_arch_is_ready
> -static __always_inline bool kasan_arch_is_ready(void)
> -{
> -	return !kasan_early_stage;
> -}
> -
>  #define addr_has_metadata addr_has_metadata
>  static __always_inline bool addr_has_metadata(const void *addr)
>  {
> diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_init.c
> index d2681272d8f..cf8315f9119 100644
> --- a/arch/loongarch/mm/kasan_init.c
> +++ b/arch/loongarch/mm/kasan_init.c
> @@ -40,11 +40,9 @@ static pgd_t kasan_pg_dir[PTRS_PER_PGD] __initdata __aligned(PAGE_SIZE);
>  #define __pte_none(early, pte) (early ? pte_none(pte) : \
>  ((pte_val(pte) & _PFN_MASK) == (unsigned long)__pa(kasan_early_shadow_page)))
>  
> -bool kasan_early_stage = true;
> -
>  void *kasan_mem_to_shadow(const void *addr)
>  {
> -	if (!kasan_arch_is_ready()) {
> +	if (!kasan_enabled()) {
>  		return (void *)(kasan_early_shadow_page);
>  	} else {
>  		unsigned long maddr = (unsigned long)addr;
> @@ -298,7 +296,7 @@ void __init kasan_init(void)
>  	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)VMALLOC_START),
>  					kasan_mem_to_shadow((void *)KFENCE_AREA_END));
>  
> -	kasan_early_stage = false;
> +	kasan_init_generic();
>  
>  	/* Populate the linear mapping */
>  	for_each_mem_range(i, &pa_start, &pa_end) {
> @@ -329,5 +327,4 @@ void __init kasan_init(void)
>  
>  	/* At this point kasan is fully initialized. Enable error messages */
>  	init_task.kasan_depth = 0;
> -	pr_info("KernelAddressSanitizer initialized.\n");
>  }

This one is weird because its the only arch that does things after
marking early_state false.

Is that really correct, or should kasan_init_generic() be last, like all
the other architectures?

Also, please move init_task.kasan_depth = 0 into the generic thing.
ARM64 might have fooled you with the wrapper function, but they all do
this right before that pr_info you're taking out.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250626132943.GJ1613200%40noisy.programming.kicks-ass.net.
