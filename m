Return-Path: <kasan-dev+bncBCOYZDMZ6UMRBZ6ZVOKQMGQE6CNH7YI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 85AF254DD12
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jun 2022 10:42:16 +0200 (CEST)
Received: by mail-ed1-x53b.google.com with SMTP id w14-20020a056402268e00b0043556edda4dsf93816edd.0
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jun 2022 01:42:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655368936; cv=pass;
        d=google.com; s=arc-20160816;
        b=y/kPsFjYv3KR3EmmnIg9cfZ2GbbeZx0xE31ReeDp+jbNIHMDi2dwL3LrlXPS7dy6Kh
         klubu15FDB6lXkSeVDdpbcCbMby4jt/O6urXH7gZED2iR51SL0DfqMjnfU9Bf6EeMyp7
         nanPTQDQa8KoiKQb4V9ZE7FewpxpFJUpXw7aX9IUfUQR7dtZpQWbf+YFRpFiVy4Qbgud
         q+oko/rlwRXuOkK1DrufJaBnp5gUaZCid2euL2U8i9zasdhtNCVSii6VfvTgegfUWHZ4
         B3tiHhNEVJ+He8GczU1LP88E4eANIHWM+m177KgLL2e8HHFPZRs0xFn1X3lMsKlancGg
         sF+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=nnie7s/2T+N7tsxNQOF6q/AESUKwH68ljrrR+nbfKrU=;
        b=xpuFayWvsEGNBvzBAOtHMtVBGd2nviKaYQZCOktsphuRi5kEnJDN4Scvd02F/atwCQ
         3V2m9GziGNC5IJQ+zi3TCTXOdebE8J38eKpTZjb1JDJPtN2pT43ZkqzkzBs6eGiRD1w8
         iTmzofFt+pT9yp81nqRxwxJ5LgMM9HwcAFvkp4AdhM3GIVidFauzwGgr/uETU23qsiqk
         DxRqOK05Ftcv29hTIoFvjtjR8O2lkW709rqgvrN0Bkxxa2AJXoVWG7Xn/BICCV23CBLc
         qoBAXoxILo6xY7mgcdt0jnHIiQh3leKdejVTbRSLsTfSPjWGMSxV3guI3qBnwrJ56J7K
         9odw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:message-id:date:mime-version:user-agent:subject
         :content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nnie7s/2T+N7tsxNQOF6q/AESUKwH68ljrrR+nbfKrU=;
        b=gGRbCnyRHPc8vBozjrbhCQMo42NkkGk8PrBpDU9O/iFKF++rraZCr5xjFKFILuzgzj
         QSfVcQYT/WEtdlhxCiY17FKrXYkxytsHNeI5QYqcbIP8LoYmEmteeMmK2BqOtGESpkAW
         oy/k4J/Ri6Gg7IODdZtWwvjTPc5DGjnLE7S0xv8r+IB1oyqG/jn31KzIUvgWom4KVRz5
         paV8Lpr9ns3vMv12BdHPJZOA9+RBcU0AkTiX1wBtU2vKaB4pqpF0lJ+sVIvyJuvQwPfE
         oQrspTerONtfqDecfqpycZWigeKQYjvV73gTRa/cFFtWdnWTez7BTE5G9hhNRyd793xe
         4kcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nnie7s/2T+N7tsxNQOF6q/AESUKwH68ljrrR+nbfKrU=;
        b=Jpvdnu6JS1nnrJfXvq8C3WFG8d1eNS+6/y9oZjLCfv/AZQ7ANPqqw1QbRld7pI5tb1
         ux43EsRz5XT0NM5ngdU71o9nq2QZpNsoPQx/ZfIfUL5PSC1q0mI0S080GPcuzCvsoSwB
         V6tOvqqb99FoDOc4jYIJNJRBAzLU4zrT3j1wE5kJvam+yBNKR6sfgZ8dr+k8PXte6MlJ
         lPuORjD2m0zsgzHlWNHsNAclODtErMx5BD8J8t36r8AhUpRjFObcAKJhq1IUYlZGJBFd
         0P4cZRCP2szVD+UHBU1E+mZ4YagbEb3qsvtq755mX41bvBZXw3ONBkvCDbsk+lSzOoSz
         pCaQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora+KOWCg5WwbuVa9xFyrWzfp9Bmu4Rgl5FTSEETP5Eey66mZYGbW
	oceCXpONE0FOReAB7vI2T50=
X-Google-Smtp-Source: AGRyM1vnYVP7OV8AO2jmaCpMna35e7GoY0hMWCNPt6GuNzHakZGNwbPGbwaUOuHyI4yX7kXIWKVNXw==
X-Received: by 2002:a05:6402:2552:b0:431:5fc5:5bf with SMTP id l18-20020a056402255200b004315fc505bfmr4962084edb.287.1655368935984;
        Thu, 16 Jun 2022 01:42:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:95c1:b0:6ff:45d:c05d with SMTP id
 n1-20020a17090695c100b006ff045dc05dls463051ejy.5.gmail; Thu, 16 Jun 2022
 01:42:14 -0700 (PDT)
X-Received: by 2002:a17:907:6ea8:b0:711:3404:440d with SMTP id sh40-20020a1709076ea800b007113404440dmr3424026ejc.764.1655368934863;
        Thu, 16 Jun 2022 01:42:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655368934; cv=none;
        d=google.com; s=arc-20160816;
        b=Yxh2MDcwu6sKKoI3CWn3RcNDXp4DaEiKKjfM00jPdI92uXwd5ECIAM0sPZvkeHyg4B
         idYCEXudZ03PO+UMBwxNMzhU5ENIcEZAU+L486zoCJ5IOSJlpGZLeURl5EG8Ba60X5ZC
         bldcnrok+tw/NCKNK79SuBINoNUuGhKfWCQY6XoQwYCVnJWiOA6qerVfM5y2+XIgfU27
         xXMQ/Hi62Vv6lxYxrPNxhnO6z55z1C19EFmaKNXcPqHQcNS30gjAIO7JPQzCUro4dXsL
         lmklNtKiUXVVlhYhekBkXjDYWuBSb4TdEbWUhONVycYX7tB96hBNobFtHeV8Zi4xQKpe
         Uu0g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=qiDoDM0a04NQq98uvEW0S1Dv2gGG9It0Aj6P0RZCzz4=;
        b=Eg7n6zsyMsE70f0/d2+TvBCeIZU50G9wO6EcnTfZX8TRGpGas6ZwhK2Hx5qgG3jloB
         AslaYf7HKD8UIK/L24lcANVi4JsfASil8S/IAP3TWAjW7qogQfF4C35ObDGRACwTmiLf
         IR/DiaysnzMRzZI3WReLQQ+nej7U2pRSCv/ou/xYI+MgNBmpzinJiUruU/clsLKsF31W
         DV7c5ZpYbDXZ8ZifXrtsNMdqSfdJ0WjOVUzJ9hzLMhop0aWOxaTCbxyhYRzPIk0642Nd
         OAHuJMXGECtdN2LjFD3lHO6fTJocMb087LOs+qBhgRlsimRhHZvGP6lzUU8QVNYk1Ktm
         fvCw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id d5-20020a056402400500b0043508a37413si59590eda.5.2022.06.16.01.42.14
        for <kasan-dev@googlegroups.com>;
        Thu, 16 Jun 2022 01:42:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 2D7BB12FC;
	Thu, 16 Jun 2022 01:42:14 -0700 (PDT)
Received: from [10.57.69.164] (unknown [10.57.69.164])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 09D883F7F5;
	Thu, 16 Jun 2022 01:42:11 -0700 (PDT)
Message-ID: <75aa779d-785f-6515-51cd-654e8c5d18f5@arm.com>
Date: Thu, 16 Jun 2022 09:42:10 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.9.1
Subject: Re: [PATCH v2 2/4] mm: kasan: Skip unpoisoning of user pages
Content-Language: en-US
To: Catalin Marinas <catalin.marinas@arm.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Andrey Konovalov <andreyknvl@gmail.com>
Cc: Will Deacon <will@kernel.org>, Peter Collingbourne <pcc@google.com>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-arm-kernel@lists.infradead.org
References: <20220610152141.2148929-1-catalin.marinas@arm.com>
 <20220610152141.2148929-3-catalin.marinas@arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
In-Reply-To: <20220610152141.2148929-3-catalin.marinas@arm.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: vincenzo.frascino@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172
 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
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



On 6/10/22 16:21, Catalin Marinas wrote:
> Commit c275c5c6d50a ("kasan: disable freed user page poisoning with HW
> tags") added __GFP_SKIP_KASAN_POISON to GFP_HIGHUSER_MOVABLE. A similar
> argument can be made about unpoisoning, so also add
> __GFP_SKIP_KASAN_UNPOISON to user pages. To ensure the user page is
> still accessible via page_address() without a kasan fault, reset the
> page->flags tag.
> 
> With the above changes, there is no need for the arm64
> tag_clear_highpage() to reset the page->flags tag.
> 
> Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Peter Collingbourne <pcc@google.com>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> ---
>  arch/arm64/mm/fault.c | 1 -
>  include/linux/gfp.h   | 2 +-
>  mm/page_alloc.c       | 7 +++++--
>  3 files changed, 6 insertions(+), 4 deletions(-)
> 
> diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
> index c5e11768e5c1..cdf3ffa0c223 100644
> --- a/arch/arm64/mm/fault.c
> +++ b/arch/arm64/mm/fault.c
> @@ -927,6 +927,5 @@ struct page *alloc_zeroed_user_highpage_movable(struct vm_area_struct *vma,
>  void tag_clear_highpage(struct page *page)
>  {
>  	mte_zero_clear_page_tags(page_address(page));
> -	page_kasan_tag_reset(page);
>  	set_bit(PG_mte_tagged, &page->flags);
>  }
> diff --git a/include/linux/gfp.h b/include/linux/gfp.h
> index 2d2ccae933c2..0ace7759acd2 100644
> --- a/include/linux/gfp.h
> +++ b/include/linux/gfp.h
> @@ -348,7 +348,7 @@ struct vm_area_struct;
>  #define GFP_DMA32	__GFP_DMA32
>  #define GFP_HIGHUSER	(GFP_USER | __GFP_HIGHMEM)
>  #define GFP_HIGHUSER_MOVABLE	(GFP_HIGHUSER | __GFP_MOVABLE | \
> -			 __GFP_SKIP_KASAN_POISON)
> +			 __GFP_SKIP_KASAN_POISON | __GFP_SKIP_KASAN_UNPOISON)
>  #define GFP_TRANSHUGE_LIGHT	((GFP_HIGHUSER_MOVABLE | __GFP_COMP | \
>  			 __GFP_NOMEMALLOC | __GFP_NOWARN) & ~__GFP_RECLAIM)
>  #define GFP_TRANSHUGE	(GFP_TRANSHUGE_LIGHT | __GFP_DIRECT_RECLAIM)
> diff --git a/mm/page_alloc.c b/mm/page_alloc.c
> index e008a3df0485..f6ed240870bc 100644
> --- a/mm/page_alloc.c
> +++ b/mm/page_alloc.c
> @@ -2397,6 +2397,7 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
>  	bool init = !want_init_on_free() && want_init_on_alloc(gfp_flags) &&
>  			!should_skip_init(gfp_flags);
>  	bool init_tags = init && (gfp_flags & __GFP_ZEROTAGS);
> +	int i;
>  

Nit: Since "i" is not used outside of the for loop context we could use the
contract form "for (int i = 0; ..." which is allowed by C11.

>  	set_page_private(page, 0);
>  	set_page_refcounted(page);
> @@ -2422,8 +2423,6 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
>  	 * should be initialized as well).
>  	 */
>  	if (init_tags) {
> -		int i;
> -
>  		/* Initialize both memory and tags. */
>  		for (i = 0; i != 1 << order; ++i)
>  			tag_clear_highpage(page + i);
> @@ -2438,6 +2437,10 @@ inline void post_alloc_hook(struct page *page, unsigned int order,
>  		/* Note that memory is already initialized by KASAN. */
>  		if (kasan_has_integrated_init())
>  			init = false;
> +	} else {
> +		/* Ensure page_address() dereferencing does not fault. */
> +		for (i = 0; i != 1 << order; ++i)
> +			page_kasan_tag_reset(page + i);
>  	}
>  	/* If memory is still not initialized, do it now. */
>  	if (init)

Either way:

Reviewed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/75aa779d-785f-6515-51cd-654e8c5d18f5%40arm.com.
