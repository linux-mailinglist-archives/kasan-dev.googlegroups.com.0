Return-Path: <kasan-dev+bncBCOYZDMZ6UMRB3W2VOKQMGQE46FH2CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id D4FE154DD24
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jun 2022 10:44:31 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id k38-20020a0565123da600b0047974049f03sf444232lfv.23
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Jun 2022 01:44:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1655369071; cv=pass;
        d=google.com; s=arc-20160816;
        b=F7yvRo7SXlek+xEfJz68iIdC0EDgv98Zwr+SRvBGKVjtloExGJSyr7aidO0RidovAf
         Uh4clqQUQq4ImtuKaFn5B8O7eftSOczvwlp15FE0N3TO77nzKk1qOL3cLU+lJE4CV68E
         /0nlkOTNck4qJkrMdF+5PPGl70LtqFIsIjVtTmIgyGibTCIkl/POIwxevk8OSm+sVn/P
         VBz9xz0uZ9E4asfiHfux+nv24fM9xpcuZPzfQpvjwr/OP7krsqAKpILqdLKSh8W5s7zC
         Ewpq2bDHcjOjN+3P0YrXf0o3LfMwcIloEDwk65/0pzILkDx21XZPIQSUGAk3UCx7DR9G
         xAFg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=PD/eNjljlCy4atqFfM98ZLxOGVmg3ftDlsd2WvGldZU=;
        b=diMWf7WBYzLGj/A4BVB4Ciiogos2jc8h5LPX5w3aF5SdmBPHysC9FfvkSXyiwXzRXL
         AwGgozWFTthF6mjr0RaE5qGUQBczetyxrgm8LHgsSrHyDkP+56dYkeWE5PtIPzFBijYu
         3I1hHWFmNpSpjYpc5KJu8GfISvWNSzxTNDAtU6wU4gyLzF8zKAo7qA8l1FAof3zRAJtf
         gMZJo0xjj5XTlQGWS9p10zKb3qJbBuTT4C904A/nU5Esne2QO73Ah00UfA8mPNYt2eyH
         Rs/6Ou52jX8cYkv7ucfbz2SQ1VFLfpDzvHngoNGzRGK/hsEYL4Q0ZqSpAajwElMtMk+r
         YuUg==
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
        bh=PD/eNjljlCy4atqFfM98ZLxOGVmg3ftDlsd2WvGldZU=;
        b=hDRWTfjbw5QyCY7vSnLr7X2GU9pHTxWSeMy6+db8ZquTQZ7bo3GusrTEWE1T/8dq9F
         arDaHy2zNi7eiUbYCESQW9eesCo2yX/Gfs+/VfRAOZ4eiEU8IPvGqtYWGpxj5cFl1wQp
         h3socDB6Avd/B38+tFWlHvFmTvobZgEYmb4WVZWEpfZr7JZN/5YG4Wp7OSb4+uoPdFnm
         e03AyS293E3LZN+Fe5oCI7J3qRAzgXvIKMpEKPTsoXUcxneLyE8og2T24U53sxXzfIoH
         RWhBswpu4kLoevz95y86ixlfPnaG1atAHaXtnpIjKxu8q0MSao17azDwJfC7EkRIOgJT
         wCJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:message-id:date:mime-version:user-agent
         :subject:content-language:to:cc:references:from:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=PD/eNjljlCy4atqFfM98ZLxOGVmg3ftDlsd2WvGldZU=;
        b=1qOj5JDECIQMcFcqpcD0UWtgSTmPdT5J2R2HMF+5cZ1Tw5yOJI7I51Ml/0ldYf8lMj
         dZ1MfseBtRYH2xF0bgQGdu08tlq+s/qodDDAOOvSn3kH9BsPs4ceNB0KxpXBK+yZ37qs
         RNef0bv9EVRzt6RUoFv01CgNQwb94xXSdl0/aTWl11i/FfAto+QEo1/Ocqj+pv8So2fd
         Icq73jdnebNVY73tYXO6u0U7n14cJSZGTQXWldF4Jy6QVW2l3/3uYE4LhflIu5hjeAhx
         raQwdLxQHqECSZrdo0ezCm2XCmEg5tPLCUb3iRVjSzFBXO9amHMfw1ZyXr9faI3QVk92
         AwNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9ie/mzmwR2h7Wmua4gav03GvmhPjjT8yxBLaGY5bLVTwlfZMuz
	unB5oEA8jSYc1sNsCjuUUn0=
X-Google-Smtp-Source: AGRyM1uAfta+SjsAFYtuPfQGohClLBWCCGz9ns5i35DiUk1ShaK78UUBu3rnvOjYzn3vgVHmQu2DuA==
X-Received: by 2002:a2e:8952:0:b0:255:804c:1d3f with SMTP id b18-20020a2e8952000000b00255804c1d3fmr1992583ljk.485.1655369070862;
        Thu, 16 Jun 2022 01:44:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:7003:0:b0:255:95cf:cecf with SMTP id l3-20020a2e7003000000b0025595cfcecfls170331ljc.11.gmail;
 Thu, 16 Jun 2022 01:44:29 -0700 (PDT)
X-Received: by 2002:a2e:9815:0:b0:255:be2d:2fae with SMTP id a21-20020a2e9815000000b00255be2d2faemr1896441ljj.435.1655369069591;
        Thu, 16 Jun 2022 01:44:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1655369069; cv=none;
        d=google.com; s=arc-20160816;
        b=NJD8wpNMxeJ2TrvFyYiyHnBBt2cpWmOrEXmhNOpgBauwuPz4sn8yW5hx3BBH5Fbf4Y
         RCy/w1RwcA6LRXe2tWL4nlfGe4kRzjcmXk/uPET9IPHUWZKGMb7W2OTp0iKge3DFn0Ph
         PLKNsBX4wJ8GT7nl4Cg/lz3CeKOWA4RIvmVNpZM/nzqc4H8NHUU3rl8TfxzwEtty08lj
         nulQxOTHSbjemiUhXUlJtKgaJEbP2ugd6MEdgKvF0qW+LumD3sGfXL+NlUW6qAH75Bnb
         ssk+KcPFzLyO1YDJAsau1sYRt4NmXCBigESL76oP+NOFrDXYyPbxRPjoqyzcLmbGQhC0
         EZyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:from:references:cc:to
         :content-language:subject:user-agent:mime-version:date:message-id;
        bh=zGFzUSVc3OuXIfFjyLXIuVxInYV1frPtWAMf8rzZYgo=;
        b=DOjQq/C5Uhy3lvxVXVdjN2F7uV/XQwVLhYTUbDIjEwS5H28hEYaMUfs+ucSCyKiXvi
         MMNWQuI/qekvcg8p2t8sCHhXY0ErMkY/vVp4TJVJjyo0ul5RlMpg0EO9jHRM2V6gzkqj
         GgSkc0kkKDPwMwgjkxCFijsXF0oKQ/TJK/WiNobNSRVzKZD2qZ+oilRWMUmSPSKQJCQS
         N58UVvnJvSNZqnzd5YWoenk2D9sB47ZplFp0mGIqtjGqAH7cJLDoG8XAlsfmHgs607kW
         HHI8vt2pPb3kCVOeSML0fbLiv3NS/OHv+TzZzG1EfW9GzhH4nUaAh+wj4EVBhCGd7elO
         OnGg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=vincenzo.frascino@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id c13-20020a2ebf0d000000b0025a45f568e9si39401ljr.0.2022.06.16.01.44.28
        for <kasan-dev@googlegroups.com>;
        Thu, 16 Jun 2022 01:44:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of vincenzo.frascino@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 4127D13D5;
	Thu, 16 Jun 2022 01:44:28 -0700 (PDT)
Received: from [10.57.69.164] (unknown [10.57.69.164])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 8B02C3F7F5;
	Thu, 16 Jun 2022 01:44:26 -0700 (PDT)
Message-ID: <266cb1c3-6167-8be2-57cf-4f6cf15ae7d1@arm.com>
Date: Thu, 16 Jun 2022 09:44:24 +0100
MIME-Version: 1.0
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101
 Thunderbird/91.9.1
Subject: Re: [PATCH v2 4/4] arm64: kasan: Revert "arm64: mte: reset the page
 tag in page->flags"
Content-Language: en-US
To: Catalin Marinas <catalin.marinas@arm.com>,
 Andrey Ryabinin <ryabinin.a.a@gmail.com>,
 Andrey Konovalov <andreyknvl@gmail.com>
Cc: Will Deacon <will@kernel.org>, Peter Collingbourne <pcc@google.com>,
 kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-arm-kernel@lists.infradead.org
References: <20220610152141.2148929-1-catalin.marinas@arm.com>
 <20220610152141.2148929-5-catalin.marinas@arm.com>
From: Vincenzo Frascino <vincenzo.frascino@arm.com>
In-Reply-To: <20220610152141.2148929-5-catalin.marinas@arm.com>
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
> This reverts commit e5b8d9218951e59df986f627ec93569a0d22149b.
> 
> Pages mapped in user-space with PROT_MTE have the allocation tags either
> zeroed or copied/restored to some user values. In order for the kernel
> to access such pages via page_address(), resetting the tag in
> page->flags was necessary. This tag resetting was deferred to
> set_pte_at() -> mte_sync_page_tags() but it can race with another CPU
> reading the flags (via page_to_virt()):
> 
> P0 (mte_sync_page_tags):	P1 (memcpy from virt_to_page):
> 				  Rflags!=0xff
>   Wflags=0xff
>   DMB (doesn't help)
>   Wtags=0
> 				  Rtags=0   // fault
> 
> Since now the post_alloc_hook() function resets the page->flags tag when
> unpoisoning is skipped for user pages (including the __GFP_ZEROTAGS
> case), revert the arm64 commit calling page_kasan_tag_reset().
> 
> Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
> Cc: Will Deacon <will@kernel.org>
> Cc: Vincenzo Frascino <vincenzo.frascino@arm.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Peter Collingbourne <pcc@google.com>

Reviewed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

> ---
>  arch/arm64/kernel/hibernate.c | 5 -----
>  arch/arm64/kernel/mte.c       | 9 ---------
>  arch/arm64/mm/copypage.c      | 9 ---------
>  arch/arm64/mm/mteswap.c       | 9 ---------
>  4 files changed, 32 deletions(-)
> 
> diff --git a/arch/arm64/kernel/hibernate.c b/arch/arm64/kernel/hibernate.c
> index 2e248342476e..af5df48ba915 100644
> --- a/arch/arm64/kernel/hibernate.c
> +++ b/arch/arm64/kernel/hibernate.c
> @@ -300,11 +300,6 @@ static void swsusp_mte_restore_tags(void)
>  		unsigned long pfn = xa_state.xa_index;
>  		struct page *page = pfn_to_online_page(pfn);
>  
> -		/*
> -		 * It is not required to invoke page_kasan_tag_reset(page)
> -		 * at this point since the tags stored in page->flags are
> -		 * already restored.
> -		 */
>  		mte_restore_page_tags(page_address(page), tags);
>  
>  		mte_free_tag_storage(tags);
> diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
> index 57b30bcf9f21..7ba4d6fd1f72 100644
> --- a/arch/arm64/kernel/mte.c
> +++ b/arch/arm64/kernel/mte.c
> @@ -48,15 +48,6 @@ static void mte_sync_page_tags(struct page *page, pte_t old_pte,
>  	if (!pte_is_tagged)
>  		return;
>  
> -	page_kasan_tag_reset(page);
> -	/*
> -	 * We need smp_wmb() in between setting the flags and clearing the
> -	 * tags because if another thread reads page->flags and builds a
> -	 * tagged address out of it, there is an actual dependency to the
> -	 * memory access, but on the current thread we do not guarantee that
> -	 * the new page->flags are visible before the tags were updated.
> -	 */
> -	smp_wmb();
>  	mte_clear_page_tags(page_address(page));
>  }
>  
> diff --git a/arch/arm64/mm/copypage.c b/arch/arm64/mm/copypage.c
> index 0dea80bf6de4..24913271e898 100644
> --- a/arch/arm64/mm/copypage.c
> +++ b/arch/arm64/mm/copypage.c
> @@ -23,15 +23,6 @@ void copy_highpage(struct page *to, struct page *from)
>  
>  	if (system_supports_mte() && test_bit(PG_mte_tagged, &from->flags)) {
>  		set_bit(PG_mte_tagged, &to->flags);
> -		page_kasan_tag_reset(to);
> -		/*
> -		 * We need smp_wmb() in between setting the flags and clearing the
> -		 * tags because if another thread reads page->flags and builds a
> -		 * tagged address out of it, there is an actual dependency to the
> -		 * memory access, but on the current thread we do not guarantee that
> -		 * the new page->flags are visible before the tags were updated.
> -		 */
> -		smp_wmb();
>  		mte_copy_page_tags(kto, kfrom);
>  	}
>  }
> diff --git a/arch/arm64/mm/mteswap.c b/arch/arm64/mm/mteswap.c
> index a9e50e930484..4334dec93bd4 100644
> --- a/arch/arm64/mm/mteswap.c
> +++ b/arch/arm64/mm/mteswap.c
> @@ -53,15 +53,6 @@ bool mte_restore_tags(swp_entry_t entry, struct page *page)
>  	if (!tags)
>  		return false;
>  
> -	page_kasan_tag_reset(page);
> -	/*
> -	 * We need smp_wmb() in between setting the flags and clearing the
> -	 * tags because if another thread reads page->flags and builds a
> -	 * tagged address out of it, there is an actual dependency to the
> -	 * memory access, but on the current thread we do not guarantee that
> -	 * the new page->flags are visible before the tags were updated.
> -	 */
> -	smp_wmb();
>  	mte_restore_page_tags(page_address(page), tags);
>  
>  	return true;

-- 
Regards,
Vincenzo

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/266cb1c3-6167-8be2-57cf-4f6cf15ae7d1%40arm.com.
