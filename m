Return-Path: <kasan-dev+bncBDOY5FWKT4KRB45J26OQMGQEBE74KDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x40.google.com (mail-oa1-x40.google.com [IPv6:2001:4860:4864:20::40])
	by mail.lfdr.de (Postfix) with ESMTPS id 7BBDF65DCDA
	for <lists+kasan-dev@lfdr.de>; Wed,  4 Jan 2023 20:35:17 +0100 (CET)
Received: by mail-oa1-x40.google.com with SMTP id 586e51a60fabf-14c90f25682sf15221117fac.10
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Jan 2023 11:35:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1672860916; cv=pass;
        d=google.com; s=arc-20160816;
        b=BBClgZaNa8lJuG6rx0JUUGvPCuHlL5yarVl9xklvu+24n1dX4RcSgxVtF7lcpw6twK
         E/Ag8dxZ1QJ9ZGAMJVzKTaEd2HeoS3/mkJ3oj9d/vU1xIj6Jd2ybRISMo1cVpw+qxOMG
         sGCIzJg6dH5GHMQSGvPvltnPUmNU+4bxT2DXqREx6EnC762l9ubc36GpwWumlzKrrUnc
         EBsoJ3ucbNT2JLuT18EbyMzYRP5VS/p4JXO1mgBdn1i6+TSE+lUofZSLOoCGMx/RYach
         tMT6NvSuNAzRbwfexvrP7C2MZzbKbHhuaRcaSNZCOjPeDhvHkB38hbSjGsn/8CbmFvJr
         WSsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=YXqs2maU/9G4UEy8Lblh1ftY2MIhXf/oFhaPY5iADac=;
        b=kMDizq/VWkuNdZVdOtrQZq8/mdXZog/Cz67PZY6ERsS0Uza7hFQ+X5hgGi2TnHQ4Gx
         /InWXnzYQsY4Bm/OkRIxkrLCrsdC65Ov0qRmrnE66nPp8Q4TWx96ivkII8gwxPmLJFW4
         A5h+/539MCaIrC1BksWPfO5Ly+QMi2iKoE8HpqbdVPzmPDc1xoXvOVW/B/hrsyuYqsih
         wJcFahVrbRC9PNMu33kTiMgSMw/QRGp5gITWRO/5ux+GszQqFHKX26ePLY/Oq8yGJoPU
         JVn9dCvf1lluQzkendEQLYcWOQVkYEVGlhiqvOXat2ORpF04TT9sbgc8npyi4fAKfv4B
         X0zA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CZG94dIa;
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YXqs2maU/9G4UEy8Lblh1ftY2MIhXf/oFhaPY5iADac=;
        b=ZHnVfZaw2mw5TAN94/SuerCPotyvAYYwEyVq1TojWwUMxwjWkywF5BMMXjc252pzS9
         Jq0drTZwoCL5XW7cA22DHyW5AO4s3Q+dA100djVrj453HpobLtHtx6sNKR3at03GMOU+
         /ZtciR5G6DVyoIkcxysyCtsWqBXFNVkzCnhTWGX96yDXMXbpPN1AIoTfiFhpiBa5hkOV
         GxUs5apWg7cBWFCQxIbUs2qNnYkG/2Ob+g06PduhNfclAbyVd17AqP7Ct/JwOJFr24tx
         xmtqXRUYDsCJ0PJvU60URx4My1qFj+Qq6n3FvaECEIex3KNSLVU2DCw3Y3v8gCNkkwNa
         s+bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=YXqs2maU/9G4UEy8Lblh1ftY2MIhXf/oFhaPY5iADac=;
        b=EOPbT8fAr9aamwKZR7mq62zBEn+boWn4wlHjR8m/1WlA3uzPjgyT+0AnngI09/++7m
         GF1EmgzqWxtBW/e6W5lhOKR8ghnYnE4JDCJA01tSSc+XjR/zJvB6ArKZy+QZsKVzHyNy
         nRceurYI9VeH8b/426hyc2U6MWT2ErF6kist6i2JQmqX2ABQwxj+AXUljoxp4CpWae3r
         fhdCQZzuV9SIEsNbGkQ/fh/AqUEp+AINuZ7jQApCVCzedimwmwZGWgf7grxKuQiRSheV
         Yp5bfrJzLDj6widI9x7QcCjhIMRWSKPh5vvg3ty4W21cdg4DZlMrQygPp4u4uhRANHiU
         leAg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kpR7b2Bk7mld//kYb9u/3kgsvz4LL39TAQxS7FY2Rmv2z9Ut5Vk
	Q2DdNvw0IB02ZcCLk0+ZGpw=
X-Google-Smtp-Source: AMrXdXu7QKCkFWUGxCzjPjZoqW41sJcZzBrTHdThHG8WI0GWB9POIbEkGbqUQRUNVjmDxgFsAqtVMA==
X-Received: by 2002:a05:6830:1441:b0:670:f1c7:789d with SMTP id w1-20020a056830144100b00670f1c7789dmr2101733otp.33.1672860915910;
        Wed, 04 Jan 2023 11:35:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:4e6:0:b0:66e:aed3:654a with SMTP id 93-20020a9d04e6000000b0066eaed3654als5498001otm.4.-pod-prod-gmail;
 Wed, 04 Jan 2023 11:35:15 -0800 (PST)
X-Received: by 2002:a9d:6d8b:0:b0:676:88d1:575c with SMTP id x11-20020a9d6d8b000000b0067688d1575cmr27416723otp.14.1672860915565;
        Wed, 04 Jan 2023 11:35:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1672860915; cv=none;
        d=google.com; s=arc-20160816;
        b=N/Us3KS/iAYZMYy4cewrNkNLLZLBx1shArkxpP8ebAlS2x94hzgQ9xVTLWo35Hr6gk
         4Akv9d/1axnsKNaKs0ueKY72stu0MdPzGcc1HdCT4Fe0ECdKbonFhuDcxRoX+jJdSyZc
         Ur44xLsWJnA8r9/FZ3fvGnSRWvMm7HW4SZ3fMEVHoVgS/al7giCXL3qdpR8OYKZUczQ1
         /9Aq6SF+TgMJAROyKm7lcRe0NF+g9n7kZUx2JW/QTFY8F7BE5+SfH/bbpWmAJa9hoWC7
         dmV2yVAtVYr0Di8ZU/OVlgSVne9vZPbNUFh44nP/j48CnhSHp9S8v3KUz7c7bORLxgc/
         wqOw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=vxL5P38A5MF2VaxMGG+r7VO721m/rv62JfmYkR/SGps=;
        b=M8ViF/AHC2KvCfvP2BD72PEDjeR0Wvbapk90SA3/9sdn/4Bbxju47bjuVzAlmR++Cv
         9CKJ9ze+tpEhQwxTHC/Ns0N9po3r81v3NE7ApA7nn0HW3pZDQPsiETs+6ztdoGAG1HnA
         78y9b0ux3xSWRkqV7C9Y1r9d2RR670wvldoTuycg+6XSUpEfwHsoC8uXqYBxofPoioBf
         Kz/9Fjp1gJhzPPWqps1qiL6RCMj/7WdsuYRc7NsFIDTbPFRxJasLcFbtXGp4akTEefVQ
         PEKJ89m1KVxZjQxl/E5pazfrlzzp1jyL35sHQouTTZSfHp5M1t6La1TD7jvLdWckx147
         sxew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=CZG94dIa;
       spf=pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id g84-20020acab657000000b00353e4e7f335si4638662oif.4.2023.01.04.11.35.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 04 Jan 2023 11:35:15 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 4C38A617ED;
	Wed,  4 Jan 2023 19:35:15 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id E819FC433EF;
	Wed,  4 Jan 2023 19:35:08 +0000 (UTC)
Date: Wed, 4 Jan 2023 21:34:57 +0200
From: Mike Rapoport <rppt@kernel.org>
To: Aaron Thompson <dev@aaront.org>
Cc: linux-mm@kvack.org, "H. Peter Anvin" <hpa@zytor.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andy@infradead.org>,
	Ard Biesheuvel <ardb@kernel.org>, Borislav Petkov <bp@alien8.de>,
	Darren Hart <dvhart@infradead.org>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>,
	Marco Elver <elver@google.com>,
	Thomas Gleixner <tglx@linutronix.de>, kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org, linux-kernel@vger.kernel.org,
	platform-driver-x86@vger.kernel.org, x86@kernel.org
Subject: Re: [PATCH 1/1] mm: Always release pages to the buddy allocator in
 memblock_free_late().
Message-ID: <Y7XU4Wf2ohArLtvs@kernel.org>
References: <20230104074215.2621-1-dev@aaront.org>
 <010101857bbc4d26-d9683bb4-c4f0-465b-aea6-5314dbf0aa01-000000@us-west-2.amazonses.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <010101857bbc4d26-d9683bb4-c4f0-465b-aea6-5314dbf0aa01-000000@us-west-2.amazonses.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=CZG94dIa;       spf=pass
 (google.com: domain of rppt@kernel.org designates 2604:1380:4641:c500::1 as
 permitted sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=NONE
 sp=NONE dis=NONE) header.from=kernel.org
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

Hi,

On Wed, Jan 04, 2023 at 07:43:36AM +0000, Aaron Thompson wrote:
> If CONFIG_DEFERRED_STRUCT_PAGE_INIT is enabled, memblock_free_pages()
> only releases pages to the buddy allocator if they are not in the
> deferred range. This is correct for free pages (as defined by
> for_each_free_mem_pfn_range_in_zone()) because free pages in the
> deferred range will be initialized and released as part of the deferred
> init process. memblock_free_pages() is called by memblock_free_late(),
> which is used to free reserved ranges after memblock_free_all() has
> run. memblock_free_all() initializes all pages in reserved ranges, and

To be precise, memblock_free_all() frees pages, or releases them to the
pages allocator, rather than initializes.

> accordingly, those pages are not touched by the deferred init
> process. This means that currently, if the pages that
> memblock_free_late() intends to release are in the deferred range, they
> will never be released to the buddy allocator. They will forever be
> reserved.
> 
> In addition, memblock_free_pages() calls kmsan_memblock_free_pages(),
> which is also correct for free pages but is not correct for reserved
> pages. KMSAN metadata for reserved pages is initialized by
> kmsan_init_shadow(), which runs shortly before memblock_free_all().
> 
> For both of these reasons, memblock_free_pages() should only be called
> for free pages, and memblock_free_late() should call __free_pages_core()
> directly instead.

Overall looks fine to me and I couldn't spot potential issues.

I'd appreciate if you add a paragraph about the actual issue with EFI boot
you described in the cover letter to the commit message.

> Fixes: 3a80a7fa7989 ("mm: meminit: initialise a subset of struct pages if CONFIG_DEFERRED_STRUCT_PAGE_INIT is set")
> Signed-off-by: Aaron Thompson <dev@aaront.org>
> ---
>  mm/memblock.c                     | 2 +-
>  tools/testing/memblock/internal.h | 4 ++++
>  2 files changed, 5 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/memblock.c b/mm/memblock.c
> index 511d4783dcf1..56a5b6086c50 100644
> --- a/mm/memblock.c
> +++ b/mm/memblock.c
> @@ -1640,7 +1640,7 @@ void __init memblock_free_late(phys_addr_t base, phys_addr_t size)
>  	end = PFN_DOWN(base + size);
>  
>  	for (; cursor < end; cursor++) {
> -		memblock_free_pages(pfn_to_page(cursor), cursor, 0);
> +		__free_pages_core(pfn_to_page(cursor), 0);

Please add a comment that explains why it is safe to call __free_pages_core() here.
Something like

	/*
	 * Reserved pages are always initialized by the end of
	 * memblock_free_all() either during memmap_init() or, with deferred
	 * initialization if struct page in reserve_bootmem_region()
	 */

>  		totalram_pages_inc();
>  	}
>  }
> diff --git a/tools/testing/memblock/internal.h b/tools/testing/memblock/internal.h
> index fdb7f5db7308..85973e55489e 100644
> --- a/tools/testing/memblock/internal.h
> +++ b/tools/testing/memblock/internal.h
> @@ -15,6 +15,10 @@ bool mirrored_kernelcore = false;
>  
>  struct page {};
>  
> +void __free_pages_core(struct page *page, unsigned int order)
> +{
> +}
> +
>  void memblock_free_pages(struct page *page, unsigned long pfn,
>  			 unsigned int order)
>  {
> -- 
> 2.30.2
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y7XU4Wf2ohArLtvs%40kernel.org.
