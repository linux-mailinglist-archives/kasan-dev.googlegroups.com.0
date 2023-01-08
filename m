Return-Path: <kasan-dev+bncBDOY5FWKT4KRB6HI5OOQMGQEFWAYHLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 51D796616DA
	for <lists+kasan-dev@lfdr.de>; Sun,  8 Jan 2023 17:51:05 +0100 (CET)
Received: by mail-wm1-x33c.google.com with SMTP id m38-20020a05600c3b2600b003d1fc5f1f80sf5950334wms.1
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Jan 2023 08:51:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673196665; cv=pass;
        d=google.com; s=arc-20160816;
        b=rqcK+IaYW3HSIeClUXFR47ikP+ArdZXjqbYt6n3gWneonVlZ2BgKx8k9wfiJcHB8Wr
         aRb0+5f+zhAYzVZKi4x2lPzHznsvIokWQJ0VkYbuPMvTNHAL1xmJs3c+D07cp6mLY/CO
         GQxwjeBSp46cSdFIMQ2Sszi0AHJA+LjbastfIjAIEkbP4tZCynnOD5MzeSrYzZV6NpRl
         iQOaQCgL33P3xqpA7W6oNuAxjbjaFF0nR2AkPI9Mjt4Jnn5b++nOalmiRcNU+lpGK3rA
         v7dLOWQ0DvLaBZOSie1rMueopdVlTj/7Hbpb9R7FYpY4iqH5cR+G7lMBao00Naboq4mA
         lAHg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=eBRgpzIloD1XJqHcoGVZNACmD7cG+RxkSQocj4YXgBY=;
        b=ZF3yXiIcGEhs/A83HT5SHwBqSOygLZZTV85Bgdt2pDIz1F4ujFrgS9zPHfxrCKi8YJ
         MKoEq+xm2sEjzSP/KFydetQJ1FctR2QqeCV6ap5aaZOUdh+TWiA3KazS3AmeCLC65g+F
         QWqMSevaAiHfMkWkpKKMi6mWD0EB3GntgLjmjkS3bzLxi+IrIDybKIX7BRjDiEOlI5Rg
         NLuRZ1ZQpvrLog4K5xSPbeV+Lv+lMI0yu4fT14krnBw17gnsh02TPpEF1N8awB3fdQnC
         FGCcehMlWFXRNBgArOAQWv4xqSWFFa8K6crC8CYaMe2zxYpD8jQvYesUZt9//yZmWxIw
         voPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BtebHmmq;
       spf=pass (google.com: domain of rppt@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=eBRgpzIloD1XJqHcoGVZNACmD7cG+RxkSQocj4YXgBY=;
        b=GSafToaEWaEjMDRActLkifAhpEPv2JkrVOsT3wSq/+VzHahBrBJyxNGI9LI4bjQKi4
         xYc77n+rS7uzWuEoatknGo1+O+V7SYGCSO+rflVZXSiC030xZx4A1Eg6OMngitHxKthk
         0jxF6tjJZ6ditydNo1476DIHkXHnQRHGt1RPR+I+pMP/3Kn4BYCZ16kjb8ax4rNj0ie2
         c/Ya8G3vY6m4qr/SZTsClMFqdQuqJ0yMKYUur9rRYiTN2LkN2/5XIFrdEBv3V0jksAL/
         jZvpQroY5dIa6BjZK6MBp1bjghWh2X29gCgn0jFQEBXe0QztvFRw6WHSU2RiDTAk14KK
         5iwg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eBRgpzIloD1XJqHcoGVZNACmD7cG+RxkSQocj4YXgBY=;
        b=Ew/dZo3/ADmWX1CBXJ8MEUNivBJzDNseMkUh+Ni/Z6/tgdaZD1/I++CdY5UtX28wfE
         FMWL5nYAKj7LKxBFzMytOidr7WUqetlQNne4UF+Ateq3DppqULUnVhaO0qVcl/p/h66T
         SYzuric0HfUM9P4WZ1mNn+3wXMS44XUW6fj4rhY0FrBAD31WkcOjZ9oHHa8rRRKGMl/p
         4LtEN14qPkFyDLz2N34u2AAB9hr5LNC4VsKKAwsqWpBp37JJW0dh+o+lg/DoXVObYUpG
         1EP+/wE9nKq/LA/roR3AOImFuASdvMocDXKWIr8H6QkTAVbaj2z92FabD+ftg8yB6y7+
         nwQw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2kry8fPeQ3ViaTul0+gN9HCbh23/61QbpZuEECItiDSg0sDr1vbh
	m/GzQrk1AjwbgiZHIJRBleM=
X-Google-Smtp-Source: AMrXdXvX2dA6avQc8pJaAWDv43n+dE0z4gUuQ8FDXzsSdHsVHri5hSmH4Znlyx/JPQ6rmiW/7842Sg==
X-Received: by 2002:a05:600c:4148:b0:3d2:3897:99e9 with SMTP id h8-20020a05600c414800b003d2389799e9mr3076993wmm.154.1673196664639;
        Sun, 08 Jan 2023 08:51:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4aaf:b0:3d1:be63:3b63 with SMTP id
 b47-20020a05600c4aaf00b003d1be633b63ls3599323wmp.1.-pod-canary-gmail; Sun, 08
 Jan 2023 08:51:03 -0800 (PST)
X-Received: by 2002:a1c:ed19:0:b0:3d3:52bb:3984 with SMTP id l25-20020a1ced19000000b003d352bb3984mr45233847wmh.17.1673196663573;
        Sun, 08 Jan 2023 08:51:03 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673196663; cv=none;
        d=google.com; s=arc-20160816;
        b=izITo2eHEBTA/FS3dKZRgQmEoi/UgveMSfXD51vD3VKvcSFB0HcuL87oM1UiHFL2oh
         cC7GczqP1eukn8FWKn7qzfX896yssWMUmqhtzdErTy3stewphTtwjo76Aww4km8RIvhg
         KTwWncpFZEvCuHNcab74McyEoys3qOU9/ASc7HGBcIyF1LNF9aTGmDEcTepTT1Q//nBT
         sySN3u8eEKEwRCq2c7yKYM6ofOJSDhuYVO7ojOrxu5poNCdJ2mH0SNUJvOS9W7q4ybds
         pkJ+eJVydV2bpIHrPcU2mokd5hpT9uxVJ8QRhQ8+wnUGq1xSpVaSZdyPDFa1bjkVEKMh
         wWRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=kWGPtjdb0i7Eewgft4eB7xLHOFmG9M2Gti1bU6M7HCk=;
        b=A627OflfxtkWjMOoq1xR71gFkQYib8b/ghLX9yqrSkhVqS4pUp2z7vR40Tj5J1thdz
         ZT68kM06/K3XZbzwNYzcOwqFnN2gOmyM42+aULPb1Iyq4UsLAOVU5R3AV3k4x0GVidRp
         gQiHF8Q2BpPGbRq6r9qw4bHk9roPLqtKSmnFWdZeXNGaHmaEc+IwOVP7CGLatHpz6600
         QqSOZJTkTUnw1ZlEm9Vh2B3fH6bhJrTzLieGtW9DMTntww+5ze5vUem/psF0zaq6ti2M
         Bgm3JSkCCcNlgpOkGG9KkTeaJBJDKcPpXvHKzBfE/Sj6rXip3E6cvu5hPMqGQyufBh8r
         mtAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=BtebHmmq;
       spf=pass (google.com: domain of rppt@kernel.org designates 145.40.68.75 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [145.40.68.75])
        by gmr-mx.google.com with ESMTPS id r65-20020a1c2b44000000b003d9cc2bca83si445271wmr.0.2023.01.08.08.51.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 08 Jan 2023 08:51:03 -0800 (PST)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 145.40.68.75 as permitted sender) client-ip=145.40.68.75;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 323FCB80B56;
	Sun,  8 Jan 2023 16:51:03 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8226CC433D2;
	Sun,  8 Jan 2023 16:50:55 +0000 (UTC)
Date: Sun, 8 Jan 2023 18:50:45 +0200
From: Mike Rapoport <rppt@kernel.org>
To: Aaron Thompson <dev@aaront.org>
Cc: linux-mm@kvack.org, "H. Peter Anvin" <hpa@zytor.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Andy Shevchenko <andy@infradead.org>,
	Ard Biesheuvel <ardb@kernel.org>, Borislav Petkov <bp@alien8.de>,
	Darren Hart <dvhart@infradead.org>,
	Dave Hansen <dave.hansen@linux.intel.com>,
	David Rientjes <rientjes@google.com>,
	Dmitry Vyukov <dvyukov@google.com>, Ingo Molnar <mingo@redhat.com>,
	Marco Elver <elver@google.com>,
	Thomas Gleixner <tglx@linutronix.de>, kasan-dev@googlegroups.com,
	linux-efi@vger.kernel.org, linux-kernel@vger.kernel.org,
	platform-driver-x86@vger.kernel.org, x86@kernel.org
Subject: Re: [PATCH v3 1/1] mm: Always release pages to the buddy allocator
 in memblock_free_late().
Message-ID: <Y7r0ZRlwvCK0xOnQ@kernel.org>
References: <20230106222222.1024-1-dev@aaront.org>
 <01010185892de53e-e379acfb-7044-4b24-b30a-e2657c1ba989-000000@us-west-2.amazonses.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <01010185892de53e-e379acfb-7044-4b24-b30a-e2657c1ba989-000000@us-west-2.amazonses.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=BtebHmmq;       spf=pass
 (google.com: domain of rppt@kernel.org designates 145.40.68.75 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Fri, Jan 06, 2023 at 10:22:44PM +0000, Aaron Thompson wrote:
> If CONFIG_DEFERRED_STRUCT_PAGE_INIT is enabled, memblock_free_pages()
> only releases pages to the buddy allocator if they are not in the
> deferred range. This is correct for free pages (as defined by
> for_each_free_mem_pfn_range_in_zone()) because free pages in the
> deferred range will be initialized and released as part of the deferred
> init process. memblock_free_pages() is called by memblock_free_late(),
> which is used to free reserved ranges after memblock_free_all() has
> run. All pages in reserved ranges have been initialized at that point,
> and accordingly, those pages are not touched by the deferred init
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
> 
> One case where this issue can occur in the wild is EFI boot on
> x86_64. The x86 EFI code reserves all EFI boot services memory ranges
> via memblock_reserve() and frees them later via memblock_free_late()
> (efi_reserve_boot_services() and efi_free_boot_services(),
> respectively). If any of those ranges happens to fall within the
> deferred init range, the pages will not be released and that memory will
> be unavailable.
> 
> For example, on an Amazon EC2 t3.micro VM (1 GB) booting via EFI:
> 
> v6.2-rc2:
>   # grep -E 'Node|spanned|present|managed' /proc/zoneinfo
>   Node 0, zone      DMA
>           spanned  4095
>           present  3999
>           managed  3840
>   Node 0, zone    DMA32
>           spanned  246652
>           present  245868
>           managed  178867
> 
> v6.2-rc2 + patch:
>   # grep -E 'Node|spanned|present|managed' /proc/zoneinfo
>   Node 0, zone      DMA
>           spanned  4095
>           present  3999
>           managed  3840
>   Node 0, zone    DMA32
>           spanned  246652
>           present  245868
>           managed  222816   # +43,949 pages
> 
> Fixes: 3a80a7fa7989 ("mm: meminit: initialise a subset of struct pages if CONFIG_DEFERRED_STRUCT_PAGE_INIT is set")
> Signed-off-by: Aaron Thompson <dev@aaront.org>

Applied, thanks!

> ---
>  mm/memblock.c                     | 8 +++++++-
>  tools/testing/memblock/internal.h | 4 ++++
>  2 files changed, 11 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/memblock.c b/mm/memblock.c
> index 511d4783dcf1..fc3d8fbd2060 100644
> --- a/mm/memblock.c
> +++ b/mm/memblock.c
> @@ -1640,7 +1640,13 @@ void __init memblock_free_late(phys_addr_t base, phys_addr_t size)
>  	end = PFN_DOWN(base + size);
>  
>  	for (; cursor < end; cursor++) {
> -		memblock_free_pages(pfn_to_page(cursor), cursor, 0);
> +		/*
> +		 * Reserved pages are always initialized by the end of
> +		 * memblock_free_all() (by memmap_init() and, if deferred
> +		 * initialization is enabled, memmap_init_reserved_pages()), so
> +		 * these pages can be released directly to the buddy allocator.
> +		 */
> +		__free_pages_core(pfn_to_page(cursor), 0);
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y7r0ZRlwvCK0xOnQ%40kernel.org.
