Return-Path: <kasan-dev+bncBDK6PCW6XEBBB45AW3CQMGQE2IYVY7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 5BA1DB35A47
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 12:46:14 +0200 (CEST)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-325e31cecd8sf1665961a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 03:46:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756205172; cv=pass;
        d=google.com; s=arc-20240605;
        b=EhSywfMCyCOPfhlOOkfJhthjRiQ6UQNtYj4NgwELiwqr23RFqZ9B7pkTY1ao/GAWT5
         YlHrAjUoO195O+Mdx1nvuK/srtoUwJi09GMtTUbKUYWHXFjkvBGRngGkECsdw5EmYnV4
         0PgqslGcs1hSQWehxyOCEHtzUK2FY1tQZBIy7YgwLfaodEAg2ZQVrtT2u4S9I0AKtAmr
         x/TzR8TKtkiEU1j+VGv5GubW3Q2DOo1FtmywrwujxKgkAavLhtPo22aPYSkKUDB2fDlO
         BtlT+M/SG72EPf9a7YP2wbMJ3EKqBqM9nd7zRTujzGfw+Ae2dueARsP45Ed520IEAyCR
         w4ww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=rCTji3+9myZQIyi7Y5Aojo/T83cvqCoGABUan0Ksoog=;
        fh=+ActcEPCHJGqjVUKFvUsyqKztadQjx5Ki4ByN5Hndko=;
        b=d419UYUoN5Mq/sFI/ZTsz8rjv4p850N65sniVHskePMHAT52wttqUWR39jXf86Y+Se
         foxZtkYqeiG4t1vKCSLLdawJAchrF0i2kAqB2b7EHwm0IYmyp8KimMjFpGzDQcammWiB
         902mLFbt7Ig3svJ2S+gIvgWJltOt10Y46q+QMJAhbokjLNdIuHQiixCp3I/BV/CizY6P
         J9uaxa6uE5ai1bcAu47lO/6uMXPMSmscH9K2D/WQxXx2EkFOYaCsgPXlcRm5Zwp10+rN
         ADEDVvdnki2cXsCfLzm7fY1JvkhVf2zBua0i+UvcRdHU+nxIIs+6o3ep2uvaFJmDf0bz
         Wu2g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of alexandru.elisei@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=alexandru.elisei@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756205172; x=1756809972; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rCTji3+9myZQIyi7Y5Aojo/T83cvqCoGABUan0Ksoog=;
        b=AKVDEMljNVIXMDAB7WXO2bnX0vhWN/gPyAG4DJPGiBsNj1/OCv6T7S3tgcUbysf04I
         k2EaSPjRkTayvsuAIQ0eJ6fl2jwTdeQHOdLOVPxyg3UtL+HkMUkDM8nOfAj8jdVvQ09B
         CsVS1PoK4cT1bhFSN99XA41Z3oTL1MfyRLhF+U9EDvouLCzYsorxPICQ3naDGy1ShbP7
         MugV1ORNetjbtS4gcO3PJzlz3Tjzep2yXJbmePVxjmvi7kppC3kS/P3scttH0aRBz6Ux
         4gl5Uo5lqkeZyy3nedBEBbxd0+b7StemtVsUJ44NhALBGlro3oxTRUAxomIelzCVCAHQ
         86HQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756205172; x=1756809972;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=rCTji3+9myZQIyi7Y5Aojo/T83cvqCoGABUan0Ksoog=;
        b=QBWznxdu6K95qsrdtlGunpujClHu4VJim34mCKa+//7J2oHyXNm2qdU1slKaIOXjo7
         fqYkCHSCkn2Ww7g5PE7Xqy7uNDPVbEfP8+xgwJPorbYcZ50F9a2y5UoNmwIYI9315uuX
         EIWaRWNNyjWUjosqZ0qY9NCbad5mWYf9F3o38NPOkrEN5xLRGGsBdcDy+dX888DxvZOS
         cJkhCgiviFLh2n8Q8awsKdLG1cuyi2Tq3ddXMCVvhrw2z7j0wApvuqQe4rFtBebnihKD
         dobmq6OGgNA3l0rsZysWOK64UbpLkX6kTUOP7EGXib2/75qidah/dkx3J6DZgjFOAHPS
         nBRg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX8IkmkNCpvGBDJsKZjcVf6SWhGrspTINgzo9UzxofwkLGLzUdDeybxOxn+kj4afFqinVJeDQ==@lfdr.de
X-Gm-Message-State: AOJu0YyMImMMwhUDR0lf4VVCTKq1p3wXwcQhi1VoO26MiG6kvW7QACim
	7qVnlX4zOL25/A872B2vBnQcI3N37p26p8OCHrBAt65uHb5//Sj51MsP
X-Google-Smtp-Source: AGHT+IHyX3EQU6bg2uNGHoKzRzNbkIxnS6W0bw0OeUizW/isJ/RATJA8uxIKgK1Ys4GGrUX+h3IWzA==
X-Received: by 2002:a17:90b:2f47:b0:321:87fa:e1ec with SMTP id 98e67ed59e1d1-32515ef197cmr18840795a91.34.1756205171880;
        Tue, 26 Aug 2025 03:46:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfYq3AZtsZH7W6K/+nMEmbOvTydmXoN36RaRhD+2dSdlg==
Received: by 2002:a17:90b:3504:b0:312:f2f1:3aaf with SMTP id
 98e67ed59e1d1-3254e751814ls3696031a91.0.-pod-prod-06-us; Tue, 26 Aug 2025
 03:46:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXsPqQWusEkPE0SDSkeRxBjMw2yl0aX/WSQ6axEgOyR+R2YVhYQFQz+T9FUsUBaearQlVlhC2slGgw=@googlegroups.com
X-Received: by 2002:a17:90b:1802:b0:325:8e03:c146 with SMTP id 98e67ed59e1d1-3258e03c374mr9973886a91.3.1756205170197;
        Tue, 26 Aug 2025 03:46:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756205170; cv=none;
        d=google.com; s=arc-20240605;
        b=LejL7If8OLR6jQk7+/Szc0Xf7LqVJGVfYRrnycGfYXzhLnPl+7EMfSatJflROx7q/Z
         OR6kxnD061ldg/XI3xqZDfAz6J4mUs/PjOG266l33JhYn+7cgAZKKH530QrE46dHZo72
         8tqxyLFmAi/g1tj3T0oukFOF2J6ynvNvL7HiXglBqelfkLntURXUF1eo/GEtMSx0spZa
         haLEXm14OnPopEDh3qWh1uNqMXuXObhgeah2fYdNHPOMMXw+YiEmqVk977oUZOUvP+wy
         bAqNy4Mi8c97vbMYtgGIdWw3Vs0IXLuxfh/K0oRm0LCuGT/y6CeerC1DSmyjMCdmT3+9
         miwQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=9psFt/Yy9/q5Gaj5Xh49YriPzaysEXZb7xyINMu8P/Y=;
        fh=vX6gO3pliJpm/AGrWIy9cYz9F3J0yH3JYHwS9n457z8=;
        b=ksfoaY8dvz+ETGqaGBuAr2AScmnhu/JTcmj4WCvRmOcRg0EPNMcy4jna5Hcj6iTNZe
         pOZQ1MDLY6/wOV2kiwcbI191WUYHpeEOOpz6j3Or9CI4GudiW9JM/oYOWjdCaZ/XfXp+
         XWriCMmddniDD+MFaMnHkHm50j1TkITDZBHWDdhovQPbp6RajM0NT06YoIlAYipJlLEN
         SXvXjogeh3Xl1YBZdmYwlEUTt3vMMFgzUGdRc17ouONqHwTcdT1kwg/X3nc9yJ0/DpdE
         NGVzq/iMHkLnML40HqPgoGsDUJnfEzGNrPrzkvefOfxv8CLRFEHb8dVTTEXOcbd0TDde
         RFIA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of alexandru.elisei@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=alexandru.elisei@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 98e67ed59e1d1-327415067d9si85053a91.0.2025.08.26.03.46.10
        for <kasan-dev@googlegroups.com>;
        Tue, 26 Aug 2025 03:46:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandru.elisei@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 0AD2A1A00;
	Tue, 26 Aug 2025 03:46:01 -0700 (PDT)
Received: from raptor (usa-sjc-mx-foss1.foss.arm.com [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 93FC13F694;
	Tue, 26 Aug 2025 03:46:01 -0700 (PDT)
Date: Tue, 26 Aug 2025 11:45:58 +0100
From: Alexandru Elisei <alexandru.elisei@arm.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
	io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>,
	Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>,
	John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
	kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
	linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
	linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
	linux-mmc@vger.kernel.org, linux-mm@kvack.org,
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Marco Elver <elver@google.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
	Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
	Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH RFC 21/35] mm/cma: refuse handing out non-contiguous page
 ranges
Message-ID: <aK2QZnzS1ErHK5tP@raptor>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-22-david@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250821200701.1329277-22-david@redhat.com>
X-Original-Sender: alexandru.elisei@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of alexandru.elisei@arm.com designates 217.140.110.172 as
 permitted sender) smtp.mailfrom=alexandru.elisei@arm.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=arm.com
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

Hi David,

On Thu, Aug 21, 2025 at 10:06:47PM +0200, David Hildenbrand wrote:
> Let's disallow handing out PFN ranges with non-contiguous pages, so we
> can remove the nth-page usage in __cma_alloc(), and so any callers don't
> have to worry about that either when wanting to blindly iterate pages.
> 
> This is really only a problem in configs with SPARSEMEM but without
> SPARSEMEM_VMEMMAP, and only when we would cross memory sections in some
> cases.
> 
> Will this cause harm? Probably not, because it's mostly 32bit that does
> not support SPARSEMEM_VMEMMAP. If this ever becomes a problem we could
> look into allocating the memmap for the memory sections spanned by a
> single CMA region in one go from memblock.
> 
> Signed-off-by: David Hildenbrand <david@redhat.com>
> ---
>  include/linux/mm.h |  6 ++++++
>  mm/cma.c           | 36 +++++++++++++++++++++++-------------
>  mm/util.c          | 33 +++++++++++++++++++++++++++++++++
>  3 files changed, 62 insertions(+), 13 deletions(-)
> 
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index ef360b72cb05c..f59ad1f9fc792 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -209,9 +209,15 @@ extern unsigned long sysctl_user_reserve_kbytes;
>  extern unsigned long sysctl_admin_reserve_kbytes;
>  
>  #if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
> +bool page_range_contiguous(const struct page *page, unsigned long nr_pages);
>  #define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
>  #else
>  #define nth_page(page,n) ((page) + (n))
> +static inline bool page_range_contiguous(const struct page *page,
> +		unsigned long nr_pages)
> +{
> +	return true;
> +}
>  #endif
>  
>  /* to align the pointer to the (next) page boundary */
> diff --git a/mm/cma.c b/mm/cma.c
> index 2ffa4befb99ab..1119fa2830008 100644
> --- a/mm/cma.c
> +++ b/mm/cma.c
> @@ -780,10 +780,8 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
>  				unsigned long count, unsigned int align,
>  				struct page **pagep, gfp_t gfp)
>  {
> -	unsigned long mask, offset;
> -	unsigned long pfn = -1;
> -	unsigned long start = 0;
>  	unsigned long bitmap_maxno, bitmap_no, bitmap_count;
> +	unsigned long start, pfn, mask, offset;
>  	int ret = -EBUSY;
>  	struct page *page = NULL;
>  
> @@ -795,7 +793,7 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
>  	if (bitmap_count > bitmap_maxno)
>  		goto out;
>  
> -	for (;;) {
> +	for (start = 0; ; start = bitmap_no + mask + 1) {
>  		spin_lock_irq(&cma->lock);
>  		/*
>  		 * If the request is larger than the available number
> @@ -812,6 +810,22 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
>  			spin_unlock_irq(&cma->lock);
>  			break;
>  		}
> +
> +		pfn = cmr->base_pfn + (bitmap_no << cma->order_per_bit);
> +		page = pfn_to_page(pfn);
> +
> +		/*
> +		 * Do not hand out page ranges that are not contiguous, so
> +		 * callers can just iterate the pages without having to worry
> +		 * about these corner cases.
> +		 */
> +		if (!page_range_contiguous(page, count)) {
> +			spin_unlock_irq(&cma->lock);
> +			pr_warn_ratelimited("%s: %s: skipping incompatible area [0x%lx-0x%lx]",
> +					    __func__, cma->name, pfn, pfn + count - 1);
> +			continue;
> +		}
> +
>  		bitmap_set(cmr->bitmap, bitmap_no, bitmap_count);
>  		cma->available_count -= count;
>  		/*
> @@ -821,29 +835,25 @@ static int cma_range_alloc(struct cma *cma, struct cma_memrange *cmr,
>  		 */
>  		spin_unlock_irq(&cma->lock);
>  
> -		pfn = cmr->base_pfn + (bitmap_no << cma->order_per_bit);
>  		mutex_lock(&cma->alloc_mutex);
>  		ret = alloc_contig_range(pfn, pfn + count, ACR_FLAGS_CMA, gfp);
>  		mutex_unlock(&cma->alloc_mutex);
> -		if (ret == 0) {
> -			page = pfn_to_page(pfn);
> +		if (!ret)
>  			break;
> -		}
>  
>  		cma_clear_bitmap(cma, cmr, pfn, count);
>  		if (ret != -EBUSY)
>  			break;
>  
>  		pr_debug("%s(): memory range at pfn 0x%lx %p is busy, retrying\n",
> -			 __func__, pfn, pfn_to_page(pfn));
> +			 __func__, pfn, page);
>  
>  		trace_cma_alloc_busy_retry(cma->name, pfn, pfn_to_page(pfn),

Nitpick: I think you already have the page here.

>  					   count, align);
> -		/* try again with a bit different memory target */
> -		start = bitmap_no + mask + 1;
>  	}
>  out:
> -	*pagep = page;
> +	if (!ret)
> +		*pagep = page;
>  	return ret;
>  }
>  
> @@ -882,7 +892,7 @@ static struct page *__cma_alloc(struct cma *cma, unsigned long count,
>  	 */
>  	if (page) {
>  		for (i = 0; i < count; i++)
> -			page_kasan_tag_reset(nth_page(page, i));
> +			page_kasan_tag_reset(page + i);

Had a look at it, not very familiar with CMA, but the changes look equivalent to
what was before. Not sure that's worth a Reviewed-by tag, but here it in case
you want to add it:

Reviewed-by: Alexandru Elisei <alexandru.elisei@arm.com>

Just so I can better understand the problem being fixed, I guess you can have
two consecutive pfns with non-consecutive associated struct page if you have two
adjacent memory sections spanning the same physical memory region, is that
correct?

Thanks,
Alex

>  	}
>  
>  	if (ret && !(gfp & __GFP_NOWARN)) {
> diff --git a/mm/util.c b/mm/util.c
> index d235b74f7aff7..0bf349b19b652 100644
> --- a/mm/util.c
> +++ b/mm/util.c
> @@ -1280,4 +1280,37 @@ unsigned int folio_pte_batch(struct folio *folio, pte_t *ptep, pte_t pte,
>  {
>  	return folio_pte_batch_flags(folio, NULL, ptep, &pte, max_nr, 0);
>  }
> +
> +#if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
> +/**
> + * page_range_contiguous - test whether the page range is contiguous
> + * @page: the start of the page range.
> + * @nr_pages: the number of pages in the range.
> + *
> + * Test whether the page range is contiguous, such that they can be iterated
> + * naively, corresponding to iterating a contiguous PFN range.
> + *
> + * This function should primarily only be used for debug checks, or when
> + * working with page ranges that are not naturally contiguous (e.g., pages
> + * within a folio are).
> + *
> + * Returns true if contiguous, otherwise false.
> + */
> +bool page_range_contiguous(const struct page *page, unsigned long nr_pages)
> +{
> +	const unsigned long start_pfn = page_to_pfn(page);
> +	const unsigned long end_pfn = start_pfn + nr_pages;
> +	unsigned long pfn;
> +
> +	/*
> +	 * The memmap is allocated per memory section. We need to check
> +	 * each involved memory section once.
> +	 */
> +	for (pfn = ALIGN(start_pfn, PAGES_PER_SECTION);
> +	     pfn < end_pfn; pfn += PAGES_PER_SECTION)
> +		if (unlikely(page + (pfn - start_pfn) != pfn_to_page(pfn)))
> +			return false;
> +	return true;
> +}
> +#endif
>  #endif /* CONFIG_MMU */
> -- 
> 2.50.1
> 
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aK2QZnzS1ErHK5tP%40raptor.
