Return-Path: <kasan-dev+bncBDZMFEH3WYFBB3UYULCQMGQEN236BCY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23c.google.com (mail-oi1-x23c.google.com [IPv6:2607:f8b0:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 33DAFB31E77
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 17:27:44 +0200 (CEST)
Received: by mail-oi1-x23c.google.com with SMTP id 5614622812f47-435de72bc57sf3189826b6e.1
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 08:27:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755876463; cv=pass;
        d=google.com; s=arc-20240605;
        b=J0LJWq9RFPyDcCmj++kVweixjsLd2Vv7C0Htm5t4vf9gYuS9aGI2IGiDKUswf97xZ6
         xMZCD+sCNfb8MWogKqVZ37reLTMvSXR7QsZYvgPDWGe8yNSIRZr2ZHg5LSKbUYmMGLqI
         /usMcrHIznXLQlLO0s7z/oRn2iTqxuF2OyVYwH0kZ6TLjSHzZ5jn45AFHIr5ZnB8c3br
         /hSfFsJmvGfA3VP9cbcQV4vQ3ZWdlUeC6f8ng76pG2dvE4cSuSJDUZxJqSDaPKEtfBIZ
         p+G1EWQXIpfsGXnhECvT3tFYR7LwBkPWR03bF9Rl7UXt63GEmRfKd5uP7OtNBzA/hHqM
         EY1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=079mR+zybGRR9YKAmxZRCrlhkRz1OP+qJ4C/UvW+usw=;
        fh=roJh7ZeghAq7PvLNzJO71CR85HnTPxh0m793oZAnQgc=;
        b=CwnTgO5DdBip9UJ4bQVCJAvIdI+kc6wa5EercFgIj0xMvT3XVZ5he+JxAK+gXc0ilC
         xRsSCjE9x3ZhqssF+yJVZPXAdJ+z1ovXs2wcJ1j7w8a8ye4KEre8+IYSlqOKnEnpjnaw
         qCuRjbmMPdmZ82t0i/88q9/tQWBLMeR40nx6ofTCYNqEC732gNN4QpoT5fya5SFiSERu
         TK1bXtPMYFb3IXAVXGlfxZ/v8bNuy3qEq5f0Pi5epRV/NYJLHDBw/l+zDSXQ+6S3tD4R
         6c3vdN3TJAZC+wzIn3uVvlrrn3l7px8dZfmpaTYoM7WPksruiwwIR+seZPSzuA/P4iup
         6cPQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="CMSA8/iN";
       spf=pass (google.com: domain of rppt@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755876463; x=1756481263; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=079mR+zybGRR9YKAmxZRCrlhkRz1OP+qJ4C/UvW+usw=;
        b=Cb9SPSdfPAHnQu8NBPpNQMGaqk1iVU+VrxZvZb8vGukFZO8An/fF+CWITtqoRtaeS/
         8bWSAG0cd1Cp78FeXySmzMDuU+rlz8c4lFhkgnNL9aAJzM7pnPDZnSaa4P2bXif4Caoz
         J6zngLyX5ignYDFvhwyhvTRSKxTlXoa4ekxN9ybEOOxBZt+h/vrEh19wEqmtrZw0pu5H
         LwdUtu42bPrFCkFIzpMzBuuLNdHAKAChDGQs8P0UtAp4DQdFL1iGcgl/ZPiIhF+EI/tN
         eJxETjH03tXNK5g/rStt6HV8ur3E1fyWVXHSlfQRdJv9E5EdskA4NQq/tIPJQ+hMzFly
         boCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755876463; x=1756481263;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=079mR+zybGRR9YKAmxZRCrlhkRz1OP+qJ4C/UvW+usw=;
        b=aWjETFqGAP2/m5L3lNvNsWHLuvj0/X616mq3+n7lX0z1iIExMcRc4o+yP3JGg07R7q
         PRDR5fRDD+nrFHuJqZ6zfR52R2TlbWMwqz9Cf4WchWY3WaCzDjcqcVy2zesLLvA3n8xU
         VyKUYxggkRVxLTia4YVBE3IoztL4J1IH87DNGuwjT1Mc3LY7FcRluDxtZoeIoM8/rvK0
         M5erwFhNDer/BO+lIRPpt/Q8ACTp8JuGVOmaVnBqVmScFQ/eDoaKwdxxWhXwqCin3ItA
         7Rdt0Zi6ifUDW1k34IK8mMMXWcjJOKmg7YcZAbETEQWF8Gdnxn+gigaToXPEUQCiK1tu
         SIxg==
X-Forwarded-Encrypted: i=2; AJvYcCUX7DuqEB/F0+qPUgvcbDlNvDSxahLUh5VJ6vQTFD2NV8iFowzjYVc089wFmuYpQq5sz6ZNlQ==@lfdr.de
X-Gm-Message-State: AOJu0Yy1rhYnh12TkCApoIDKFLq/yCy2+dCdrS11LvdtoEV9mf2mpwUB
	pIXD1gMD9Po+7MLHXCbC4970d4hrPjwiS/7kFXYeyZi0griwX2le/+8l
X-Google-Smtp-Source: AGHT+IH8HradKH1DgPQ9blRYopdDV+wsW8cfd7XtAdm3DjwTNMsd8oBIx7vL0UzbYv1Bk0c8ZrrVoA==
X-Received: by 2002:a05:6808:4f4f:b0:433:fe80:5404 with SMTP id 5614622812f47-4378518e0cfmr1614041b6e.5.1755876462759;
        Fri, 22 Aug 2025 08:27:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdgb59loeTmmiZwOsMNmzD7s4jcm4vnbepx3WjpSVB2gQ==
Received: by 2002:a05:6871:d211:b0:30b:c665:1d65 with SMTP id
 586e51a60fabf-314c231d70els879122fac.2.-pod-prod-05-us; Fri, 22 Aug 2025
 08:27:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXWX4iqxErHUCLCPwel6M/u6Jfs0AYsZiwBkKf2DYYny2ttucUM20K3OjHans+ci4RWDfjVyq/55ak=@googlegroups.com
X-Received: by 2002:a05:6871:4185:b0:30b:75a2:a45e with SMTP id 586e51a60fabf-314dcdd8341mr1555897fac.33.1755876461847;
        Fri, 22 Aug 2025 08:27:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755876461; cv=none;
        d=google.com; s=arc-20240605;
        b=MouGgS4E5Zcbujd5T4aIZHltvrT34vKSGGs/kTs4f31BZKbWMDevufhQfc7q4CNwBn
         Q2urIh6cSn8anBtAoHuQJYjislya6/WUCZMCXiiZDW9C49ccqAJxzXQwVTETTEPkxZRg
         GHV0pGDWgDIl3dxuRr2EseAb2s/scW84/GLPUr0wZ2Zwt8XV3u4g9BCIGBl1jj+IPQSN
         4yu/j9/lXgHCemcIAGRQIzdWZvg018KnRKOCebsiU48gQvxuBsQRQAkfIMm4Sv6Z0UWm
         vLbsrVFw6VKTSdpRNYt4LM42auJ9L+1Jj0BmbXjpscUnDDRq3yah/byttqUjuOYZEjpA
         L/oA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=J1I8u9xZyArfke8NFAOrJRZCKODw+0YzgRZABhPnQa4=;
        fh=9i7Xo3ec5v6Czbc/Gl1AZEKMmN1XodXJiUIITipUCZU=;
        b=FjXiT54cze2nQd5VvPBiHbNa+bSWZwQH86fuKpnjhD0tC/YoJQ3kJdcQlgplcitBlb
         A1vn+VFO5D+Bm+4az072zumoxEF8QYulU/pFCcYSN06sTuK9pKD3AkunyT5/vLNwW8J4
         7g30s6zp9DpoWHh4dSNqDJu4wjPnJEVvkrdCHCCcX81gatMuXrhhSbvqbJFqRPGj70YQ
         VyvZdtv0ufIgAFDTDeTrgw9Q5RMa/wO3k1kCss7AHcfhVwyk6iQGnOg4TxxdnUHWvWd9
         t8j9pIMc/SmmAU65BMqN0aG/5C0swUSiroSW2vKJP25hJ0mowprUYO37lhPix5IJsN5b
         /oZw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="CMSA8/iN";
       spf=pass (google.com: domain of rppt@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-310ab8a935csi871874fac.1.2025.08.22.08.27.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 22 Aug 2025 08:27:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 2FD7B601E7;
	Fri, 22 Aug 2025 15:27:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 95AB4C4CEF4;
	Fri, 22 Aug 2025 15:27:26 +0000 (UTC)
Date: Fri, 22 Aug 2025 18:27:22 +0300
From: "'Mike Rapoport' via kasan-dev" <kasan-dev@googlegroups.com>
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
	Michal Hocko <mhocko@suse.com>, Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>,
	Peter Xu <peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Subject: Re: [PATCH RFC 09/35] mm/mm_init: make memmap_init_compound() look
 more like prep_compound_page()
Message-ID: <aKiMWoZMyXYTAPJj@kernel.org>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-10-david@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250821200701.1329277-10-david@redhat.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="CMSA8/iN";       spf=pass
 (google.com: domain of rppt@kernel.org designates 2600:3c04:e001:324:0:1991:8:25
 as permitted sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Mike Rapoport <rppt@kernel.org>
Reply-To: Mike Rapoport <rppt@kernel.org>
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

On Thu, Aug 21, 2025 at 10:06:35PM +0200, David Hildenbrand wrote:
> Grepping for "prep_compound_page" leaves on clueless how devdax gets its
> compound pages initialized.
> 
> Let's add a comment that might help finding this open-coded
> prep_compound_page() initialization more easily.
> 
> Further, let's be less smart about the ordering of initialization and just
> perform the prep_compound_head() call after all tail pages were
> initialized: just like prep_compound_page() does.
> 
> No need for a lengthy comment then: again, just like prep_compound_page().
> 
> Note that prep_compound_head() already does initialize stuff in page[2]
> through prep_compound_head() that successive tail page initialization
> will overwrite: _deferred_list, and on 32bit _entire_mapcount and
> _pincount. Very likely 32bit does not apply, and likely nobody ever ends
> up testing whether the _deferred_list is empty.
> 
> So it shouldn't be a fix at this point, but certainly something to clean
> up.
> 
> Signed-off-by: David Hildenbrand <david@redhat.com>
> ---
>  mm/mm_init.c | 13 +++++--------
>  1 file changed, 5 insertions(+), 8 deletions(-)
> 
> diff --git a/mm/mm_init.c b/mm/mm_init.c
> index 5c21b3af216b2..708466c5b2cc9 100644
> --- a/mm/mm_init.c
> +++ b/mm/mm_init.c
> @@ -1091,6 +1091,10 @@ static void __ref memmap_init_compound(struct page *head,
>  	unsigned long pfn, end_pfn = head_pfn + nr_pages;
>  	unsigned int order = pgmap->vmemmap_shift;
>  
> +	/*
> +	 * This is an open-coded prep_compound_page() whereby we avoid
> +	 * walking pages twice by initializing them in the same go.
> +	 */

While on it, can you also mention that prep_compound_page() is not used to
properly set page zone link?

With this

Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>

>  	__SetPageHead(head);
>  	for (pfn = head_pfn + 1; pfn < end_pfn; pfn++) {
>  		struct page *page = pfn_to_page(pfn);
> @@ -1098,15 +1102,8 @@ static void __ref memmap_init_compound(struct page *head,
>  		__init_zone_device_page(page, pfn, zone_idx, nid, pgmap);
>  		prep_compound_tail(head, pfn - head_pfn);
>  		set_page_count(page, 0);
> -
> -		/*
> -		 * The first tail page stores important compound page info.
> -		 * Call prep_compound_head() after the first tail page has
> -		 * been initialized, to not have the data overwritten.
> -		 */
> -		if (pfn == head_pfn + 1)
> -			prep_compound_head(head, order);
>  	}
> +	prep_compound_head(head, order);
>  }
>  
>  void __ref memmap_init_zone_device(struct zone *zone,
> -- 
> 2.50.1
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aKiMWoZMyXYTAPJj%40kernel.org.
