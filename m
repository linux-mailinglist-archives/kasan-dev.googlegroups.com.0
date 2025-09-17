Return-Path: <kasan-dev+bncBDZMFEH3WYFBBZMKVPDAMGQEWVWPO7Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53a.google.com (mail-pg1-x53a.google.com [IPv6:2607:f8b0:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id EE350B7FF87
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 16:27:51 +0200 (CEST)
Received: by mail-pg1-x53a.google.com with SMTP id 41be03b00d2f7-b4c72281674sf4769404a12.3
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Sep 2025 07:27:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758119270; cv=pass;
        d=google.com; s=arc-20240605;
        b=XL0uCmybiv2cXqNpbVQeKeNhL+5iSc2F9jmWVwO/FW5hr/qFCgTx8As3dx+yL9jauf
         +tMoBpz9XK8Z1BCA7v4iv/RwCY9/iy8AZUlKMwsk19G+KklPvbuifsbNra9grrXwfOsg
         o1cWsbsgk3PVnC6h/oToYOiD4EqLzHIvQRQaEfD+dYK5qv+muAq9N8XCqQB0wG44Tz6X
         HojuKMaRCD/L3j1nvOwHhe0Ou7foYtYm74ym/Gmmc12f1zAsPh1dxqoS5BfKMbofcHMj
         tTBOFwSNSgTNAgaHRtDHYdc45pko9oD+VKEUOGx5c2QBurR9yLoSq4kCIIssbNmC1/2b
         TGgQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=8SvMP5M6XgF8T7a/x1Ln3US/lB8SZ1TK6DY/Z8xnN0A=;
        fh=w9Zh/qRufOXSrpfytflW7G/OJlddxMXxE8N9Nv2ZTXk=;
        b=iQfYYHrprhDgX1KTkKwbnpGhClmAt8n6Wp1DMBmXMwNRZOer6Gzr+yWbth0eLjMo43
         eB4GJu0P1eSlpVlVBQey5wgW+KUpMiAu0yRiQOV6H29vkH5TBqya7dv1PHXQEebmd+Eo
         gxGCLN3WflVTIZPxOuDRDf87JOld2tvcnZETnjDWo1OiWOYGGGfGMjJu5mBY+Zt1iV6V
         RfV6sSF4SD4Jla7/bstKnsSjWGutbiUJFSO1z+8S/igKtw3KXMfUGDU/8v5Cfh+/jS43
         ecYHIAzfskEjN7PSkFi84LX9++QvsBe0B/zswNWNM5C3BP2VW225rKp27gjaMKT1TpW8
         y8Qg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VRhST95e;
       spf=pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758119270; x=1758724070; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=8SvMP5M6XgF8T7a/x1Ln3US/lB8SZ1TK6DY/Z8xnN0A=;
        b=jVpHiAzt7mhPppWBnq+0V4sXJfs+pdTk0jOsQSBnfrdQ04IVUwvBApbsRLENojRyY3
         TiJdBzdOotf3Dz9XlpIR2DzuyzFVJsIwL7zG2u7DwFjtkJy13B3GzXUkmjfiAIxZdpza
         EhgTe9o7Pxkp2/KqFm4WfTBJW2JdhN8RgiNrea49wWYr89ZaK/LoRgWKPmsApZ4diJBP
         vkxBINyBHLUnd0CFfoNACsKoxgNQzI0gdYceICgDEOy+NVlXa9dsn+fa4CLqqm6Scg1X
         X4ZUcYLwxtx7AobnMoRyz62kcGjYWS5HRpKSbaoI27/zCKyjFXuuILad9DAQ1qea101y
         OjCg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758119270; x=1758724070;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8SvMP5M6XgF8T7a/x1Ln3US/lB8SZ1TK6DY/Z8xnN0A=;
        b=i9tYsZchcKApQ6wD0lyX5XZ78Cf9lLokILkkT947xsz24/h57lj4XQtBD3PMNlNAO+
         Q+EUwvFpgESgLIeeYvZmFP4RFdNNjAzET5EKvA7+1t6D4/vfWdhuKmUbX4k4bhUjgSpT
         I8qbDAqFa25JoA88f/h0/iUmJlxpeGYmKrubOwgU/7YjB4x994EjRlJz5j1JfLdFvCJA
         WZQIGv/O4o6bArAoXDoNLnAxwORR9fdwIJ8uHfMAsj66SakOFJgdM9asGYBGSrh/kuXB
         JKLJPin/Fn0ALhp8JHBoOZCQsgys0z5x5n7h2ng9/bpeVl8ULJ2SgG29I5WpK5UrSCQG
         Vnfw==
X-Forwarded-Encrypted: i=2; AJvYcCXrbhpWSVTRMzMCMMwxV6JiUEYnwZyDzB9RNN/owcfNG/Z4w8Bees8J1s924YWEM7m1d92wJg==@lfdr.de
X-Gm-Message-State: AOJu0YxDtswga8XHllvlbpEzGKqTBhuLq05Vbix08HfOp8sFxYihGU7p
	LUfU9hwlE3FonNAQT0aN1taYGli1bmhNnmgsoy0t+a6lN/DOQVaFQBdW
X-Google-Smtp-Source: AGHT+IG/KJFDKD0+JYOyvYW44/8aQojL6FBlzgEOJ9GykONECD7ULK9dE9ejRqhZ6/k2vwpO/npTlg==
X-Received: by 2002:a17:902:e80a:b0:25c:343a:12eb with SMTP id d9443c01a7336-268118a5f34mr33803345ad.4.1758119270033;
        Wed, 17 Sep 2025 07:27:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5WmSRmXinV/4NdlXeKoKU21z36ijDsISx/nquNvewhUA==
Received: by 2002:a17:90a:142:b0:32b:d16c:6b5e with SMTP id
 98e67ed59e1d1-32dd4ed009cls4954133a91.2.-pod-prod-02-us; Wed, 17 Sep 2025
 07:27:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUdhsYWYIpeotsOIUSkOh0sIl1wwGeYr6/hT5XeLRvbGs+IrLLQplrhsfsU/f79IrAKZ8BDjPQJ7DA=@googlegroups.com
X-Received: by 2002:a17:90b:4a90:b0:32d:d714:b3eb with SMTP id 98e67ed59e1d1-32ee3e77decmr2410125a91.4.1758119268468;
        Wed, 17 Sep 2025 07:27:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758119268; cv=none;
        d=google.com; s=arc-20240605;
        b=XgN2AsdsI4enIiiesfrv/yKesMtlwEzFl8XsSw+Wew85Ho1nVtlmqVD8KkOov6rwSV
         d97C+9mtFdM/z4VXiEdxQODZj//xBg9xpGF94Zt6/33Hcu9p7XLMO9ioiG6+P6ev/oC8
         75zJ7jXT1cFAFEBNC/MUkemu4lOhon6dc5jZsQq1muXXvXMZ3oVslik41HP7l3XXC5wb
         215tp6UquWEIq/FBIIn/BZyPcbH15IcFdz9wIhAUUV4+aqnUfXXW2G+2B+XmCoWTRkJn
         AX2DJqNYsKs6kx21SI5vIPEcutONGF+xiQqGlYCZLLK3LB8Ya15IXm+wkLe1EBcC8p2Z
         SzAg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=Q2F1whqw3f8oSfwZw5QkxhptwD3fG5ea5Q8QE4Ni/oE=;
        fh=e+VlNkVPC9pdCP+vNawoNWChtfjiSnoy2FJ1/uLw3ZM=;
        b=aEn1ZdCwoIbBq292Tas0PEvSWP1kXe+2yGFIH9LFIAaNxqVvliiX3/mtMhrXwK7/dn
         rN3Kt2aB2j/lTZ8lPKD9mH74M+P6DHxlmCoAwIEN3al/rVRHjOj7mzzVnYALWCzF02QB
         msekzkpmmEnkVHI5ehH9EGtO8OOAniQmg88FSj2evRZkjV72rnUDP7mxFC3yjbyQ6Cim
         7HNVOMgMW/rMWQzi0MkTltvarjcTrtXU45xPHgAir/pce5fMGWwIxIaiZ3ExY+gETihO
         U7ttBw+186b0qvxxdniDX3pgZxYaD6/lshhPQBMBvI7R98kqSIOvLHSCZKFRj2SyV2Sg
         +IVg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=VRhST95e;
       spf=pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3305894bee3si1775a91.0.2025.09.17.07.27.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 17 Sep 2025 07:27:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 84C69601ED;
	Wed, 17 Sep 2025 14:27:47 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id BEF49C4CEE7;
	Wed, 17 Sep 2025 14:27:43 +0000 (UTC)
Date: Wed, 17 Sep 2025 17:27:40 +0300
From: "'Mike Rapoport' via kasan-dev" <kasan-dev@googlegroups.com>
To: Alexander Potapenko <glider@google.com>
Cc: akpm@linux-foundation.org, david@redhat.com, vbabka@suse.cz,
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, elver@google.com,
	dvyukov@google.com, kasan-dev@googlegroups.com,
	Aleksandr Nogikh <nogikh@google.com>
Subject: Re: [PATCH v1] mm/memblock: Correct totalram_pages accounting with
 KMSAN
Message-ID: <aMrFXOTrlcgPhqjo@kernel.org>
References: <20250917123250.3597556-1-glider@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250917123250.3597556-1-glider@google.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=VRhST95e;       spf=pass
 (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted
 sender) smtp.mailfrom=rppt@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
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

On Wed, Sep 17, 2025 at 02:32:50PM +0200, Alexander Potapenko wrote:
> When KMSAN is enabled, `kmsan_memblock_free_pages()` can hold back pages
> for metadata instead of returning them to the early allocator. The callers,
> however, would unconditionally increment `totalram_pages`, assuming the
> pages were always freed. This resulted in an incorrect calculation of the
> total available RAM, causing the kernel to believe it had more memory than
> it actually did.
> 
> This patch refactors `memblock_free_pages()` to return the number of pages
> it successfully frees. If KMSAN stashes the pages, the function now
> returns 0; otherwise, it returns the number of pages in the block.
> 
> The callers in `memblock.c` have been updated to use this return value,
> ensuring that `totalram_pages` is incremented only by the number of pages
> actually returned to the allocator. This corrects the total RAM accounting
> when KMSAN is active.
> 
> Cc: Aleksandr Nogikh <nogikh@google.com>
> Fixes: 3c2065098260 ("init: kmsan: call KMSAN initialization routines")
> Signed-off-by: Alexander Potapenko <glider@google.com>
> ---
>  mm/internal.h |  4 ++--
>  mm/memblock.c | 18 +++++++++---------
>  mm/mm_init.c  |  9 +++++----
>  3 files changed, 16 insertions(+), 15 deletions(-)
> 
> diff --git a/mm/internal.h b/mm/internal.h
> index 45b725c3dc030..ae1ee6e02eff9 100644
> --- a/mm/internal.h
> +++ b/mm/internal.h
> @@ -742,8 +742,8 @@ static inline void clear_zone_contiguous(struct zone *zone)
>  extern int __isolate_free_page(struct page *page, unsigned int order);
>  extern void __putback_isolated_page(struct page *page, unsigned int order,
>  				    int mt);
> -extern void memblock_free_pages(struct page *page, unsigned long pfn,
> -					unsigned int order);
> +extern unsigned long memblock_free_pages(struct page *page, unsigned long pfn,
> +					 unsigned int order);

No need for extern, the inconsistency is fine here.

>  extern void __free_pages_core(struct page *page, unsigned int order,
>  		enum meminit_context context);
>  
> diff --git a/mm/memblock.c b/mm/memblock.c
> index 117d963e677c9..de7ff644d8f4f 100644
> --- a/mm/memblock.c
> +++ b/mm/memblock.c
> @@ -1834,10 +1834,9 @@ void __init memblock_free_late(phys_addr_t base, phys_addr_t size)
>  	cursor = PFN_UP(base);
>  	end = PFN_DOWN(base + size);
>  
> -	for (; cursor < end; cursor++) {
> -		memblock_free_pages(pfn_to_page(cursor), cursor, 0);
> -		totalram_pages_inc();
> -	}
> +	for (; cursor < end; cursor++)
> +		totalram_pages_add(
> +			memblock_free_pages(pfn_to_page(cursor), cursor, 0));
>  }
>  
>  /*
> @@ -2259,9 +2258,11 @@ static void __init free_unused_memmap(void)
>  #endif
>  }
>  
> -static void __init __free_pages_memory(unsigned long start, unsigned long end)
> +static unsigned long __init __free_pages_memory(unsigned long start,
> +						unsigned long end)
>  {
>  	int order;
> +	unsigned long freed = 0;
>  
>  	while (start < end) {
>  		/*
> @@ -2279,10 +2280,11 @@ static void __init __free_pages_memory(unsigned long start, unsigned long end)
>  		while (start + (1UL << order) > end)
>  			order--;
>  
> -		memblock_free_pages(pfn_to_page(start), start, order);
> +		freed += memblock_free_pages(pfn_to_page(start), start, order);
>  
>  		start += (1UL << order);
>  	}
> +	return freed;
>  }
>  
>  static unsigned long __init __free_memory_core(phys_addr_t start,
> @@ -2297,9 +2299,7 @@ static unsigned long __init __free_memory_core(phys_addr_t start,
>  	if (start_pfn >= end_pfn)
>  		return 0;
>  
> -	__free_pages_memory(start_pfn, end_pfn);
> -
> -	return end_pfn - start_pfn;
> +	return __free_pages_memory(start_pfn, end_pfn);
>  }
>  
>  static void __init memmap_init_reserved_pages(void)
> diff --git a/mm/mm_init.c b/mm/mm_init.c
> index 5c21b3af216b2..9883612768511 100644
> --- a/mm/mm_init.c
> +++ b/mm/mm_init.c
> @@ -2548,24 +2548,25 @@ void *__init alloc_large_system_hash(const char *tablename,
>  	return table;
>  }
>  
> -void __init memblock_free_pages(struct page *page, unsigned long pfn,
> -							unsigned int order)
> +unsigned long __init memblock_free_pages(struct page *page, unsigned long pfn,
> +					 unsigned int order)

Please either align this with 'struct' or drop spaces and keep only tabs.

>  {
>  	if (IS_ENABLED(CONFIG_DEFERRED_STRUCT_PAGE_INIT)) {
>  		int nid = early_pfn_to_nid(pfn);
>  
>  		if (!early_page_initialised(pfn, nid))
> -			return;
> +			return 0;
>  	}
>  
>  	if (!kmsan_memblock_free_pages(page, order)) {
>  		/* KMSAN will take care of these pages. */
> -		return;
> +		return 0;
>  	}
>  
>  	/* pages were reserved and not allocated */
>  	clear_page_tag_ref(page);
>  	__free_pages_core(page, order, MEMINIT_EARLY);
> +	return 1UL << order;
>  }
>  
>  DEFINE_STATIC_KEY_MAYBE(CONFIG_INIT_ON_ALLOC_DEFAULT_ON, init_on_alloc);

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aMrFXOTrlcgPhqjo%40kernel.org.
