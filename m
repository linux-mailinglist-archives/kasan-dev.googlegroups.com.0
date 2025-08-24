Return-Path: <kasan-dev+bncBDZMFEH3WYFBBJNFVTCQMGQESL7ZXYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb40.google.com (mail-yb1-xb40.google.com [IPv6:2607:f8b0:4864:20::b40])
	by mail.lfdr.de (Postfix) with ESMTPS id D5309B33019
	for <lists+kasan-dev@lfdr.de>; Sun, 24 Aug 2025 15:24:54 +0200 (CEST)
Received: by mail-yb1-xb40.google.com with SMTP id 3f1490d57ef6-e931cdd05a8sf4108367276.3
        for <lists+kasan-dev@lfdr.de>; Sun, 24 Aug 2025 06:24:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756041893; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZzgPzqID7ewl76g5OCo7Xjh5U0niEex2nSDCX2XJRuGcRRZzhENGZyFE3fBnu3p2BK
         ahTEoOpay10IgRa+pReBGgQ7HsUgA/+uPAHjjUwhEvqqVoxxP6fnvfmbmh6KO01nGOCC
         jyO1RDOs8CJvlLeyvNssMZDlOkl+ii7wyk4xCWQbqM6dsByLA/qL9G5pQNNoVgk10RVe
         AIbdMY3HhNfCPT8IFv53fUtcctlBqu36OnzIoWLlrdEIuAL4HSninV0BMGCMs7gpi6a3
         /VQds57u1RrFiPqXLPopRMBXxTzC/cdgknGxx67WzoxCUnl+lS5IEdUMbM9pClKt6IKV
         d5fA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=NjEs7OYwY7N0jta1iGGt7PC61jOzERiQO6xgVD5+Pig=;
        fh=NWzayXwbKVObSIl7aSqa1MdqAwqtintOu6P8n+3tGbQ=;
        b=Tiqes0Qes0Y7hlZGdSq5wNy0rJhzAB051iDkKwbz3aH6e7FwFU1ys43QfhgZxUehGi
         4dh4A7PBQI29CrTXTdZSqMeUojcwv6Tr2FteuNjKU2k/kmwnFftNNxuyQ7dm+gw3FWs2
         K1/ZHqZyifUCJeOr9jMHZYAHXhPMUUQEjGitFHunX9W4wMrbzrk2DNrc0jBg4X9ZAfpT
         306tdwtcFcWxhXFQnSCUURp3p6l26se0M1WVu1/htQ/Unobu5LQXXwas+sgtZsZSwCpJ
         PHie/IdlYH+TxX3GKhc9Fg1LRGHoKznYW10Jl/Xu24Q1uBgUDNf4u6FQpyhD3RIa32lv
         UROA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SquWihWK;
       spf=pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756041893; x=1756646693; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=NjEs7OYwY7N0jta1iGGt7PC61jOzERiQO6xgVD5+Pig=;
        b=wSm7xP1xC8WHoc0Fnp3LtlhfNbOuk+DpNQv6Q6MKxcm/v5JYwrEc8mv1WZjedZpByi
         qmOLp2rzkEMLhlwP7DWf/5ywXg+1EmilK36dm+Qo5bm6Vbpc9z2KN8x++JvfBWUE/PNR
         X2zQX9uiKl3TQNV4tewEMz4qCke8zI/Ens1cH0KZbxQNXXoZyBPy9Fa4Ts9u60JUkU69
         jRuy4WPtIU8HTxoCj+nCHzlC/nPqLSWvLGMFfpogFH1d9I707WD84Kgb5xhWHrB/tkn7
         cGVwjPG6KBIPUUhEi7JG55Cvwm9eDWEKmy+f5ttdMc9jEbcL7x538yR/oJIQP/XTbTki
         MVOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756041893; x=1756646693;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=NjEs7OYwY7N0jta1iGGt7PC61jOzERiQO6xgVD5+Pig=;
        b=rEfBqpq2phbMI8cCmb9w4u1yU9kjwhH6hqEIUCNmDwTiRmdPkCtER0qNrP1nOdogJk
         5SPSaGBi2zpUopdfM0l5YNjpVs56tfb9DO+AlSaasuYstnekxob+6MvOrvK9ydOmCJPf
         UU5FvFOjTtLyfdv9A396yj6kYpggJD0t51Yyj2q6i33JRWpbsDh9z3fSYpYRNQZt9egS
         3v0UiafVhapVI4NvvVAoV2vFr2e+YSoLfm+A2FwqvTmPd+e0GmuY8WAV6RRsfU9gY2nP
         9jHReEXCP6sOZ2Q9QuKYSxZH0FSxAIrLCn79lJGgKhwNXCm2iBcNVyjouV7sOSIhCbKO
         GmKw==
X-Forwarded-Encrypted: i=2; AJvYcCW2X+O5iuC1W6LhPZ+2ZiIx3HMLA1/E8+z6ycH0ykzeWhttplJDzF0n07wZR8Y8DBv6dNYA3g==@lfdr.de
X-Gm-Message-State: AOJu0YzRGUl9qQQVVADGN/IND7w8UUbJKWgT8DtYReQXcvUx/TJqVhll
	cLrnOsils/URBJhlBTteSmZUabLD1PcH4FP2Nfn+YDA/93BlBZCrnB2C
X-Google-Smtp-Source: AGHT+IFP3WWAy93HSg07NK6WbU5eqlqxz6JnBDXQMhd63yba2s5755+3kCr6h8yrAkwiwaq5H3gtgw==
X-Received: by 2002:a05:6902:6285:b0:e95:2d93:7d83 with SMTP id 3f1490d57ef6-e952d937e31mr5155393276.21.1756041893341;
        Sun, 24 Aug 2025 06:24:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZem/KuPuO2FYBvU3RnOMZG9vIWBSJztwgIs6jv4rAOACA==
Received: by 2002:a25:d8d3:0:b0:e95:3cbb:bf23 with SMTP id 3f1490d57ef6-e953cbbc423ls344641276.2.-pod-prod-05-us;
 Sun, 24 Aug 2025 06:24:52 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXkIinEXrcZQPkWjaRNszY5IK6GZ8Ow0BT6EuqICJbRmMB+3TDVFuiP+fVLDoKutkmh4DnCrkFYYGY=@googlegroups.com
X-Received: by 2002:a05:690c:b06:b0:702:52af:7168 with SMTP id 00721157ae682-71fdc2be3eemr93251767b3.2.1756041892342;
        Sun, 24 Aug 2025 06:24:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756041892; cv=none;
        d=google.com; s=arc-20240605;
        b=fh8vrLfRi6Jqs/TsdDcq1nQSje4blZv8i7dTlsKvEhQ0nC889agdyymfWt6g+ATcF0
         BVKLvycRudyEKOz6VXc1YOhbsSQ3pUfq3JNcwJhbKUIkIQLaPS2NbpZlExr3J8RMzXGZ
         YFqfbNNk3UVG0smHFT9/QeCh/YwQFEB2Zr69YnRijKb05XoZ812WY7Kijc5y3yjmBE18
         imm3MCEpcR4hEfESy0Xop5yhbTmRPFYhBntUxNkv5r0lFpe/63W3xsACwO+5yNoviTiJ
         qhlnFydncFSyvAk84UlJSd3qcW7ZMoPnZuiy05khUNhlQOOKwNxkePMQB/ee41acin70
         zreQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=sTgVSQ/agc49mf+WMVj/m/VVuvPKZX5i68p4dayRd8w=;
        fh=9i7Xo3ec5v6Czbc/Gl1AZEKMmN1XodXJiUIITipUCZU=;
        b=TdePE5XE/zuWgloa2RqAlSFpdvQeTxx5ATO0gBSHl5pV96DF8Vsz6ZKEJx3eB3uByr
         7Wk3pvpm8501GugcGlmZooOc4UXmX9tSsilXWyr7iwRaBpIh7QSUjpOaIXx3L9+UWyxv
         m04ZCLhwsoQz0Q/ehQ+kBQcwjpPLAoUzX33ZGuM96M8ryPu2761iKYllzIzYn+OQKkq8
         Iu8FjJpn3RsLY8JatiIh6IIhhlQXNG3NRtbVdK//GO+k2OE7q0QZLRSHBDL+fyh3vUEQ
         UUVuf7VwjyFy/bgc7xzWTq2IyjKd1dv3KnzBlJwJoPI8SZ+AJOEcXKQ+xSfy5ml1Q3hh
         GKgA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=SquWihWK;
       spf=pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-71ff1713f9asi1732027b3.1.2025.08.24.06.24.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 24 Aug 2025 06:24:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 7D3EC43442;
	Sun, 24 Aug 2025 13:24:51 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B4638C4CEEB;
	Sun, 24 Aug 2025 13:24:26 +0000 (UTC)
Date: Sun, 24 Aug 2025 16:24:23 +0300
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
Subject: Re: [PATCH RFC 12/35] mm: limit folio/compound page sizes in
 problematic kernel configs
Message-ID: <aKsSh0OEjf4GLmIG@kernel.org>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-13-david@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250821200701.1329277-13-david@redhat.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=SquWihWK;       spf=pass
 (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
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

On Thu, Aug 21, 2025 at 10:06:38PM +0200, David Hildenbrand wrote:
> Let's limit the maximum folio size in problematic kernel config where
> the memmap is allocated per memory section (SPARSEMEM without
> SPARSEMEM_VMEMMAP) to a single memory section.
> 
> Currently, only a single architectures supports ARCH_HAS_GIGANTIC_PAGE
> but not SPARSEMEM_VMEMMAP: sh.
> 
> Fortunately, the biggest hugetlb size sh supports is 64 MiB
> (HUGETLB_PAGE_SIZE_64MB) and the section size is at least 64 MiB
> (SECTION_SIZE_BITS == 26), so their use case is not degraded.
> 
> As folios and memory sections are naturally aligned to their order-2 size
> in memory, consequently a single folio can no longer span multiple memory
> sections on these problematic kernel configs.
> 
> nth_page() is no longer required when operating within a single compound
> page / folio.
> 
> Signed-off-by: David Hildenbrand <david@redhat.com>

Acked-by: Mike Rapoport (Microsoft) <rppt@kernel.org>

> ---
>  include/linux/mm.h | 22 ++++++++++++++++++----
>  1 file changed, 18 insertions(+), 4 deletions(-)
> 
> diff --git a/include/linux/mm.h b/include/linux/mm.h
> index 77737cbf2216a..48a985e17ef4e 100644
> --- a/include/linux/mm.h
> +++ b/include/linux/mm.h
> @@ -2053,11 +2053,25 @@ static inline long folio_nr_pages(const struct folio *folio)
>  	return folio_large_nr_pages(folio);
>  }
>  
> -/* Only hugetlbfs can allocate folios larger than MAX_ORDER */
> -#ifdef CONFIG_ARCH_HAS_GIGANTIC_PAGE
> -#define MAX_FOLIO_ORDER		PUD_ORDER
> -#else
> +#if !defined(CONFIG_ARCH_HAS_GIGANTIC_PAGE)
> +/*
> + * We don't expect any folios that exceed buddy sizes (and consequently
> + * memory sections).
> + */
>  #define MAX_FOLIO_ORDER		MAX_PAGE_ORDER
> +#elif defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
> +/*
> + * Only pages within a single memory section are guaranteed to be
> + * contiguous. By limiting folios to a single memory section, all folio
> + * pages are guaranteed to be contiguous.
> + */
> +#define MAX_FOLIO_ORDER		PFN_SECTION_SHIFT
> +#else
> +/*
> + * There is no real limit on the folio size. We limit them to the maximum we
> + * currently expect.
> + */
> +#define MAX_FOLIO_ORDER		PUD_ORDER
>  #endif
>  
>  #define MAX_FOLIO_NR_PAGES	(1UL << MAX_FOLIO_ORDER)
> -- 
> 2.50.1
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aKsSh0OEjf4GLmIG%40kernel.org.
