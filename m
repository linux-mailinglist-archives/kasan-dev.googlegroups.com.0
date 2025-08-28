Return-Path: <kasan-dev+bncBC7OBJGL2MHBBS5NYDCQMGQELSLM7BY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id D99A0B39750
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 10:43:57 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-327b016a1f3sf499292a91.1
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 01:43:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756370636; cv=pass;
        d=google.com; s=arc-20240605;
        b=KtfJ+/EQ6HFyo3gVQmlq5948VqJO8pSf6VxiZnjEMYg/966HuE1pxvr/k0z5g0lEES
         bBcYznCSFsRYnoPXde9cYfp45RhhzdaDf7kS36pa2x+wkEovCxpYPjzgOQ+t2YucGfIG
         6/zVFtXCt8SYz8aVt00JnF/Qw9mgRnoXdieno7re3dRsS5mdcxi6toUtB69e2feByqu0
         s9blQlWPlNHS2PBwqc3VeJM+aZgiueyA8eZCx8CLpJ8QDQbfxIg9+gCQ9ZoXGIfia2bu
         I8fzuupOy0MNdRHCsefhzff2rpH7W0seaSzcIECnZNRrRgf92twK58xetpWjC9ciV95i
         Mygw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=JAk96WX9y8B3rv+yt3+GsrbFb3UvytNb8ypxbdZzIQs=;
        fh=PxvdozPT0VJ80MZFBkd/m9inbOD0S87YHHcDyM0flvQ=;
        b=lZFZhAFjWYuaNpzf1HG7HThsnp7pv5Dvl2n1/ZnM3yWBHaudpiLI0wyKbPpqXIloy+
         JDWovxsVxrT/sfIuJ2/Wl9/5uyo7Ws9/8wrdvAzliA/sOA9WCDybwGvfRtmQuhqY6se5
         kNjqZu6E8TBNgV03yYOarCxFtgntObDfZbvJsyPiKwUnZ3MPaJGBdZF2+o8gWQ8wNIXX
         836VF2uqAriuDgPZDwz9XCWQQXLGu4F7I26pTVax/kGyKQQsAF3FcUwJFgUbuODyOW+P
         w7L1RMFKEpt+IYe0cdUWw53mYfu2dSLBz2v6cTvJIwyguDab9dkfpLRJDJggvWLcm7nl
         wp1w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1d+ohk5b;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756370636; x=1756975436; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JAk96WX9y8B3rv+yt3+GsrbFb3UvytNb8ypxbdZzIQs=;
        b=hErAlxrhTkcQUMsR8i5n7tcgcpwbjqsYUG6xOYTb3Snggnc5vziNdrIJikDAib2fUC
         i+T6dOFRVQ5uyk4ynQOp7bkFHCHJEPcTfQSsTs3PUQzHkuHDvc3pRdMrMxMj9Q8JJC6H
         sJKrng7wlRS9/dJGNs9UDu1yQfGfOwMi1DACAtKIPWMdy93BD+CsnRMV9hxeoqde6ZvG
         uxP16c14bWfTRI3FXj8ILICm3HQFSjohaLJwTsWgfgZhpNN68TuRAG0Q01VOfFVfjsPg
         nynUHc+zQzEwOlkKkLNC+FMN8WHS5DazZSJZyp7fRe0tskkAXDIM3EJcPzDCXItiIPOq
         t9Mg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756370636; x=1756975436;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=JAk96WX9y8B3rv+yt3+GsrbFb3UvytNb8ypxbdZzIQs=;
        b=WBbUoGIXmaxhRDcngfC8quXWfuuf4rVlxH3PhKBrXHL8hypCo3G8vUnPbTnNJryarO
         +SQrjuO3zOph2WjGwe+KoDQ4wXNhrTeq40cNI3UhiS30bvq35LN/DMLX67jiq6bf1YWc
         QeaVysUrkanGIHUnXVOubiK3B2mMIiLChvPFpXB7rmhKdunlyJtkejnfYo44zYA2cCE7
         RFTK7Faqu0GMUQu4BurGbs2dgpaGRN5e7bYzlLotcK5dLyo9xwPcSnXfQqUa1HUjOxQR
         mMfk9qox9P3uG1mT+ndC4B/Zu/17b2q6Rcie7N0cDIccfAZD4PH3Kf5SN0F1C02qOax1
         2eZw==
X-Forwarded-Encrypted: i=2; AJvYcCViYCQg+vFpBtfG4GgdcVGd985HnuL1K3UQvdVSTBByk7K80XQhC/83SXd5cmylVxA795Aa4Q==@lfdr.de
X-Gm-Message-State: AOJu0YyD91439H+7HV+xQCRA5Xrx0eEZa9NhvAkz7qojfDJ8DwjfXZ+4
	wkrlaf9/CQG1leEY4vsfO9aRHC5yp+IVRo79WRjxoG51PDpCQpPAyKiV
X-Google-Smtp-Source: AGHT+IF+fhCvcYY7jLFdW8cgcaUq8GxyJo90mn5COHUY0CSWXxFWKNhN447OImFTSHIPzFcv1Dc2jA==
X-Received: by 2002:a17:90b:3bcc:b0:324:e431:e426 with SMTP id 98e67ed59e1d1-3275085e5femr11311401a91.17.1756370636044;
        Thu, 28 Aug 2025 01:43:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfuAdyoL4OzWQV4K71baF9o9uifpAY5QWwsLScMAl90fA==
Received: by 2002:a17:90b:2e87:b0:325:3ba2:118e with SMTP id
 98e67ed59e1d1-327aa8ea99dls404633a91.0.-pod-prod-00-us; Thu, 28 Aug 2025
 01:43:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX0IEOEPFQ8HUW+xhWosCdGqFbKS9E27m4wf8+JrSUxs1KInJpzIPcl5aMKwUFbqrWWM9u4jkZ8+eo=@googlegroups.com
X-Received: by 2002:a17:90b:2ec3:b0:325:65e7:5cc with SMTP id 98e67ed59e1d1-3275085d776mr10366127a91.3.1756370633484;
        Thu, 28 Aug 2025 01:43:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756370633; cv=none;
        d=google.com; s=arc-20240605;
        b=XasqLJpZIMm2nNzsThwh1A4NehWLXBwVkg0HIRYOd4VnxtYHbpq2bd51xmoIV0ygxj
         a+RzM+c0NqJ2CCqAlGO6W9ngX717e75qSe4mQnv20fiKtzRg7xKHB7Ai4VxfkRlRLhnl
         YLlpGgJyedxfjJg3Oh3nnwXuVm0vm8DgnD+zA4I5n5IUEUhW+kp6u97edX2dwszofVPo
         i9x8YjDFWe9jZ/JV1irTWpiVPAZljAjhzgti6Dgs1aR50hEw7nVH3oOi347t2iuXrCAk
         /0vbXLw8Wb5d71/fCSm47eTwWQM8BuyBbwKDZg4cut2QDWm3pEKDnoI7kcz6UP60LHNi
         96xw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jLT2osl3N94HJBBJWKPAk2avCo16Lo88yw1WJjz/wsM=;
        fh=1qeczsFjcm/ZxvV2Xi0nlOqrI04ssmjuGqrtEiyysjM=;
        b=juHor90nou17cSzBZobetWa9KBLlfxGIUr9KhfCDC/sD7tjrI57Z2CQxKly1MyzKPz
         /14Ny9f/SCMH75FleigmYfdBera5Bn5mI3gt4htcpzelPEqpgXAK1niXsrjT1UquuVtA
         iM48wRwH7+uAttdeDWtUytRI2ZAQIgl2izxoAqwduXGxABJaumx+G87O8i3aOMGVqjTb
         UOdZDVT4E2DpRPzuYV6ktym35m3m8J99UWKkU+xJLESkRKmD96LsPn1ao/KedhL99bkf
         BgkRZSudAsyk4HPpFPaLLOgm+um4OVf+w3iIUWyCyBqa2mUXiDd/DIus3Ag9/hJsSrsr
         VUaQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1d+ohk5b;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::633 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x633.google.com (mail-pl1-x633.google.com. [2607:f8b0:4864:20::633])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3276f538490si134985a91.1.2025.08.28.01.43.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Aug 2025 01:43:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::633 as permitted sender) client-ip=2607:f8b0:4864:20::633;
Received: by mail-pl1-x633.google.com with SMTP id d9443c01a7336-248d5074ff7so3596635ad.0
        for <kasan-dev@googlegroups.com>; Thu, 28 Aug 2025 01:43:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXJ0ZmGsLMKvMDAn/daYpY78hG3WGQB+s5PsFAymikoppvYQSB/+mPb6PZqwsH1iQ0fvQYPNbMhpIs=@googlegroups.com
X-Gm-Gg: ASbGncvodlI+FJrdJkTW/bkhEkcHH79QMYB08ONrHlfuK0PS3h45/oVGt51rH8aKWCN
	D/QQlNv2BoE8qRQGSseVg8yGZSfMTKruUgaQAM3Qipcw6LS2dRHL0rlfb73tvD37qbP9X5wQCzX
	JOKq3mBVBOk93bZM6TzjJnw4itF3CmJBaxlZJb3k7MsQDCD65od7oV2O1ezQC6hBW1lxiM2C068
	Se8csAafHY5toRXO+FWxI4GCwA=
X-Received: by 2002:a17:903:3d06:b0:248:8063:a8b4 with SMTP id
 d9443c01a7336-2488063abcbmr89508125ad.22.1756370632768; Thu, 28 Aug 2025
 01:43:52 -0700 (PDT)
MIME-Version: 1.0
References: <20250827220141.262669-1-david@redhat.com> <20250827220141.262669-35-david@redhat.com>
In-Reply-To: <20250827220141.262669-35-david@redhat.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 28 Aug 2025 10:43:16 +0200
X-Gm-Features: Ac12FXwMzUnIHp_v7uH0kV3Hu6ram9vqgPmCMZ3TyuNNAlhDfe6K8rTgx1FpO8k
Message-ID: <CANpmjNP8-dM-cizCfsVOUNDS2jBaY6d=0Wx8OGen5RbXgaqcfQ@mail.gmail.com>
Subject: Re: [PATCH v1 34/36] kfence: drop nth_page() usage
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>, 
	dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org, 
	iommu@lists.linux.dev, io-uring@vger.kernel.org, 
	Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>, 
	John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com, kvm@vger.kernel.org, 
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Linus Torvalds <torvalds@linux-foundation.org>, 
	linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org, 
	linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org, 
	linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org, 
	linux-mmc@vger.kernel.org, linux-mm@kvack.org, 
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org, 
	linux-scsi@vger.kernel.org, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>, 
	Marek Szyprowski <m.szyprowski@samsung.com>, Michal Hocko <mhocko@suse.com>, 
	Mike Rapoport <rppt@kernel.org>, Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org, 
	Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>, 
	Robin Murphy <robin.murphy@arm.com>, Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>, 
	virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, 
	x86@kernel.org, Zi Yan <ziy@nvidia.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=1d+ohk5b;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::633 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Thu, 28 Aug 2025 at 00:11, 'David Hildenbrand' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> We want to get rid of nth_page(), and kfence init code is the last user.
>
> Unfortunately, we might actually walk a PFN range where the pages are
> not contiguous, because we might be allocating an area from memblock
> that could span memory sections in problematic kernel configs (SPARSEMEM
> without SPARSEMEM_VMEMMAP).
>
> We could check whether the page range is contiguous
> using page_range_contiguous() and failing kfence init, or making kfence
> incompatible these problemtic kernel configs.
>
> Let's keep it simple and simply use pfn_to_page() by iterating PFNs.
>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Marco Elver <elver@google.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>

Reviewed-by: Marco Elver <elver@google.com>

Thanks.

> ---
>  mm/kfence/core.c | 12 +++++++-----
>  1 file changed, 7 insertions(+), 5 deletions(-)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 0ed3be100963a..727c20c94ac59 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -594,15 +594,14 @@ static void rcu_guarded_free(struct rcu_head *h)
>   */
>  static unsigned long kfence_init_pool(void)
>  {
> -       unsigned long addr;
> -       struct page *pages;
> +       unsigned long addr, start_pfn;
>         int i;
>
>         if (!arch_kfence_init_pool())
>                 return (unsigned long)__kfence_pool;
>
>         addr = (unsigned long)__kfence_pool;
> -       pages = virt_to_page(__kfence_pool);
> +       start_pfn = PHYS_PFN(virt_to_phys(__kfence_pool));
>
>         /*
>          * Set up object pages: they must have PGTY_slab set to avoid freeing
> @@ -613,11 +612,12 @@ static unsigned long kfence_init_pool(void)
>          * enters __slab_free() slow-path.
>          */
>         for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
> -               struct slab *slab = page_slab(nth_page(pages, i));
> +               struct slab *slab;
>
>                 if (!i || (i % 2))
>                         continue;
>
> +               slab = page_slab(pfn_to_page(start_pfn + i));
>                 __folio_set_slab(slab_folio(slab));
>  #ifdef CONFIG_MEMCG
>                 slab->obj_exts = (unsigned long)&kfence_metadata_init[i / 2 - 1].obj_exts |
> @@ -665,10 +665,12 @@ static unsigned long kfence_init_pool(void)
>
>  reset_slab:
>         for (i = 0; i < KFENCE_POOL_SIZE / PAGE_SIZE; i++) {
> -               struct slab *slab = page_slab(nth_page(pages, i));
> +               struct slab *slab;
>
>                 if (!i || (i % 2))
>                         continue;
> +
> +               slab = page_slab(pfn_to_page(start_pfn + i));
>  #ifdef CONFIG_MEMCG
>                 slab->obj_exts = 0;
>  #endif
> --
> 2.50.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250827220141.262669-35-david%40redhat.com.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP8-dM-cizCfsVOUNDS2jBaY6d%3D0Wx8OGen5RbXgaqcfQ%40mail.gmail.com.
