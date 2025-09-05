Return-Path: <kasan-dev+bncBC32535MUICBBHEM5LCQMGQEXOLV2JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id 08319B44E0C
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Sep 2025 08:41:35 +0200 (CEST)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-244581ce13asf39125875ad.2
        for <lists+kasan-dev@lfdr.de>; Thu, 04 Sep 2025 23:41:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757054493; cv=pass;
        d=google.com; s=arc-20240605;
        b=IeqytcHqtHAaAMNtRWYCw8qYyU5iZwHDdmZCXXE89HMFV8u27/0lEYvx3KosrVwGMB
         MWrpxmh6fsJgkhjYiZAgq23TJ2QD2yRLyzo3ymPtrlBahs60mH7Luq+f6prfLRlf1fvN
         6fyUv2FZ/ewSAvF75aZhf0KZoW/7xcKBXHW7cKNwYetsIUt3P/qRgA47MrgEygSpyT4b
         mLVUGey3IO3VjQS5SRUfFQDUXitpIiOBkUus29pryPPsm2K3ed2jwlb2UPdSodUR3x+M
         BrDqKHMkW4D2BhUJ5NmOmpYCjCNQWD2fjRZHs1wJ6JZItE556aqkDmMtT3H1XwNgNcKj
         hNAA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-language
         :in-reply-to:autocrypt:from:references:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-signature;
        bh=gzDdUSDwS6fOmW2t2SJa7X5X4k8QD4iCrTGlo01ofBo=;
        fh=E7sjaelbmMODUVmPW3uyBKdyhHymS2EiJynwWXfTs9I=;
        b=J02lbAQutBAtewZmakdBzczcEElgDZp+yM8zZF5cerJxJiroHQSha5vMaIuK7DJkVQ
         XWAvqvoYtvpYfKWozmzQGQGqjI8MD1yfmDParTxzjHJHxe9a2sEGKEvNuoolUmObCpta
         pQlRlLU06i06MhHI99bAHnMkBW4XywpcFiX7bJyEW5pMOBNApDJa0hqnBqWFkjiZF2fk
         mmJw8FoSqaEhS5m3qrdAXGLHYHZANkGZ8KsS+KVz8RBuNyqwOCWmpzfvTGWnhFFXM6Ls
         HQJ8SRezWTgjdDxPooiA5+SB8d0BsPi+BFsPFeDfuFBTy5sqt8FGwsjWalh822OydlB3
         NPwg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=EpW1p9MM;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757054493; x=1757659293; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=gzDdUSDwS6fOmW2t2SJa7X5X4k8QD4iCrTGlo01ofBo=;
        b=ss38izuw979LCpLb73pP4eThSkGrc57D4s4G6/pSxsX2okKe8FXrBWZVvELsPQQL2E
         +ZFQ7pbK7V8L6DSyxGi9afGHxLfa7aEXGECnMccG8JGqhFTaHxHlcCo1wuP+yZb2PbpH
         y7XfIrHGphd1hVTgrlucNW0V8pUG4Fop8QhFjh5fgfsXZohBslnlqxMBxboGr0gw9uCr
         Tlc+oHlJF1K/CHnvVL9JdPQFO2ehlbxvGkImZU2zFGGWXkUnfcJfXaZubgJXMf6bNNk+
         z/mwJiY9Kt6DETS7jQ3bCio4PbhwV4UlE382WNLIGV7Nr7EpMkePxbY1yj/bfLnM32fv
         JWQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757054493; x=1757659293;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-language:in-reply-to:autocrypt:from:references:cc:to
         :subject:user-agent:mime-version:date:message-id:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=gzDdUSDwS6fOmW2t2SJa7X5X4k8QD4iCrTGlo01ofBo=;
        b=c9t0mNYgNO6NSFvGvr75zfBNWi2CU6Douz8Z40ScxVpoR/C2RdL0kV4PnZYh0FOhpr
         eQxJqfXSqPv0JdQhPVWd3ZHIJ8y0AXuTpzZwK7pT+8oazgOV6Dmdu7GEHWlUHHkYWTj3
         odsS9iroL55r1taeQ+vY6ieDEsANUCtc8K2NGH2IneV/eqmmjpMeJ3gdur1G7dgLWguA
         MtnjNHTyVSN0JsGET1r+lDOmWr4Z69gh200BTcp+heLLUlrJzpOXYMNJQy4kypAFgL4U
         lyJpJqi2eOqJCZchDBIOthdZAhVzmVcKyAl77R76Hp7vry3YbElBA+vsrkw0ecI568jl
         4l3g==
X-Forwarded-Encrypted: i=2; AJvYcCUi0VQwXZ3U/gyFjsBe/zn80rPsdjQ/JyGzSWQ9VmTnYC8N0Ii8yj4J/lKatUmiCxFnnaKJ8A==@lfdr.de
X-Gm-Message-State: AOJu0YwrVpFJC+Urtld2uWgj9kfGJJsi36h/wLbHywB9djrg8tJVDmtE
	UzeYZoUiy1xPWysZr6eBVnLdu+rS0JCCuqqkwZ1K0cwIH2Q4sv8nSaZv
X-Google-Smtp-Source: AGHT+IGRJOJZ758xYsV2NNLsGmSOnwjkcfwW+ije2YMpOF47EMWUy23BNapiI2TaUUVbeiOpsWSWfg==
X-Received: by 2002:a17:903:ac8:b0:248:7878:cee9 with SMTP id d9443c01a7336-24944ad05a0mr245405135ad.42.1757054493173;
        Thu, 04 Sep 2025 23:41:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcB50Fh3r/NygNZEQzJVifVz2i8zs4q2F31LYM9R24a0Q==
Received: by 2002:a17:903:3293:b0:24b:63d:52bf with SMTP id
 d9443c01a7336-24d4c188d2fls3544045ad.0.-pod-prod-03-us; Thu, 04 Sep 2025
 23:41:31 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV6zrjX0cpHLcLT5AWydIutVe9y8EW4eNGxi0rtLn6Z9s0yqLe4kkC/ijioiCePGeIJtE4qzb1+mZw=@googlegroups.com
X-Received: by 2002:a17:903:3d0d:b0:24c:8984:5f9c with SMTP id d9443c01a7336-24c898478c6mr117936195ad.36.1757054491553;
        Thu, 04 Sep 2025 23:41:31 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757054491; cv=none;
        d=google.com; s=arc-20240605;
        b=ktmFJsrcj048Va5g4HVCaWzYWYOh6qZCXSwPOg4qUnqO819TYq5UywpInPOTbJmN0Y
         hRcP4+R2KshS0HqLBySciK9z0sbyGhq8/m75aqcRr8GZGEEJOqO0h5KoJu3XSzsNUGJM
         Lhcm93mpZlHuBgX2k4L6UF6vO6gB64F2KKcZQQK5EXOh4GoxpJ9rMm4R98r/QQ8i2oek
         WOHcppiGjf7PRVdPIyum6QPN/tp3NvtX2twxt2noNppUTTZh/0MUg8f2a2puCxTcJBpH
         lYxz2ZZx7FcL5nvHBFRvBgBCfxxNCWLf8tF7xUPKEEdWtZur1uHPnBf5DJU/zJ9mojW4
         DmWA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:content-language:in-reply-to:autocrypt
         :from:references:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature;
        bh=oF3HN1Q6ZNxZN3c5DymWi4LgFv8yUurotu5FuTflls4=;
        fh=dG5DXcInsYQLCMbfXdZpHyawgm/AU94nqD0+YsQ4WVQ=;
        b=Ihz/y6RiwN2sXuRBgNuPBR5/zGnYED6J4xSIKKE1ahSiLkj4PQ54L8hfLe1e+8SQXw
         82PMk4O3bUXdM7NIKupfeoZ/FcxcWIq76ERTsBjzDp7bxprd0CPvPJgYZrqm26VFzJhx
         RGhnWUI0BBqq3wqfIwj7LEW4D9yNecOz+qxOtMsaQSZvQ1b0Gnni6rnVr5Y8HUAv9NxR
         5q2wwrrFEVzixyVBdyu+L+NR06+TClBcVGOKdboA+KistzpAuBLYF4o6V6+5yN3xUnsY
         QI5w85kSDfYoi5o5IEkACtBuQlrDQHOhtApiKYG3Ezm4YqTyxND0HTN01iMNfWtpDUVM
         wn9A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@redhat.com header.s=mimecast20190719 header.b=EpW1p9MM;
       spf=pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
Received: from us-smtp-delivery-124.mimecast.com (us-smtp-delivery-124.mimecast.com. [170.10.133.124])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32b915ead9dsi145337a91.0.2025.09.04.23.41.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 04 Sep 2025 23:41:31 -0700 (PDT)
Received-SPF: pass (google.com: domain of david@redhat.com designates 170.10.133.124 as permitted sender) client-ip=170.10.133.124;
Received: from mail-wm1-f71.google.com (mail-wm1-f71.google.com
 [209.85.128.71]) by relay.mimecast.com with ESMTP with STARTTLS
 (version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384) id
 us-mta-376--IJj6dKfNACMuJNNvmkV9A-1; Fri, 05 Sep 2025 02:41:29 -0400
X-MC-Unique: -IJj6dKfNACMuJNNvmkV9A-1
X-Mimecast-MFC-AGG-ID: -IJj6dKfNACMuJNNvmkV9A_1757054488
Received: by mail-wm1-f71.google.com with SMTP id 5b1f17b1804b1-45dd9a66cfbso1788795e9.1
        for <kasan-dev@googlegroups.com>; Thu, 04 Sep 2025 23:41:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCV9blDLrJD53Pt2lZq548VzPdN1hmhaPeqen6vdLNXaHd1bs/Dm/nfgP/hxneFsRT+v0HyJxMoVgrU=@googlegroups.com
X-Gm-Gg: ASbGncu1ewZkxNdOAeTYH7ZIxpvjeJYyugriHwO9rpuJoSMLMHNUKr0wBqg0dtJao7h
	7V5JujmlZV8Vru3Y09N3fnbrgZa1Ufp2L7IG8UD7irIRKitwxhhBm3Ox13BcIWbpycy1iuSVtCi
	5uk4ZW/vy+mPPKTP4uBq5rK6bZhajYW/ymGvB2mg6372r8ZqRMILLMLI2ciIF4WR09YAfiYzEUd
	I9YOvoJ7JYbNAtbeGnFmlCioIRSakxJDwbDyPsfN0auChXXwvz+yD46ZNeeiZ0nHq/B6D0IIO5Q
	cP93AFVXRtBvVY5x7uB035LnO6QCO7+UcmBHwdhXIas2z0BAT9Kj9cWqUUcwYS2HLe55TnfvtQE
	aAv4Urw/9O3lioPde8PYFRdp/2LfnB8aAVnezhezL5yvXoxQVy6RLbcjR
X-Received: by 2002:a05:600c:4ec9:b0:45b:7ffa:1bf8 with SMTP id 5b1f17b1804b1-45b934f6a56mr114232795e9.23.1757054487705;
        Thu, 04 Sep 2025 23:41:27 -0700 (PDT)
X-Received: by 2002:a05:600c:4ec9:b0:45b:7ffa:1bf8 with SMTP id 5b1f17b1804b1-45b934f6a56mr114232615e9.23.1757054487185;
        Thu, 04 Sep 2025 23:41:27 -0700 (PDT)
Received: from ?IPV6:2003:d8:2f4d:e00:298:59cc:2514:52? (p200300d82f4d0e00029859cc25140052.dip0.t-ipconnect.de. [2003:d8:2f4d:e00:298:59cc:2514:52])
        by smtp.gmail.com with ESMTPSA id 5b1f17b1804b1-45b7e8879cesm316420125e9.12.2025.09.04.23.41.24
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 04 Sep 2025 23:41:26 -0700 (PDT)
Message-ID: <5090355d-546a-4d06-99e1-064354d156b5@redhat.com>
Date: Fri, 5 Sep 2025 08:41:23 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v2 19/37] mm/gup: remove record_subpages()
To: linux-kernel@vger.kernel.org
Cc: Alexander Potapenko <glider@google.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Brendan Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>,
 Dennis Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
 dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
 iommu@lists.linux.dev, io-uring@vger.kernel.org,
 Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>,
 Johannes Weiner <hannes@cmpxchg.org>, John Hubbard <jhubbard@nvidia.com>,
 kasan-dev@googlegroups.com, kvm@vger.kernel.org,
 "Liam R. Howlett" <Liam.Howlett@oracle.com>,
 Linus Torvalds <torvalds@linux-foundation.org>, linux-arm-kernel@axis.com,
 linux-arm-kernel@lists.infradead.org, linux-crypto@vger.kernel.org,
 linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org,
 linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org,
 linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
 linux-scsi@vger.kernel.org, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
 Marco Elver <elver@google.com>, Marek Szyprowski <m.szyprowski@samsung.com>,
 Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
 Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
 Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
 Robin Murphy <robin.murphy@arm.com>, Suren Baghdasaryan <surenb@google.com>,
 Tejun Heo <tj@kernel.org>, virtualization@lists.linux.dev,
 Vlastimil Babka <vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org,
 Zi Yan <ziy@nvidia.com>, Jens Axboe <axboe@kernel.dk>
References: <20250901150359.867252-1-david@redhat.com>
 <20250901150359.867252-20-david@redhat.com>
From: "'David Hildenbrand' via kasan-dev" <kasan-dev@googlegroups.com>
Autocrypt: addr=david@redhat.com; keydata=
 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
 qIws/H2t
In-Reply-To: <20250901150359.867252-20-david@redhat.com>
X-Mimecast-Spam-Score: 0
X-Mimecast-MFC-PROC-ID: SBwvI6qU1dr-Kcejf8g4T0_BQchhOL1gzbs0wGoZD2o_1757054488
X-Mimecast-Originator: redhat.com
Content-Language: en-US
Content-Type: text/plain; charset="UTF-8"; format=flowed
X-Original-Sender: david@redhat.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@redhat.com header.s=mimecast20190719 header.b=EpW1p9MM;
       spf=pass (google.com: domain of david@redhat.com designates
 170.10.133.124 as permitted sender) smtp.mailfrom=david@redhat.com;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=redhat.com
X-Original-From: David Hildenbrand <david@redhat.com>
Reply-To: David Hildenbrand <david@redhat.com>
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

On 01.09.25 17:03, David Hildenbrand wrote:
> We can just cleanup the code by calculating the #refs earlier,
> so we can just inline what remains of record_subpages().
> 
> Calculate the number of references/pages ahead of times, and record them
> only once all our tests passed.
> 
> Signed-off-by: David Hildenbrand <david@redhat.com>
> ---
>   mm/gup.c | 25 ++++++++-----------------
>   1 file changed, 8 insertions(+), 17 deletions(-)
> 
> diff --git a/mm/gup.c b/mm/gup.c
> index c10cd969c1a3b..f0f4d1a68e094 100644
> --- a/mm/gup.c
> +++ b/mm/gup.c
> @@ -484,19 +484,6 @@ static inline void mm_set_has_pinned_flag(struct mm_struct *mm)
>   #ifdef CONFIG_MMU
>   
>   #ifdef CONFIG_HAVE_GUP_FAST
> -static int record_subpages(struct page *page, unsigned long sz,
> -			   unsigned long addr, unsigned long end,
> -			   struct page **pages)
> -{
> -	int nr;
> -
> -	page += (addr & (sz - 1)) >> PAGE_SHIFT;
> -	for (nr = 0; addr != end; nr++, addr += PAGE_SIZE)
> -		pages[nr] = page++;
> -
> -	return nr;
> -}
> -
>   /**
>    * try_grab_folio_fast() - Attempt to get or pin a folio in fast path.
>    * @page:  pointer to page to be grabbed
> @@ -2967,8 +2954,8 @@ static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
>   	if (pmd_special(orig))
>   		return 0;
>   
> -	page = pmd_page(orig);
> -	refs = record_subpages(page, PMD_SIZE, addr, end, pages + *nr);
> +	refs = (end - addr) >> PAGE_SHIFT;
> +	page = pmd_page(orig) + ((addr & ~PMD_MASK) >> PAGE_SHIFT);
>   
>   	folio = try_grab_folio_fast(page, refs, flags);
>   	if (!folio)
> @@ -2989,6 +2976,8 @@ static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
>   	}
>   
>   	*nr += refs;
> +	for (; refs; refs--)
> +		*(pages++) = page++;
>   	folio_set_referenced(folio);
>   	return 1;
>   }
> @@ -3007,8 +2996,8 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned long addr,
>   	if (pud_special(orig))
>   		return 0;
>   
> -	page = pud_page(orig);
> -	refs = record_subpages(page, PUD_SIZE, addr, end, pages + *nr);
> +	refs = (end - addr) >> PAGE_SHIFT;
> +	page = pud_page(orig) + ((addr & ~PUD_MASK) >> PAGE_SHIFT);
>   
>   	folio = try_grab_folio_fast(page, refs, flags);
>   	if (!folio)
> @@ -3030,6 +3019,8 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned long addr,
>   	}
>   
>   	*nr += refs;
> +	for (; refs; refs--)
> +		*(pages++) = page++;
>   	folio_set_referenced(folio);
>   	return 1;
>   }

Okay, this code is nasty. We should rework this code to just return the nr and receive a the proper
pages pointer, getting rid of the "*nr" parameter.

For the time being, the following should do the trick:

commit bfd07c995814354f6b66c5b6a72e96a7aa9fb73b (HEAD -> nth_page)
Author: David Hildenbrand <david@redhat.com>
Date:   Fri Sep 5 08:38:43 2025 +0200

     fixup: mm/gup: remove record_subpages()
     
     pages is not adjusted by the caller, but idnexed by existing *nr.
     
     Signed-off-by: David Hildenbrand <david@redhat.com>

diff --git a/mm/gup.c b/mm/gup.c
index 010fe56f6e132..22420f2069ee1 100644
--- a/mm/gup.c
+++ b/mm/gup.c
@@ -2981,6 +2981,7 @@ static int gup_fast_pmd_leaf(pmd_t orig, pmd_t *pmdp, unsigned long addr,
                 return 0;
         }
  
+       pages += *nr;
         *nr += refs;
         for (; refs; refs--)
                 *(pages++) = page++;
@@ -3024,6 +3025,7 @@ static int gup_fast_pud_leaf(pud_t orig, pud_t *pudp, unsigned long addr,
                 return 0;
         }
  
+       pages += *nr;
         *nr += refs;
         for (; refs; refs--)
                 *(pages++) = page++;


-- 

Cheers

David / dhildenb

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5090355d-546a-4d06-99e1-064354d156b5%40redhat.com.
