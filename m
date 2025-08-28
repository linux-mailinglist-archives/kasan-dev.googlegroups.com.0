Return-Path: <kasan-dev+bncBDZMFEH3WYFBB4EGYDCQMGQE42H6ITQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb39.google.com (mail-yb1-xb39.google.com [IPv6:2607:f8b0:4864:20::b39])
	by mail.lfdr.de (Postfix) with ESMTPS id 42313B394FA
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 09:21:22 +0200 (CEST)
Received: by mail-yb1-xb39.google.com with SMTP id 3f1490d57ef6-e9701d3fe48sf591280276.1
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:21:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756365681; cv=pass;
        d=google.com; s=arc-20240605;
        b=EoRN3ZGkQHucoL+cP9mW5JlaC1bERLPppTNeA1QwnrEVuKaF82VytjdtThtx3dD4az
         zEdP2Jc8rDjnuf+yg1I9wV+FxLdb/wu9SALW6PnHzGGv80/1q/l4dTjDPOzVJPQ10lkq
         BCD1J2WNGMW1H4/WF4fD0Vl1UrLEh3bZMzugysE0dzxQvut7qrS3juuDIrMjN64Pyi1m
         InV+rfU0obs7qEmOOpnTdkNLBWa66S4BztndCFzjjx3rqACrPSYNs46VfOHx46RsWZ1K
         qoj/gTJJHON2lo174l/HCu51L9FIxa2jfBM1BlFJA1daP3KnkMxMnM9IIlh3xOch0+pt
         22wA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=QMnKvf+CkliAxEYx0O2CiK7U1HEBt4GDtDEj4n1wWiI=;
        fh=Xdjt36PfapY9NR8LM6jIdtjhuyeH5dZEIK8A5mHKhcE=;
        b=MRAHGySQIwTPhSqNgm26oq0iphwhwzX7ejErA9RLCHBOPvp3Yy2fb3/xz9M3hJ1hPy
         yFo8FJloXIEpvjb45Wl/QaZ8mpFedP9F3LV0kIOKxW2nN1voh30OlEC9XgL0+ml5thr2
         RIDkMzHYjP9Su5naqMCZw/A6VcdpupII7ddBuK8TWW1Nkp/x7S8z8yutmsQZuz3bB65R
         b/onpjH7xYWKXyoJIpKGlm30WVqWhwhdQo1Ranoc+Wkosf6IycwqkWqm/lf+sl6FgxtP
         aufRdX22t+B2YRz+xhhVHZGhUmxmYsDngkgx9NTWz6RWAAIvdb2ha5UyvG9kymqLTxng
         oJYg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=P3P6rik2;
       spf=pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756365681; x=1756970481; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=QMnKvf+CkliAxEYx0O2CiK7U1HEBt4GDtDEj4n1wWiI=;
        b=ZKkwSSFsR2FzcLlBS2aCh3hbHs1XNF4bXk1E3xcaWdZd4o4/uSnEpza/txqoY7E+Ug
         BVDuR3SJN94pIokE2aKWH9nVqmTyzKAjV0L+K3UhxsSpUU9C0eXhouvRrmMePMrVymVQ
         eUE9qNDnGgiQKHbqId2SQH6xzY7SL+Os3+6Sbj4tJPDHIEO+/4/dA86R+roFoS/giEcB
         Lnza4wWg/8Pb10AMzlfqVkpxBuiHeTdqCegs5HzpfSgtuOYvRj7YzYONa1eR/vdhoyRy
         EXyXBff4tOjV8e81jq0KZcWlX43ew3iilrANjYc3qvJ3y7z+GAap0Zi3TEiGOg/Ohh+N
         Pfvg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756365681; x=1756970481;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QMnKvf+CkliAxEYx0O2CiK7U1HEBt4GDtDEj4n1wWiI=;
        b=H0bHI3MFZaHsLeVcN1yI4RpD+tsdJmm7GgOvQWk3Ls+JMFoVOvjOLMaSruH7Gn2/5G
         1AvhdMBzzMQO2RoL2faZcR1iJ0GMwFJ02Ib0um9M1/gcuQz83aGhVIi7XvA8qGwTONXY
         BSHQCtzQI+3q0xKN8MkiPKpFTZkcZvL1i22pLVXxBHIGb6taN3HCYI0jytO6HRspX28Y
         4s8HncKXkrblrg17J4SOv10rW0bGc9l6xGh86vtgKVxnzOeSCnpUvsytqjv7J9+iTJZw
         OE0J8gRcm4iy7GoYMjyz5n5FSBofnS8mp2/xAG6YJft/flzgYYZBCO02PkZLTDNwBTWc
         +yZQ==
X-Forwarded-Encrypted: i=2; AJvYcCUzCGti0NHZsKfqVr1UCH1tGr4oRqEL19V8PnsDu4dL5K16VvmM8kOUoFnesQWTktQpAWmcrg==@lfdr.de
X-Gm-Message-State: AOJu0YyAyw8ibYWArNW1dhgv23iPDQV5p9aOJgLrz5so5k3y/agDnAxf
	6bPJrjmxTaGpT4exai/Tg4IkJokfza04J4HcGbAI7aWedyi5b5CPsTQM
X-Google-Smtp-Source: AGHT+IEvA8lWtRlJsBEhw+cHE5pLUR+cojMr+UMFhKOexfmqANQoYH9pioYF4qtvmh2vGtFZ3xCiKQ==
X-Received: by 2002:a05:6902:10c3:b0:e95:3e05:a634 with SMTP id 3f1490d57ef6-e953e05a74cmr15268006276.42.1756365680859;
        Thu, 28 Aug 2025 00:21:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfE7c7PzF55knKUolaZv1U+bsl2ZihJ04XIKFlPXWbcaA==
Received: by 2002:a25:6a05:0:b0:e93:349e:511f with SMTP id 3f1490d57ef6-e9700ebc802ls500180276.1.-pod-prod-05-us;
 Thu, 28 Aug 2025 00:21:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXMd8nVGak3i+EE0r8h9pNfTCX3HUyjtQg5SNmyb6+c6tmxKTMkGPvr1G/pDS5SpYBaL0HwWTzPuWg=@googlegroups.com
X-Received: by 2002:a05:690c:d93:b0:720:7f7:6991 with SMTP id 00721157ae682-72007f7940emr201792997b3.30.1756365679908;
        Thu, 28 Aug 2025 00:21:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756365679; cv=none;
        d=google.com; s=arc-20240605;
        b=KiTWnR42zOMnvmLga/VqlmrMPxMdxFXzatbirEbYTwRcfNZALApLG0ty4qdb9FgDxs
         xOBdHp6NEduLuN91L2K7wdt/g0W4D81m7bqdCZFcizz2u0qbGaStyhBpfkFZH3BWFMn4
         PQFuRqIIh64hVQ1nOo1oeU+BkJTwcTAcIDrsVxtKiRsMfgxSuFD34rpZmP3W7WsLSk3F
         jOsyrhu/w3B4RSQDDpZZLnmIzLEyv4b3taG3npiyrVaLnLaFxoY3TWSW6CRYybo5gI6d
         Lc3zR03OuXwbZ3H6VOpQrnxl5LcOaTc1urB1j9au265hSugshi8+ABWmhS/hWc+Z+ud5
         8UGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=py4avZkKZs9gMtxyD4o7g7fY03HHmjmGgT6Iq9b3bsc=;
        fh=9i7Xo3ec5v6Czbc/Gl1AZEKMmN1XodXJiUIITipUCZU=;
        b=FzsloC/1YbfHfD9ulxcmJvY13CoK5L2OtB/fUhh1veAOvp141q2JPdBkNPxBcF3Qnj
         6bbbEKcu1sat7YM7HTmEJC8ihM+LKUF+LWPT/UWt73HJYg1VnYGQQ4nstLSVrE335OH1
         XGa6YPXlLMlpLWz+D4tP1s87GcdCvaJF7LyFk9zll74hwUTOPZk/KsaDa9Ij7CRATusw
         cY/rsub2zWfjlNkX7bZX4/sSufsDAkNUIbs02b+OexBn4vHLsHc6Hx0ZQ286jJgJb9Vd
         E98pIeFhhgG3/tlg6iwnc3OwsrtcD8cw9rbAUhwuuCkH5vY+bwS97sPSlAlt5GdSkfzZ
         aR0w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=P3P6rik2;
       spf=pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-72123c5c91fsi3290167b3.3.2025.08.28.00.21.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 00:21:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 4394B601D3;
	Thu, 28 Aug 2025 07:21:19 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id D6A4FC4CEF5;
	Thu, 28 Aug 2025 07:21:04 +0000 (UTC)
Date: Thu, 28 Aug 2025 10:21:00 +0300
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
Subject: Re: [PATCH v1 13/36] mm/hugetlb: cleanup
 hugetlb_folio_init_tail_vmemmap()
Message-ID: <aLADXP89cp6hAq0q@kernel.org>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-14-david@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-14-david@redhat.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=P3P6rik2;       spf=pass
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

On Thu, Aug 28, 2025 at 12:01:17AM +0200, David Hildenbrand wrote:
> We can now safely iterate over all pages in a folio, so no need for the
> pfn_to_page().
> 
> Also, as we already force the refcount in __init_single_page() to 1,
> we can just set the refcount to 0 and avoid page_ref_freeze() +
> VM_BUG_ON. Likely, in the future, we would just want to tell
> __init_single_page() to which value to initialize the refcount.
> 
> Further, adjust the comments to highlight that we are dealing with an
> open-coded prep_compound_page() variant, and add another comment explaining
> why we really need the __init_single_page() only on the tail pages.
> 
> Note that the current code was likely problematic, but we never ran into
> it: prep_compound_tail() would have been called with an offset that might
> exceed a memory section, and prep_compound_tail() would have simply
> added that offset to the page pointer -- which would not have done the
> right thing on sparsemem without vmemmap.
> 
> Signed-off-by: David Hildenbrand <david@redhat.com>
> ---
>  mm/hugetlb.c | 20 ++++++++++++--------
>  1 file changed, 12 insertions(+), 8 deletions(-)
> 
> diff --git a/mm/hugetlb.c b/mm/hugetlb.c
> index 4a97e4f14c0dc..1f42186a85ea4 100644
> --- a/mm/hugetlb.c
> +++ b/mm/hugetlb.c
> @@ -3237,17 +3237,18 @@ static void __init hugetlb_folio_init_tail_vmemmap(struct folio *folio,
>  {
>  	enum zone_type zone = zone_idx(folio_zone(folio));
>  	int nid = folio_nid(folio);
> +	struct page *page = folio_page(folio, start_page_number);
>  	unsigned long head_pfn = folio_pfn(folio);
>  	unsigned long pfn, end_pfn = head_pfn + end_page_number;
> -	int ret;
> -
> -	for (pfn = head_pfn + start_page_number; pfn < end_pfn; pfn++) {
> -		struct page *page = pfn_to_page(pfn);
>  
> +	/*
> +	 * We mark all tail pages with memblock_reserved_mark_noinit(),
> +	 * so these pages are completely uninitialized.

                             ^ not? ;-)

> +	 */
> +	for (pfn = head_pfn + start_page_number; pfn < end_pfn; page++, pfn++) {
>  		__init_single_page(page, pfn, zone, nid);
>  		prep_compound_tail((struct page *)folio, pfn - head_pfn);
> -		ret = page_ref_freeze(page, 1);
> -		VM_BUG_ON(!ret);
> +		set_page_count(page, 0);
>  	}
>  }
>  
> @@ -3257,12 +3258,15 @@ static void __init hugetlb_folio_init_vmemmap(struct folio *folio,
>  {
>  	int ret;
>  
> -	/* Prepare folio head */
> +	/*
> +	 * This is an open-coded prep_compound_page() whereby we avoid
> +	 * walking pages twice by initializing/preparing+freezing them in the
> +	 * same go.
> +	 */
>  	__folio_clear_reserved(folio);
>  	__folio_set_head(folio);
>  	ret = folio_ref_freeze(folio, 1);
>  	VM_BUG_ON(!ret);
> -	/* Initialize the necessary tail struct pages */
>  	hugetlb_folio_init_tail_vmemmap(folio, 1, nr_pages);
>  	prep_compound_head((struct page *)folio, huge_page_order(h));
>  }
> -- 
> 2.50.1
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aLADXP89cp6hAq0q%40kernel.org.
