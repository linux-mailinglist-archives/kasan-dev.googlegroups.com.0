Return-Path: <kasan-dev+bncBDZMFEH3WYFBBAE4YDCQMGQEYFXFW2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3f.google.com (mail-oa1-x3f.google.com [IPv6:2001:4860:4864:20::3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2B261B3962A
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 10:06:26 +0200 (CEST)
Received: by mail-oa1-x3f.google.com with SMTP id 586e51a60fabf-30cce87c38dsf253870fac.1
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 01:06:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756368385; cv=pass;
        d=google.com; s=arc-20240605;
        b=FeeWzyIEV23gr90HQ0rgHxpay+5p8oE8UhyOvR7eLpKXTRf7OIUqtH6TCGqnQq9Odo
         Mt5uRR+10u7RiGuHYypvzf6juzKPSGVIBrNMwOYF1XsDKQB9GKBK95DIKA45CbDNvWBJ
         qjKU/nMa0tq1cc0WUmIfyVEjOqPb/CNyo4oIDzAeFnYywwPBzufvEjMp1C83BB0OPYjy
         BuxJrtoVTw9c3KJzPF6QTDiuQ6EAS/gH5ZrsM9DOLA6fUmU+gMZp9sDszfGIku/A+C9M
         qIsq80gYw0rAWIOG2QqcnLOjR6Vwc4CZy1aZHNmngvO8wAovhqNJXoW6sqs6wjt0xp/C
         tZWA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=8rQ7HFieDdXNTaT6lu2XIanwQU+yniZsvpa7urHpI7s=;
        fh=Mj4vzJqnkdge3nYQzO/2ZlmvrGSw+Re++FR1eDA7DY4=;
        b=V2Y8jHbLzy5Fh9/2kCbta7oQHm4HU4ZjXTaJqHwb5Pu66KL5MqtgDYZB80wzsgFRJz
         bnvOJT3q+fgqFPN5BfAyxS1dbhGGUdT8xsm0xs+JbaivZKLWpxwf9tx0p/IiAZOYc3Hn
         ZFFQfntv9vshYlWerjzgsPkpYe+JGZE+kaAgek6iNXDkHZoF7zN9eZO3CKJtAmn3PoGp
         gtKCwbyBWzo8kv1IyCnh+g86019nmBD5Z9VbSF4oY3xBYZTefkF+2q+kNIbtibsa66JF
         PqlESA0uvkcSWfTkLvAB+5iwaAP3rTixk0CZtgEAFxDwPRPhJp13igy1l52WQQ5O1196
         /W3Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=vBGjtF+G;
       spf=pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756368385; x=1756973185; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=8rQ7HFieDdXNTaT6lu2XIanwQU+yniZsvpa7urHpI7s=;
        b=E9L3GXk+pRrOuhuYoCL64yf09y3iSyCCxrvvCIG53hb6n1a9rMG8imORLi1tje7W5F
         8SRJItlHXMU5YcwAF2w3NUIOc1u507A27DDEud+Zn4pmPT2lRCpAWlAsML7FQM8VWPDC
         43psdQ3lvlm233KvRChYerCjlXxEPf7Ny0HEyIK5BAFvoXiEJ3ZwkCzMYAQM66wDpFRM
         HU/A0tw4X5eJyqbnofXpo/pm4IAVyp/cz2BikqEgklPptCC3UdMH/R8kj5Dnod0zGCOL
         4hn9hwbvosLSp0OsJR0GIw6BzuKqdNsaJIJiJbDWAEY6MsN7ICnFNtcReVN7//N5aVxB
         gcgw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756368385; x=1756973185;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=8rQ7HFieDdXNTaT6lu2XIanwQU+yniZsvpa7urHpI7s=;
        b=rn3S3VqCLZtRZvoscJZsp93GhXLfeuhFTAFmwRaDgriwt9PiAONrmXDf9J9vMuCKa6
         MQS8AcwtL1W164ZTJxR5TRfBo0UbF0j0vsvg82kzwbmeokVOxR7JwzTdeNtsHkwBRP6U
         H8wcANoXFTh577QwcNTUMVEGgsVLIw/zxVro11RAsAoJZhXYPwSIkEkd8BWFi22RCuEz
         GKWJNOgUN0WpxngFLuVlNx5IHT36HF+bk7Ntu78e5qcP/lQ7c8X/KjKXZLp3j3NgC7Ox
         FzonSIsp66dzoNzusHKR/tU0920EfqIi6LzinVg8nZv7tVN1cXIKJDZj/8gNCAhr0JMV
         n1CA==
X-Forwarded-Encrypted: i=2; AJvYcCU7Ip9xP+6ZJZZ8QucWS4fu0nrbV+vcYLv3w3ZTFiePGDbutijLw+4jZIpFDnxLdCPsBtNoYg==@lfdr.de
X-Gm-Message-State: AOJu0Yzq1/HhCOL6oLONNz1RUCZcYUMNGQDxj/fn9WmhQTb05fgb+0ap
	oMI12/y+w685lBpVUgrx+Q/8fElZ3EZ035zEouLQBBxaVyzdXGLWH3cQ
X-Google-Smtp-Source: AGHT+IEm7LHK9RN4k8RBxdQFCYBVfxfVlqiYQkF2K/m4ZWrknR0vYuRbz8EWNOupR9sSqIPU1htzoA==
X-Received: by 2002:a05:6870:a915:b0:315:a12c:f0d3 with SMTP id 586e51a60fabf-315a12cfbe7mr416598fac.27.1756368384590;
        Thu, 28 Aug 2025 01:06:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe5bDP/iNwlc1APiT2q3YM3U7R0Wrv7XXaDY7L+Bdrx/Q==
Received: by 2002:a05:6871:ae06:b0:2ef:3020:be7e with SMTP id
 586e51a60fabf-315961b2e29ls114953fac.1.-pod-prod-06-us; Thu, 28 Aug 2025
 01:06:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUPTB6rbjvtkqPQk6MBGEPLYfllfcIyvNa2QR17+BB4gvZojnP4T7bCmaPE98upgsosC2a4Lp635gc=@googlegroups.com
X-Received: by 2002:a05:6808:1805:b0:435:a9b5:f0cd with SMTP id 5614622812f47-43785283c98mr10342637b6e.11.1756368383280;
        Thu, 28 Aug 2025 01:06:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756368383; cv=none;
        d=google.com; s=arc-20240605;
        b=A19xKeyU5so7hyyhDL0dt2yGWJ/v816BTLhgbqSq5rsPleZ4iAPJH+ottf206sXUBh
         m3s3ZC7/7XpwhONZdfuqxDaPWf40GvZRVLeiaOqhKt8cTQKF2Kip+RdlBn2gS9APIdAB
         bwNvFlRp3g2Zqn0+42VsPgL2pc90CgSxBq8152v7x74SokzPTc1lc0HDHbW92WcxZG4S
         20s/akENh3tWa+q36sKQ2GOpcuWy/uYIx+LNQap27VK0B/rk+P71sOQvaP147rRqpZw0
         kY4JMk1f49MpZ+CAK4GRoFy2gyD4JzhaoDrIlwIgZkaTXbR1Z4f9FauLYxZw4pKl25JV
         PkBw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=DDvtHRzQtU3kCixyIjuOCQ09hTrFj2+oewMln+u6hX4=;
        fh=9i7Xo3ec5v6Czbc/Gl1AZEKMmN1XodXJiUIITipUCZU=;
        b=j0kh4QPB6txQQmpNxgZw2zG9YRAwWFyJ/iG5CPShOD6XuiwjtaiiGU7Vl8NHyTbDR8
         4bBb5FfXvysZS3ZsdqwcBKdjDsW4Dr4RGd2UjBm2PHZOzmEAjtwKEmeMYGvjkEm1UQjO
         dCeDzmG3iU9Ff8UXtCW+3Okiz6KMynt2VfldtdTlaaAB+VXTz/sVysYiSVnDleQj+RC0
         p/htboe6BtJEzUyhvSRhQDw9kEXvV5yh0tZAMd1wJf+acEhvM/d03aw54r45ypNgQR+a
         71io0jopXAgQmuoV+yM4MAAfCGm2WdbsVbBGyN72GqXa5KV37AzZWPBODCrvzsljgbir
         XhSg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=vBGjtF+G;
       spf=pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 006d021491bc7-61dc775bbdasi35395eaf.2.2025.08.28.01.06.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 01:06:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 62110417C0;
	Thu, 28 Aug 2025 08:06:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 04174C4CEEB;
	Thu, 28 Aug 2025 08:06:10 +0000 (UTC)
Date: Thu, 28 Aug 2025 11:06:07 +0300
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
Message-ID: <aLAN7xS4WQsN6Hpm@kernel.org>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-14-david@redhat.com>
 <aLADXP89cp6hAq0q@kernel.org>
 <377449bd-3c06-4a09-8647-e41354e64b30@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <377449bd-3c06-4a09-8647-e41354e64b30@redhat.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=vBGjtF+G;       spf=pass
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

On Thu, Aug 28, 2025 at 09:44:27AM +0200, David Hildenbrand wrote:
> On 28.08.25 09:21, Mike Rapoport wrote:
> > On Thu, Aug 28, 2025 at 12:01:17AM +0200, David Hildenbrand wrote:
> > > We can now safely iterate over all pages in a folio, so no need for the
> > > pfn_to_page().
> > > 
> > > Also, as we already force the refcount in __init_single_page() to 1,
> > > we can just set the refcount to 0 and avoid page_ref_freeze() +
> > > VM_BUG_ON. Likely, in the future, we would just want to tell
> > > __init_single_page() to which value to initialize the refcount.
> > > 
> > > Further, adjust the comments to highlight that we are dealing with an
> > > open-coded prep_compound_page() variant, and add another comment explaining
> > > why we really need the __init_single_page() only on the tail pages.
> > > 
> > > Note that the current code was likely problematic, but we never ran into
> > > it: prep_compound_tail() would have been called with an offset that might
> > > exceed a memory section, and prep_compound_tail() would have simply
> > > added that offset to the page pointer -- which would not have done the
> > > right thing on sparsemem without vmemmap.
> > > 
> > > Signed-off-by: David Hildenbrand <david@redhat.com>
> > > ---
> > >   mm/hugetlb.c | 20 ++++++++++++--------
> > >   1 file changed, 12 insertions(+), 8 deletions(-)
> > > 
> > > diff --git a/mm/hugetlb.c b/mm/hugetlb.c
> > > index 4a97e4f14c0dc..1f42186a85ea4 100644
> > > --- a/mm/hugetlb.c
> > > +++ b/mm/hugetlb.c
> > > @@ -3237,17 +3237,18 @@ static void __init hugetlb_folio_init_tail_vmemmap(struct folio *folio,
> > >   {
> > >   	enum zone_type zone = zone_idx(folio_zone(folio));
> > >   	int nid = folio_nid(folio);
> > > +	struct page *page = folio_page(folio, start_page_number);
> > >   	unsigned long head_pfn = folio_pfn(folio);
> > >   	unsigned long pfn, end_pfn = head_pfn + end_page_number;
> > > -	int ret;
> > > -
> > > -	for (pfn = head_pfn + start_page_number; pfn < end_pfn; pfn++) {
> > > -		struct page *page = pfn_to_page(pfn);
> > > +	/*
> > > +	 * We mark all tail pages with memblock_reserved_mark_noinit(),
> > > +	 * so these pages are completely uninitialized.
> > 
> >                               ^ not? ;-)
> 
> Can you elaborate?

Oh, sorry, I misread "uninitialized".
Still, I'd phrase it as 

	/*
	 * We marked all tail pages with memblock_reserved_mark_noinit(),
	 * so we must initialize them here.
	 */

> -- 
> Cheers
> 
> David / dhildenb
> 

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aLAN7xS4WQsN6Hpm%40kernel.org.
