Return-Path: <kasan-dev+bncBDZMFEH3WYFBBZNKYDCQMGQEWXCL5PI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13f.google.com (unknown [IPv6:2607:f8b0:4864:20::b13f])
	by mail.lfdr.de (Postfix) with ESMTPS id 4368EB39721
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 10:37:59 +0200 (CEST)
Received: by mail-yx1-xb13f.google.com with SMTP id 956f58d0204a3-5f8c2229b3bsf855276d50.1
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 01:37:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756370278; cv=pass;
        d=google.com; s=arc-20240605;
        b=RNmAFOWvcmmZcQDvYDawNOKUhm6EOevUdlOeWJ+krBTr2tdiLxDdhWCOicwmsO4fg7
         uVpsS1jI99B49T+5OGR5TiIneqkOrgybu2RRASE60GORi5z3m3RjLDOJ1lOGjFHgzfa7
         zzsEi0eocZe/Mfm1y3XtIhG86xXOYt0S3Z5KdHnEwLyJZ26YPGZOV7OoWoUmRqcnC9CU
         +SoXYldVKOS9ONRrW7bwctWgk/i8bkVYsOYBVuqzsigCWELONKFSB+AvYysfLmcSI9mB
         Yfc4vhqvspqG43EIe6guZOqXp4wkF5855zcAH4Gz/r3v+TGmv6LjjwrbF0Xqdgk3V2Uk
         moxA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ms9cJwnQQkxiVM7BsBFRhZ709v1PqdVv8Sp54XUAxeQ=;
        fh=5Tm4dYoQ0RwGp4LUvIZAo9jym18TTZjtzC43rgo/xw0=;
        b=claFADC7HFmic1aQzQrmFkTuJrAF3+u4fO7jUa81KD7or4Jat2sHUOOvxEILiUL8/L
         uFow9NAJTvOcyB/8ieBqCJyuOTtQOfDRuiTmMKa9JDzEpkejzGflxisQeTUyJTsedi9I
         JpeM9SgCaPJN9yXrSmPoQ5ay+OvmEC9ruxqEMP38BvD0iTBdLLkcETYsKNuMF29xICbG
         GBo9+g7fzg5cNeQp8SiJ97oBTyLnHlRPcuE18biNXlmzXHiSU5TWmURqHfOlsl9UFcnA
         +YZOL99Wn5+1PcxrnssRmO9l8WP7OFYMWfOXBbzhUcwMnOBK/BttPKbRH9chehdSdSzc
         9A5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=u4Kv9tb0;
       spf=pass (google.com: domain of rppt@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756370278; x=1756975078; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ms9cJwnQQkxiVM7BsBFRhZ709v1PqdVv8Sp54XUAxeQ=;
        b=U0TVKDA+HvimIXR1LCS5q8N7CiQUk5Ai3IFAa+I73n71dr645es0SHBTkaWAqmwcF1
         q6du/ZupFSwfr3JY0zyfrP97RThHBiwUbquW7JIFOK7YpXCnRLsvNDFebp2s2QLjjNGl
         GjOtdZgCOFbt0/PFmPHMuaZcDgnLLFw945WOlzcZFCuM5PWN6kp7l8ZIU2o85nYcsOae
         cD9JvVr41y7Y19VpYLerfwpJCPbEhPEz1gBkN8nZwWlUWrCqqfnAy70+Xz7vbsUG2i/Z
         EHUKP9DFipXuLcF9x6d4p2OEsjGU6eIx42Z26c4ugRz3CZl6M8MZq4xhgGGaFuJo7A5p
         UoFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756370278; x=1756975078;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ms9cJwnQQkxiVM7BsBFRhZ709v1PqdVv8Sp54XUAxeQ=;
        b=geD+c0PCehWnvCavRICtfbChS5hPtfieLkzzXSVFw8mVuAuQzA1kIG17Y447XKLBSt
         4NezqnY3qkptapslNPpdssQiVagWScuH7yvqOLz1/R0CHOG0r6nME57rGgiDDSBxErRj
         dXqz5dSN52BnX+V2ndIa2pG7YZxVM0uEiqNEpohFrVmFycMfLcAlobpssLmm4Q+JXj2Z
         so096HYPlBd3tSQ5QI8CNtxb5SVlwl+QgPc7KzAd4jnu2J2kO8/0aOKlI6foRO7Mm+6L
         I63NcHfPLUO7z7A6da2u6IjYqwOhFKNKs168W/dVVzPvelLhCmcj0LRgigItwV9KvZvV
         m//A==
X-Forwarded-Encrypted: i=2; AJvYcCV0uVGhYUml0fWLiuYrzQJLoewSw7tme4o+yM/Oy4kZRa4YvXcCnp7kVLYqaSH79wx1XDoQXw==@lfdr.de
X-Gm-Message-State: AOJu0YwmYj9WIV8avCRimMKlL3AM3wdOEzBP6TcYrUrraFeeoyaSPqHj
	80nl6xUTb+FrIA3w8udKOWYUhVC18aI+wDZIEvUsENCAj49bl7su15C2
X-Google-Smtp-Source: AGHT+IFmchrdkolv4CboMG4LeuNVVlAyTEp37wSE4IVnzDHIS/xq87Fi+ajxfqQFCB+6hqyy8DL4bw==
X-Received: by 2002:a05:6902:230e:b0:e97:d52:c5d1 with SMTP id 3f1490d57ef6-e970d52d164mr176430276.12.1756370278006;
        Thu, 28 Aug 2025 01:37:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZepPYUXffGnt4Q4LFK2K1t13RkKzYWxlTtX4ZM4Yjl93A==
Received: by 2002:a05:6902:2807:b0:e96:e38f:1a63 with SMTP id
 3f1490d57ef6-e9700f14395ls660588276.1.-pod-prod-06-us; Thu, 28 Aug 2025
 01:37:56 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUfqrxxaJVJRreb1wL083i2EwG7YLlYJQaFqOBejXfCRzxSOdBEg3NDEfXtCME+H3kHs/8UwvgWFtA=@googlegroups.com
X-Received: by 2002:a05:6902:4a87:b0:e97:6e5:2a1 with SMTP id 3f1490d57ef6-e9706e5085amr1029628276.10.1756370276543;
        Thu, 28 Aug 2025 01:37:56 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756370276; cv=none;
        d=google.com; s=arc-20240605;
        b=lZvE8Daft0kKLakm5fbjlqf7QH0Aao/iUeJxMUfS5kDVgJ9mHymN6zKaNel6nD9iGn
         ldAmOgct7Fyve6nfEhTC4xmvCk9GnIwslyqjA1fi7wvcU4LRuXF5JxjHN8lZBeM9vNWB
         9wtAsGwk1s9iOIhQBe5auxPURJYgFt3uSiOTOrgfJXFC9eZj8nasqHn6UCA/OAFd/P/S
         8gWdTSK9rFp3DqVjoAdN/+4OODvvm9cLNH/XsKcI9/MZpHHN+4O6Jz7qtOsjSRyKuwbA
         wJ1HhxJQ6pvz2hc65k9//xrkNHxlYPFUoajeWgZYxsbcAQEOR0LCLQ0q+bROlxxDATur
         0Jyg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=qNeXcIbDUNVZCQgqMueGfXIPkpDwNju3n2hcsJpviO8=;
        fh=9i7Xo3ec5v6Czbc/Gl1AZEKMmN1XodXJiUIITipUCZU=;
        b=VM94JXk98i20uNk0ZWLcb1k1HYLd4FRwW3s6uySfEfMrcvb9WciLMVP3ieuw/00Avj
         EfqUjiSEbXattviwLyswZ1oaBJSLlGdrYFun932G7R0+rVS+WTDWT5WdcqOnhYEJJGbX
         8cAigiBF2cEO7MZMwtBPljZbD1HH0HV0N5PNsUDcxJnnNhQwa/mJeHXfELUQHiEHiTiv
         SktpxE+hMyxrcakFCyOYxwBW5w49+d9hN3nlGBK9XXFVhbIUNQsCvE6hdCTOGvGNpee7
         wCpE09m7ozdxQeCnT2OAjT2VPF9teIoyTY2RSaDnllE1kzOiG4onKm0qS/EpDYGNmtdq
         2SMQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=u4Kv9tb0;
       spf=pass (google.com: domain of rppt@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) smtp.mailfrom=rppt@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [2600:3c04:e001:324:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 3f1490d57ef6-e96d869d159si319506276.3.2025.08.28.01.37.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 01:37:56 -0700 (PDT)
Received-SPF: pass (google.com: domain of rppt@kernel.org designates 2600:3c04:e001:324:0:1991:8:25 as permitted sender) client-ip=2600:3c04:e001:324:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id E943C601D3;
	Thu, 28 Aug 2025 08:37:55 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 836CFC4CEEB;
	Thu, 28 Aug 2025 08:37:41 +0000 (UTC)
Date: Thu, 28 Aug 2025 11:37:37 +0300
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
Message-ID: <aLAVUePBQuz9D89T@kernel.org>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-14-david@redhat.com>
 <aLADXP89cp6hAq0q@kernel.org>
 <377449bd-3c06-4a09-8647-e41354e64b30@redhat.com>
 <aLAN7xS4WQsN6Hpm@kernel.org>
 <6880f125-803d-4eea-88ac-b67fdcc5995d@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <6880f125-803d-4eea-88ac-b67fdcc5995d@redhat.com>
X-Original-Sender: rppt@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=u4Kv9tb0;       spf=pass
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

On Thu, Aug 28, 2025 at 10:18:23AM +0200, David Hildenbrand wrote:
> On 28.08.25 10:06, Mike Rapoport wrote:
> > On Thu, Aug 28, 2025 at 09:44:27AM +0200, David Hildenbrand wrote:
> > > On 28.08.25 09:21, Mike Rapoport wrote:
> > > > On Thu, Aug 28, 2025 at 12:01:17AM +0200, David Hildenbrand wrote:
> > > > > +	/*
> > > > > +	 * We mark all tail pages with memblock_reserved_mark_noinit(),
> > > > > +	 * so these pages are completely uninitialized.
> > > > 
> > > >                                ^ not? ;-)
> > > 
> > > Can you elaborate?
> > 
> > Oh, sorry, I misread "uninitialized".
> > Still, I'd phrase it as
> > 
> > 	/*
> > 	 * We marked all tail pages with memblock_reserved_mark_noinit(),
> > 	 * so we must initialize them here.
> > 	 */
> 
> I prefer what I currently have, but thanks for the review.

No strong feelings, feel free to add

Reviewed-by: Mike Rapoport (Microsoft) <rppt@kernel.org>

-- 
Sincerely yours,
Mike.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aLAVUePBQuz9D89T%40kernel.org.
