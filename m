Return-Path: <kasan-dev+bncBDK6PCW6XEBBBEXFW3CQMGQEXS4BY3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 81169B361B1
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 15:11:48 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-70d9a65c170sf87428126d6.2
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 06:11:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756213907; cv=pass;
        d=google.com; s=arc-20240605;
        b=BTfUPsOrfIv5hdC/sysvih7mg7Ai/oEWb75o4BWmKV3cyao/rKZftA3w0I2JNO+JQs
         KvOmpCU44kXep1CDsbj1rG3YAQgdQ8j7tMnBeCDAYWNrRpyoYnyYcPuq7RtyeQ9yJTV+
         GiNtkZ7Pymzv244kJjq0ezjmThOojI3UuudzW3PRuVSWYbtodsyP8yAxrilatW3bCGdL
         2886ZGnlzlI5mY7/r7qGrDppJin3R5r7+W2xbSOaD2wRNxQ4QDM3Fafxlxd1Uj+gniBT
         TuKAD19DHEVz7Xp7TZd670aEzA8YrSYGv5dGiey0Hd0fJKyaaWotqj7QBoJofWo+3z+p
         mp5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=gLC/rj11b4rDzw1NBK4yTNFwmwalYAgDQ6vx9zgRVWc=;
        fh=lQuDdptVnYYl10rPJy5GnYuTvUHjIXRrlYvJabNzhmo=;
        b=jcmlmW8Xr4jyjo0yuMG2MEdTut4dl+KH9hxetRDbQ9VhCOM7bQGobTF7aG0nJoRNJg
         JXrB6LGA+/oRMBzpKeciYlqWagryv4poZDT8p1GsuKpuVIxgxGLcb80UkPGBzkJTtaOL
         ZlWf+jj4vsFI+/ouyRIVfbdf2jks4YH1JvDaA41Rb7xuDibSTxV2yuTTnUCJaQvR48z8
         IbOd66/6j4Vjslb4977OXeMCpitUn11bLMV48B0kYJNL6tGsz3Ph3Sbnxg2taQ1+oJsQ
         0snRvhz9XhsG1Jku2MSFXZht2UqG7ZNCLl7KmXSDptiZdKJEqJYCA4evdz13QQCboW+n
         delw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of alexandru.elisei@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=alexandru.elisei@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756213907; x=1756818707; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gLC/rj11b4rDzw1NBK4yTNFwmwalYAgDQ6vx9zgRVWc=;
        b=XV4WMDnvaT4vnBfs1e/ElnbvU+wabkURUSlNTTqaUdgV91n0kRrWs6D7zPedRJSmR8
         zyartWt0nuVszMak0Q0IQrbZtTAgApXwdvlONQaJFDTYlw+aUxL7zG6yn9qWGWOX0iks
         JsMnqtamuA9+5AlEGeF5AKaB/XG7v7zE4RDRPzfcpSM4xq8L3FSXDBXVxMeq5QVX6red
         TSkjK6PCHfcI3yFnklvQZHMl7hWBHibjf+dpBnQYLQ+wvEwWp55pmDeKQmKTS3bRyWeh
         gLb37pfZD4snZCCE1r849oZYP/YIb6vR/7IRoMvVl8yG/Y8LhE7F4RamdY/yj8vbnNsM
         6j0g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756213907; x=1756818707;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=gLC/rj11b4rDzw1NBK4yTNFwmwalYAgDQ6vx9zgRVWc=;
        b=uVgrWmJ2Qrsh8W+2AuRfr+SBdDyH8/wRiGOoD//Omy6SG24H/3Yf0SA/4yf2CL3vwL
         pFsSmkp0O6hvTtb/soNhk+PXE3rdnloCrzN/zBak51PB17gyYZmkIxcH6gLluhkmRG0M
         Xyu/pL9Azt4C2++8c6HrPsSpw99YLTet2dhpVzpQ2vlkbnE30snhBCYQKw8ZzskJMUPE
         8JT9YooklaN1ypmwMrPmXU0J78ctIW6zzobJwvQfRHSfHIi7PeLsmNbUNK+NFZhWLnFS
         5MI6OYNFKx7tbLwV1bURAu9zbxx9t+0xIWUk7vXv8C3yMxHP7E3OA3pzIDILlhXhmdyC
         810A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUqznyrI2ID5tJOXwTCvHXnr9GX/Z40cQtiTNZw2vKY1kZ7EyoMF7yLjjYhuLOxu9MD9QEthA==@lfdr.de
X-Gm-Message-State: AOJu0Yy6fYsvB+yzVWDBZ5WutHTf9CWlO0vVbugVgoxeN8temEGwXMjD
	Elg5T6Mao7u/t0SwXJtqgutCSW78XGhk9pYSBGlDmV4ruEvsxkAzei8Y
X-Google-Smtp-Source: AGHT+IH4dYmbIQek4DvKoR92AyZZBzlVbzBEfaeaayaq34lWUfVjudAUPDF5pdkzu7s7zsszXcA3xw==
X-Received: by 2002:a05:6214:2626:b0:70d:beed:b352 with SMTP id 6a1803df08f44-70dbeedb706mr70512916d6.32.1756213907150;
        Tue, 26 Aug 2025 06:11:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe7BGzEXnReRx9p6iz5DtRp67lnGSvDQ1XRpe7hC97SMg==
Received: by 2002:a0c:f097:0:10b0:70d:9938:5606 with SMTP id
 6a1803df08f44-70d99385acfls41417616d6.1.-pod-prod-05-us; Tue, 26 Aug 2025
 06:11:45 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXTLcB6OdEHS1arhbX5Xt2JyZM03Gid0cQLd+04Jn7OzouHlNPLVdrSYGUUOpmmztteBUQSo1xiK6Q=@googlegroups.com
X-Received: by 2002:a05:6214:6211:b0:70d:9e0a:5ab1 with SMTP id 6a1803df08f44-70d9e0a5f2dmr103473506d6.22.1756213905673;
        Tue, 26 Aug 2025 06:11:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756213905; cv=none;
        d=google.com; s=arc-20240605;
        b=DxCV9m/czjBo04DsoXEA3qa6ALtY32Sqa10N81EX5aiCtOh6qf4FIgn1SfwHJHgIiC
         bUZHantif4kz3pP/dQiEExIY87juf9+lZOPLHZ+tFpBwB3m3K0ULcda/QnqBZHSP1Xm9
         jmso7q3GJqY9kg//rCx2Abou7TKvvGuqRfHpPT1VqQo17jTBHfFWXY74QI7mJKSH/LJH
         wUi2gMWFYQeSH+bXFAtX13BdFVSOGifVV5+20LZ3XJJ20GBIKfb1SGhxuCp1hj60K/jx
         2aGDvAKuauxIhM9ICoKgYb/CpUM62XijqezmUNVWgQOF2AedtlKO7zJY4aukaHw4uXPx
         4WuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=o0dIKLq7mMxlWwZyWFQYffTfikp/TwVGT+xrqhNBlKs=;
        fh=vX6gO3pliJpm/AGrWIy9cYz9F3J0yH3JYHwS9n457z8=;
        b=byh8j4jWjekx1AIODLuqZ/a6kgoX7TZ8WcwocPy35mpePIWXwh+RykAfQlDKHFNsCq
         bsFBqNP+z0BGwGzEeXJtcVW4BmBVKq/S8C/utYkVxhkz0PosEKrOG0uPjmunKgs4mNjK
         le5+lbSQ3xkSIb6rvZ0fCjA/F81b2lVf+dOwduNmxsJNevnDqJPwlxzAzBmyPZofzJzD
         PuWGV7dZa2c6XccTyZut+l7jDEMjmY9+szDvKZsX/VNdTQIkt7w2vo/Lc1yF7XWFUMGC
         XsPQn4ICVo5qBqsuXhKU6ia5v7cM0ry6YLbS0NKGEC2jozmayk+cn9BU4AiI0YmvDzS4
         6IyA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of alexandru.elisei@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=alexandru.elisei@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id 6a1803df08f44-70dc547bfe2si1977836d6.1.2025.08.26.06.11.45
        for <kasan-dev@googlegroups.com>;
        Tue, 26 Aug 2025 06:11:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandru.elisei@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 7C1B82BF2;
	Tue, 26 Aug 2025 06:11:36 -0700 (PDT)
Received: from raptor (usa-sjc-mx-foss1.foss.arm.com [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id 0B7A13F63F;
	Tue, 26 Aug 2025 06:11:36 -0700 (PDT)
Date: Tue, 26 Aug 2025 14:11:34 +0100
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
Message-ID: <aK2yhtQ0M_0hqQHh@raptor>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-22-david@redhat.com>
 <aK2QZnzS1ErHK5tP@raptor>
 <ad521f4f-47aa-4728-916f-3704bf01f770@redhat.com>
 <aK2wlGYvCaFQXzBm@raptor>
 <ecc599ee-4175-4356-ab66-1d76a75f44f7@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ecc599ee-4175-4356-ab66-1d76a75f44f7@redhat.com>
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

On Tue, Aug 26, 2025 at 03:08:08PM +0200, David Hildenbrand wrote:
> On 26.08.25 15:03, Alexandru Elisei wrote:
> > Hi David,
> > 
> > On Tue, Aug 26, 2025 at 01:04:33PM +0200, David Hildenbrand wrote:
> > ..
> > > > Just so I can better understand the problem being fixed, I guess you can have
> > > > two consecutive pfns with non-consecutive associated struct page if you have two
> > > > adjacent memory sections spanning the same physical memory region, is that
> > > > correct?
> > > 
> > > Exactly. Essentially on SPARSEMEM without SPARSEMEM_VMEMMAP it is not
> > > guaranteed that
> > > 
> > > 	pfn_to_page(pfn + 1) == pfn_to_page(pfn) + 1
> > > 
> > > when we cross memory section boundaries.
> > > 
> > > It can be the case for early boot memory if we allocated consecutive areas
> > > from memblock when allocating the memmap (struct pages) per memory section,
> > > but it's not guaranteed.
> > 
> > Thank you for the explanation, but I'm a bit confused by the last paragraph. I
> > think what you're saying is that we can also have the reverse problem, where
> > consecutive struct page * represent non-consecutive pfns, because memmap
> > allocations happened to return consecutive virtual addresses, is that right?
> 
> Exactly, that's something we have to deal with elsewhere [1]. For this code,
> it's not a problem because we always allocate a contiguous PFN range.
> 
> > 
> > If that's correct, I don't think that's the case for CMA, which deals out
> > contiguous physical memory. Or were you just trying to explain the other side of
> > the problem, and I'm just overthinking it?
> 
> The latter :)

Ok, sorry for the noise then, and thank you for educating me.

Alex

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aK2yhtQ0M_0hqQHh%40raptor.
