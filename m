Return-Path: <kasan-dev+bncBDK6PCW6XEBBBIHBW3CQMGQECGONX3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3E601B360B8
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 15:03:30 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id ca18e2360f4ac-886e3babe16sf401281139f.1
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 06:03:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756213408; cv=pass;
        d=google.com; s=arc-20240605;
        b=ROdnxIbI6fm4CsOWr98FRQC9K2/2rBQPpkZ5k49jOStT67PO91EYqsJI5IQa5B4QuS
         QkZ2XsAUt7lsEPwNZr1tdLGPQlF292K9LNkvMPxzt2QqcLtdE2f0Q7uh4tJEBF5gbf1K
         moYTXjFwWhRc0947E+pMe1/zjX4+cRsgPnhG/EUUZDrfeT0xzQUS/YJTGXkj9vm3yDJq
         ClR/xbSELsjU6CagkE5DS1qPaMveAj9UFNEjpUN2SZfptl2DkbwaUT5RfB4siifqf8m5
         xpZYykaEpUuRPqTD0Ip2Kce8QJWv7e1IndDK8oU/eKhfVr4zZY5LBCSFHCaGPBUP132W
         Zvtg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=pVz8oOfJVytkkoz7BiX1pYbSqbMWJ30wJ/be6SdvMg0=;
        fh=EMuKKNdo8Ztgmmw4YNmDkGXNdB+864znsyNIXegIstw=;
        b=cV/qNP7LGsr7MgABFi2DSn4qE07f8TomHFTlBudFhKGiBBHj2lC+glkVcboEv79XA5
         upZn/vRJ0SKwFpoeFroykOiosuokBNosngzfNLHk0z1klV8u7VvqEreMI7dinwprvf7z
         SD6dj6tKv5KftVkXq3Uw3X1ODeggyfTTGLmLxIr+g1qY6Tcn3joqoyUaZAGw0Oc2pF1L
         014di1Br4wuTDHeuTIgmPmS25IrYQN2t8AFmwc+nZuafHVBYBQFWZ6Bdy0WmIqmZIHh7
         p5jyPgDYCfomrA2+AjToJmnP+SdCXmHFmZVR19yDlYLPXsMZOgS7r2SIgfhJKRla80z3
         H2QA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of alexandru.elisei@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=alexandru.elisei@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756213408; x=1756818208; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pVz8oOfJVytkkoz7BiX1pYbSqbMWJ30wJ/be6SdvMg0=;
        b=fsDLVk1Svvp0U2WMCuYPxwu6xn4c+v/OaD95lbvbuHjaeaGO22wW7Y8wMKme0bPLTd
         47HLq4KE+ZGypyWWs9s2zSS6BwpHQkf/tvLsgDA0XELeQ6EsZcsVfgpwctbw4KVsfUIw
         9vczQ6IImFmB6OiXL2eUjFhmdxySKbbJwGxuLMTWnAKDAMRglM+1bF3dboKqcUDlwchH
         vJ4ts0+Ls0MY8F2vhUz7pQn6q4FKnBHFncEuSZG1T167i2AZyJCqxAxcGMBdGbFxA4Ak
         1Z8Dy351LwTjCRBP9Of+GWZnwFV5zMHoQRDlZUij9qFtIR4yEJee/c6PcxNrWXXUbNAX
         bHJw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756213408; x=1756818208;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=pVz8oOfJVytkkoz7BiX1pYbSqbMWJ30wJ/be6SdvMg0=;
        b=Whk9qwlcsh6eTsBI+bMHFVWuB6KY8f9pdBzQAzzPrp9wR2Zti4QihuTiZkRKBf18Dj
         ZNFdagOkXXBhhGwRbsXP1ckWdhRRVendw4xThOZBwCOl7kAOVN8UgGifdKTE2XJmOIsI
         c6e/sb6UvRV0er4ARfp82csP3k3gROy2shReF/yeF77+kySG1pgoQlrRXqi8cz+4klLt
         WJ03Np5O31XUVT2Q7aVcA1gJaHiW7QxpxIoeJIO8MI6B29RG+yfAtjzVYtD3WnHELHjX
         /PXn5b5kv2Iwf7zofkHbQFSpq+YPoRdgPi86VybkCPjRdNhSC0XX3T1uZmJY9e74xyEj
         hnhw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCURK8KKmUAyXKspFYmSr6ButKj8RaDlUC0prnRRuN1yWbIs5l9UcHikVVt7zhxHplHlUNk9/g==@lfdr.de
X-Gm-Message-State: AOJu0YzORg0UuFLOjSxtd8A6ZA0/w+0EYI8cgbf1PZROop7WsefD62BF
	ZlU1YCxpyXB/nEsbw3OXizDgg+Rrjp4xs3H3TelQfjHdPql35Jtt44EZ
X-Google-Smtp-Source: AGHT+IHwJgKMF4kfIVuzEi56pSXrtqkYoCPIY95k0rY4Y0ypi3UVSoapBdDENpo11vxshVrdZ2nntw==
X-Received: by 2002:a05:6e02:1749:b0:3ee:3ac4:defc with SMTP id e9e14a558f8ab-3ee3ac4e010mr51964235ab.16.1756213408338;
        Tue, 26 Aug 2025 06:03:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZc4GZuEfluIciQ3JZ5V/VjTqWecmuQpxIZGpLIi9EoAhg==
Received: by 2002:a05:6e02:4811:b0:3df:1573:75d5 with SMTP id
 e9e14a558f8ab-3e6835fdcfals58457715ab.2.-pod-prod-02-us; Tue, 26 Aug 2025
 06:03:27 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV/S76oZBRzJmrmKueViCng8p+BhOAjK4ePFpW50vDiDdxLd0A9qC0SC1U5colNsGZuSC/1dYLjPBQ=@googlegroups.com
X-Received: by 2002:a6b:5908:0:b0:883:2cef:b95e with SMTP id ca18e2360f4ac-886bd1d2838mr1625573039f.10.1756213407005;
        Tue, 26 Aug 2025 06:03:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756213406; cv=none;
        d=google.com; s=arc-20240605;
        b=B7bG28Db2BBnEJpvGhw8wA0hl9HJ6Dv+aCCgaW5GqqQXAkQ2936lL2WFAdJZDMHftU
         0cJ4+RZrtMgnDatWaHR8GaE/wrMaMAEm8nrFxWi0dvcbZIe/zjtCLUtMgpvyGGmFNaBw
         T1nLhe1Yfi3eN7sbRjg4YI+BwU3PfQNXxPN/BcPiYrAXM8GuuBu5oukojppk5dVJ6iTl
         vpZSIKNV09vOaLhfr3bwvI1EGmTxTmdB6cP6xIX+x4b29cHXy17i5FHRI76cq9HADai5
         Hyxh9flmq7npRaryKMkm73RSuORTvVv3ib7F7+xcdrDTfHruyT86UOCtAZiPAADFdLiI
         0+Pg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date;
        bh=1O/zM1zKzZOQIR19miejrCk4D8ib53PTjy+21WtrmDk=;
        fh=vX6gO3pliJpm/AGrWIy9cYz9F3J0yH3JYHwS9n457z8=;
        b=a3p5L1T5oVM3Iz9QNiLaUzT6Ok+9SO7H1Rw32OvAUpiBWWzJyt2Xcudq1WGFxWex8V
         1KNphg/bXESvIEw1vQ8vdX2Pbkns8/21kbSeByQv8R92aN8kxn/7axwA2kaQuewkxyFB
         SsyIb/XWe3rdJvBNLgMrOS5s5KvHxvlNA2RPD8PaPua5AEqb/JQdHjATfzCU5WWuOATE
         YG9CYWc326eSkfTpWPE1NcwaQFTKARVKJF2xAEEFX3pm/e3iqg12gF59UDG4n6zxjEtJ
         K796jKUgcNCCV+7ge902GHayJQ1/2q3dVw0wHKoOnjcwoUr/QwIzTo0G89pRwmalmjIe
         lFbA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of alexandru.elisei@arm.com designates 217.140.110.172 as permitted sender) smtp.mailfrom=alexandru.elisei@arm.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from foss.arm.com (foss.arm.com. [217.140.110.172])
        by gmr-mx.google.com with ESMTP id ca18e2360f4ac-886c8f6a8c8si38218839f.2.2025.08.26.06.03.26
        for <kasan-dev@googlegroups.com>;
        Tue, 26 Aug 2025 06:03:26 -0700 (PDT)
Received-SPF: pass (google.com: domain of alexandru.elisei@arm.com designates 217.140.110.172 as permitted sender) client-ip=217.140.110.172;
Received: from usa-sjc-imap-foss1.foss.arm.com (unknown [10.121.207.14])
	by usa-sjc-mx-foss1.foss.arm.com (Postfix) with ESMTP id 025E02C23;
	Tue, 26 Aug 2025 06:03:18 -0700 (PDT)
Received: from raptor (usa-sjc-mx-foss1.foss.arm.com [172.31.20.19])
	by usa-sjc-imap-foss1.foss.arm.com (Postfix) with ESMTPSA id A5B423F63F;
	Tue, 26 Aug 2025 06:03:19 -0700 (PDT)
Date: Tue, 26 Aug 2025 14:03:16 +0100
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
Message-ID: <aK2wlGYvCaFQXzBm@raptor>
References: <20250821200701.1329277-1-david@redhat.com>
 <20250821200701.1329277-22-david@redhat.com>
 <aK2QZnzS1ErHK5tP@raptor>
 <ad521f4f-47aa-4728-916f-3704bf01f770@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <ad521f4f-47aa-4728-916f-3704bf01f770@redhat.com>
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

On Tue, Aug 26, 2025 at 01:04:33PM +0200, David Hildenbrand wrote:
..
> > Just so I can better understand the problem being fixed, I guess you can have
> > two consecutive pfns with non-consecutive associated struct page if you have two
> > adjacent memory sections spanning the same physical memory region, is that
> > correct?
> 
> Exactly. Essentially on SPARSEMEM without SPARSEMEM_VMEMMAP it is not
> guaranteed that
> 
> 	pfn_to_page(pfn + 1) == pfn_to_page(pfn) + 1
> 
> when we cross memory section boundaries.
> 
> It can be the case for early boot memory if we allocated consecutive areas
> from memblock when allocating the memmap (struct pages) per memory section,
> but it's not guaranteed.

Thank you for the explanation, but I'm a bit confused by the last paragraph. I
think what you're saying is that we can also have the reverse problem, where
consecutive struct page * represent non-consecutive pfns, because memmap
allocations happened to return consecutive virtual addresses, is that right?

If that's correct, I don't think that's the case for CMA, which deals out
contiguous physical memory. Or were you just trying to explain the other side of
the problem, and I'm just overthinking it?

Thanks,
Alex

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aK2wlGYvCaFQXzBm%40raptor.
