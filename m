Return-Path: <kasan-dev+bncBCS5D2F7IUIONU5OYQDBUBHI3EEUK@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33f.google.com (mail-wm1-x33f.google.com [IPv6:2a00:1450:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id E1B26B175AF
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 19:37:44 +0200 (CEST)
Received: by mail-wm1-x33f.google.com with SMTP id 5b1f17b1804b1-455e918d690sf11382715e9.1
        for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 10:37:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753983464; cv=pass;
        d=google.com; s=arc-20240605;
        b=FutY/aH8F9lJLyvZlPYQ35BmsK4+ogX6siMpcNM1spj5aw1LyOgKgSR0PFKSoS5ZSG
         kJ768z7IAd7Z8R9se73moHqPqEZaD/M0GuFMeMQOu4BpHA3czeTYrbZZGlTO/JcuAZ49
         Pq19tu8BNzjr9lgePq2xwLD9TTADSaUImo0PYgM9kDGg/jGfUItZO/6FToNe7/DDFZDY
         cKmAMPzU6eq9sWHNVsi5dQCV7iiK+A3y7Gk5L13LKvzfWgpCy4vnPoSMcrLlA/l5g/YO
         WPlFcKOPdzOmuEraE06XyNZg8zkLdwBZmlvKAWi+P77i1fs8ANaro0gN1WYnSJOgZx3I
         uEHw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=zs7VGHWcpgsToxVy+x0NxN0dD+8E/CXW0b/KpIXUSVY=;
        fh=68kChivJyEVobDhHcu8AmA2WHRzhEMBl6SPWgq3AXzg=;
        b=VGIcSWqGPeTth3HcaNLpru91ZMtRBr3SAjj0y+1ajxZGjF0rJeYARo0BWsKIc/+Fwb
         k0UtS2Y/92cT4azvfa6O8d60R2a4cmPvFeKlzEI30xh8wtax0aa6TcYPUx/doqBJ1K6Q
         KCSTobpYFrDGu3DDFW6Q8DE0O4QsNtgTxs3YmlpXwEVfcoND5U9wAoe5BoZOPvrOJ+23
         JdnBnUht/uDXyIq6CKZpgXAZhUsAiNQIDbqJaF5vzmUBfZvDME+WdzuVODyKQ/ChTjxQ
         TY7Y2JSixRXuHi/C0ui4xGTdGm39dO5ZoC3CLoEeyMrj5TD1ZA9bFUIvMvrZSpb0bWIK
         ImSg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=iKWwh1a8;
       spf=none (google.com: willy@infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753983464; x=1754588264; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zs7VGHWcpgsToxVy+x0NxN0dD+8E/CXW0b/KpIXUSVY=;
        b=vc866ipBWkZD2LcSCXbBDqFspWjBVsVYjmKcM/n4QAFOmFZbjjlLEutU3P/bnW0ngq
         +p59qXRWTYSHC3O6LH7DPTe8MsQLi14HaiVlsHErIL5aOo1VKfqTetCfbKfzpJQV9m5O
         xaSbMVMxo4Sg6DsvaXL7N5ky3qM1at84vhNW59dX5bNDTVgVHqlgKgKxyy/sbidWVMbV
         fkWYVrEvAVc4vHM2HIdcG4F0Onitru8uWGmTbcwkRziBNvS/U5e4ZqbjsvFEn0KfFeHp
         eo0wafz8KOIMsNqfHspKJ9+O37XmWNiQi1tm/q8RSXBBKTGy7csEELaV7HVPss9+U55R
         9ZOw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753983464; x=1754588264;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=zs7VGHWcpgsToxVy+x0NxN0dD+8E/CXW0b/KpIXUSVY=;
        b=sbrpnN+JZL9CpHyyDI6kPNZHvsDPrcLXB87/e2e5X0iFOUdmDD4+mPuIDfgv0Hdjgk
         VMvw8qqn11OCV+6nJZLkGRh+ed8Vs4sByiFONlCFO5tpTp8kIokHofTp9tG5orDcVWbM
         BMrewZ1o31SSTeAleVA2EkNuJk7K1v8BLhblUp6W51DGPl+xZVYWdL6lEdVFvAmy6rpe
         MwFqVxFDr9ccjPC+ZJetiSOqSPYMvDYhvhiE9omIRkzzcM498nl7a7Uak4u9LthhrRDO
         UpXrqWNuDJGuO0rtoskvg4ULOCX+0RrwfdtYE7YCBI4F5SvKw9aBfsbGzt9VUJgxWrwP
         M7BQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV1/jrlueSzND/9pBs1TBaURTi9ZjOtmf1hgwyzOt1uZ9yuGmv0ab05JVP0HCDT/ebwu+OoCQ==@lfdr.de
X-Gm-Message-State: AOJu0YxV+nxqOPdnF8xM6nT4W0zcOJbdYRzIrfBr6YCJ93AhNJGDNqaN
	vrBbXyFMtPe+nd35dx/frROgEQX1EQGq1dnRZjI4IKK8/A3acS9dzBcK
X-Google-Smtp-Source: AGHT+IEp5zdnhoFagonmwSmXvLmMf/zlVm7ZoVraMf0/1FjNCpcOt9fSk/0oq8Y3D8jP9lqViNRz4Q==
X-Received: by 2002:a5d:64c9:0:b0:3b7:94ad:ef50 with SMTP id ffacd0b85a97d-3b79d42068bmr2362187f8f.2.1753983462772;
        Thu, 31 Jul 2025 10:37:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZe0v16u10v2uH5R5h3/Z5PxWyBMjgHqtVOC4MOSS/dCdw==
Received: by 2002:a05:6000:2007:b0:3b5:f09f:4a9f with SMTP id
 ffacd0b85a97d-3b7951d2072ls550844f8f.1.-pod-prod-00-eu-canary; Thu, 31 Jul
 2025 10:37:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWDWsSebdm/7T72rGagCUlBzfehy+eE+PIeOuVmYW55nHfdUPo7U191971W3P/Vt6gdyuOuZMoxh6E=@googlegroups.com
X-Received: by 2002:a05:6000:188c:b0:3a5:8977:e0fd with SMTP id ffacd0b85a97d-3b79d1f809bmr2840560f8f.0.1753983459077;
        Thu, 31 Jul 2025 10:37:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753983459; cv=none;
        d=google.com; s=arc-20240605;
        b=Ix6YQkBgg9mcxQh/b22c2Ls89gyHYlLScQP+i6Xnnn41itkI+8dSl5Ap2ECSCEUvE1
         xQHja/PIYif18tgf9xV/xYCNDE95L9w6cjRPyP+ZdFgtQv/Vl7cSuc+v+PO21stkGC7N
         mENvbjgeO7VfMdCLwSoz/MBax8ezLYZ6F7KqybJ6oIK2GpJr1PEjIqz4hjMFrncn7FUz
         Gbe0yQuypvwUhewabu0td+P2ikAvh5BKOvJEjJ+teEGVqD4JrqXYhFeEUuCfqv5Ylm7R
         H/IkbpqFC+xEHWrbqnAk3Qf/RWQ7Lq3i+TYRXjUjjsQlVgENtaXV19pO1W+mW7cwaRBx
         6Smg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=p81bLGAEXCTve0S2bSlDolWBTWQ0gkC1ozZDbrTl9gw=;
        fh=oAt3CmzDhFh4viFxsurSoo58VZFx2ag9hNGckAnYPCk=;
        b=XdPaaDYjdUz55pJHKvRxUdsYlOu698eoidfI0FHI6X5tFMkvAoL/gvAYwku0cRhQZK
         K/dU+mmn4ZAxpJSG2qQBl99t7ALcRd5Oh6a5tczEkab5F95KD0OgUQNkmKmj10jvOAVf
         rtqxOvVxJZE2zZ+XcTtw5BOOFiAHuUfcYUQZf/SWNsj247vdKW5xdNpUWxo7g+TNuI+B
         vRictdl2u0PbP3tAYjlGJc0VKSTmePhG69Yd7T0S/nxSkD11kH+6jxs9AyYEBRs2klmH
         fpcMDi//nP94XAuR//9GQPKhC0eNv3xx6ppKxJ/GduJumS4I5UA3dVPuSbd0x2KxD//l
         86sA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=casper.20170209 header.b=iKWwh1a8;
       spf=none (google.com: willy@infradead.org does not designate permitted sender hosts) smtp.mailfrom=willy@infradead.org
Received: from casper.infradead.org (casper.infradead.org. [2001:8b0:10b:1236::1])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4588dd3fe52si2622295e9.1.2025.07.31.10.37.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 31 Jul 2025 10:37:39 -0700 (PDT)
Received-SPF: none (google.com: willy@infradead.org does not designate permitted sender hosts) client-ip=2001:8b0:10b:1236::1;
Received: from willy by casper.infradead.org with local (Exim 4.98.2 #2 (Red Hat Linux))
	id 1uhXDL-0000000H6sX-2SDg;
	Thu, 31 Jul 2025 17:37:11 +0000
Date: Thu, 31 Jul 2025 18:37:11 +0100
From: Matthew Wilcox <willy@infradead.org>
To: Robin Murphy <robin.murphy@arm.com>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
	Christoph Hellwig <hch@lst.de>, Leon Romanovsky <leon@kernel.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Joerg Roedel <joro@8bytes.org>, Will Deacon <will@kernel.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	Eugenio =?iso-8859-1?Q?P=E9rez?= <eperezma@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	=?iso-8859-1?B?Suly9G1l?= Glisse <jglisse@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, iommu@lists.linux.dev,
	virtualization@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-trace-kernel@vger.kernel.org, linux-mm@kvack.org,
	Jason Gunthorpe <jgg@ziepe.ca>
Subject: Re: [PATCH 0/8] dma-mapping: migrate to physical address-based API
Message-ID: <aIupx_8vOg8wQh6w@casper.infradead.org>
References: <CGME20250625131920eucas1p271b196cde042bd39ac08fb12beff5baf@eucas1p2.samsung.com>
 <cover.1750854543.git.leon@kernel.org>
 <35df6f2a-0010-41fe-b490-f52693fe4778@samsung.com>
 <20250627170213.GL17401@unreal>
 <20250630133839.GA26981@lst.de>
 <69b177dc-c149-40d3-bbde-3f6bad0efd0e@samsung.com>
 <f912c446-1ae9-4390-9c11-00dce7bf0fd3@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <f912c446-1ae9-4390-9c11-00dce7bf0fd3@arm.com>
X-Original-Sender: willy@infradead.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=casper.20170209 header.b=iKWwh1a8;
       spf=none (google.com: willy@infradead.org does not designate permitted
 sender hosts) smtp.mailfrom=willy@infradead.org
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

Hi Robin,

I don't know the DMA mapping code well and haven't reviewed this
patch set in particular, but I wanted to comment on some of the things
you say here.

> Marek, I'm surprised that even you aren't seeing why that would at best be
> pointless churn. The fundamental design of dma_map_page() operating on
> struct page is that it sits in between alloc_pages() at the caller and
> kmap_atomic() deep down in the DMA API implementation (which also subsumes
> any dependencies on having a kernel virtual address at the implementation
> end). The natural working unit for whatever replaces dma_map_page() will be
> whatever the replacement for alloc_pages() returns, and the replacement for
> kmap_atomic() operates on. Until that exists (and I simply cannot believe it
> would be an unadorned physical address) there cannot be any *meaningful*
> progress made towards removing the struct page dependency from the DMA API.
> If there is also a goal to kill off highmem before then, then logically we
> should just wait for that to land, then revert back to dma_map_single()
> being the first-class interface, and dma_map_page() can turn into a trivial
> page_to_virt() wrapper for the long tail of caller conversions.

While I'm sure we'd all love to kill off highmem, that's not a realistic
goal for another ten years or so.  There are meaningful improvements we
can make, for example pulling page tables out of highmem, but we need to
keep file data and anonymous memory in highmem, so we'll need to support
DMA to highmem for the foreseeable future.

The replacement for kmap_atomic() is already here -- it's
kmap_(atomic|local)_pfn().  If a simple wrapper like kmap_local_phys()
would make this more palatable, that would be fine by me.  Might save
a bit of messing around with calculating offsets in each caller.

As far as replacing alloc_pages() goes, some callers will still use
alloc_pages().  Others will use folio_alloc() or have used kmalloc().
Or maybe the caller won't have used any kind of page allocation because
they're doing I/O to something that isn't part of Linux's memory at all.
Part of the Grand Plan here is for Linux to catch up with Xen's ability
to do I/O to guests without allocating struct pages for every page of
memory in the guests.

You say that a physical address will need some adornment -- can you
elaborate on that for me?  It may be that I'm missing something
important here.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aIupx_8vOg8wQh6w%40casper.infradead.org.
