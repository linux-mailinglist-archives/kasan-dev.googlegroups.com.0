Return-Path: <kasan-dev+bncBC3ZLA5BYIFBB5FJ5TCQMGQEH3EXY6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf40.google.com (mail-qv1-xf40.google.com [IPv6:2607:f8b0:4864:20::f40])
	by mail.lfdr.de (Postfix) with ESMTPS id 1C813B45F50
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Sep 2025 18:51:02 +0200 (CEST)
Received: by mail-qv1-xf40.google.com with SMTP id 6a1803df08f44-71fe8dd89c6sf45166076d6.2
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Sep 2025 09:51:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757091061; cv=pass;
        d=google.com; s=arc-20240605;
        b=TI9sdAN1Up12ERXS3eH/eo2zx4h6G8fVQGG5cogiBxwWoUNlvT+bWHmQG4ekrqczp3
         t8+DK7KqAod2y33nKLeHfRPFywGUpGjcml74j++HvPebH2UqNEMZx1tBgCMvueQaQlcS
         N9Epye2CY3OjbYqCnUwJ+rouG1QzSaj8dry0UgIy8xl9143D8vsfKGILGC6eVVn2B0Gv
         dcWOU84NLyN7Q5Xs4ur6jyWYkY5/hzbBc3augcv2IXUrq3cun7GQHW38v08Pf0PcvdEc
         y3dVhwAWyultjRLvWNxr8E+zA9WB0vLr6Aze7Fl2yAMLQ9rFcryTJ0egtPkKRGaLoaA0
         nlaw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=3CH8j+xRnO6p4AYlfHFoo7wQHm/wctwp0Q0r25URLfk=;
        fh=n+0t61Wa9MU43CEKgvISXQFgZ3jEIkjTWEdDtO8eI3Y=;
        b=Xc7K1Y0gEo99Doky1b/F2Ghpo33zhepS+W/Ft+AkvK0cm2b9Abu/94kNoYBh0H4FiS
         6DboNaZDLPiKN9xLC7m3KbIYH+scY+pS87EWsB3JKU3OKXEz5mPBXGaMYVLE+jmK6JzC
         IQlcqqiulec897AkNMSvD3VzvbDCVinkhHuOuHcEdV7beUfpoRfC/S32b5fGU6GFy7iQ
         zg7CFMlHI4nzZvKXllx2kHlHORcUkMg12WAVLobmz/bpOn4b+spvGZIh9qxRrlbq1hoA
         9YtA/zpM7w/A0hxGGcpQxPEV2M7hjqyCGZrgslzziHX4GJsC7m8qIaTOSphDbDcnd7ZY
         nJlw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Hkj6jwvL;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757091061; x=1757695861; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=3CH8j+xRnO6p4AYlfHFoo7wQHm/wctwp0Q0r25URLfk=;
        b=h8RGXfsMq98M9OfQL8iSULqfjcdGz1VRcGS+s0QdPk8noMvdNN2mne+F7m0EE1tffj
         98BTCm3PRtybxdYinz5V+18EAAuWAjXhT5JOMTheluS77EDDNhLqXnqjabejRvt64cv4
         IjTuwYbZA6/VeRHulHaLWhWLDsK3RgQUKQojPPTqCTTqLMennRMosXXAuDdLBJwSen5N
         lR9xVpcOhbjyCzwKQjoMnY5t6bz6NnRnTXrgnubRgQkF+StfIWS130VjZslppA1yZhnM
         cbNfAdFjmVgiuj9eEifxvgespCutZtGDsUCWrFp/uugwdJoYSMIUcjsu2VZTxDKLhEfj
         IfLQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757091061; x=1757695861;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=3CH8j+xRnO6p4AYlfHFoo7wQHm/wctwp0Q0r25URLfk=;
        b=v+Qg6GrdZl4x818cD0nEFwlyUJLqeeGvaa/vpb1kYjK6v9BYnPIm239W+/gkA9Bzds
         HIY6Uj5k5vQM16DGouq/nR0IzFPklJxgW59nUzmypNsH/xqBkAgrY0qe1FGZJmAkjiVx
         CtK0rE0iMR5A2Ga6qPfzpa7DbFS35J5tW7QMHkAlg3wOonp+ycgChW6gwtPDfAipx3A2
         rK5tJlJB1fmDaY7BjU04sfQ5Ks7+hNp9NUG7qe8LEM7dAXXlkb4FXDsqIE6ZerLsibPC
         tH+Bko6rGNPj5s6BeuxoKg8SuousODGBRVwDGIuKD5R60lCwPhcgo+VAA9soJuwOie0q
         Z+jg==
X-Forwarded-Encrypted: i=2; AJvYcCVo9RLzO1oCBhE337zpeFr/aJofOsKkILs9GvslCGEhtAsvRwjDSajWAT6mvL6XnNjO5Yvjxg==@lfdr.de
X-Gm-Message-State: AOJu0Yzd2RZ9b66QCaZRGBoPIfsGX1kxTNOfKTIIa/JMrt6rmARXnBFW
	kQHEPMhM68e4ENwbOsRbyGKQ9uWIbNzt3jhHNCCB46g3OtgejTwc1ds6
X-Google-Smtp-Source: AGHT+IHswjDCjuNYGEo2dtvOweaUbMHPJj2lX30MdBk/S6R0la1Tn4LvJ6fq2vOUBrynIsaRZokiGQ==
X-Received: by 2002:a05:6214:2466:b0:72c:cc04:c3b1 with SMTP id 6a1803df08f44-72ccc04c56amr32206386d6.0.1757091060652;
        Fri, 05 Sep 2025 09:51:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZenOd7mgtjd6ddXGIe/OExFVbFqg2DWaiAnYnAp2C6UMQ==
Received: by 2002:a05:6214:c82:b0:70d:bc98:89ea with SMTP id
 6a1803df08f44-72d3cbab092ls10836636d6.2.-pod-prod-09-us; Fri, 05 Sep 2025
 09:50:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWHApcNQeEC4g2ApvcFxuOjJd9t6ZWIF35YR4K0PpTPMpTXcq0yXgW9Q6d5P5C1JocixlSN8JeCMtw=@googlegroups.com
X-Received: by 2002:a05:6122:3d06:b0:542:59a2:72fb with SMTP id 71dfb90a1353d-544a02b1510mr8808317e0c.9.1757091059101;
        Fri, 05 Sep 2025 09:50:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757091059; cv=none;
        d=google.com; s=arc-20240605;
        b=lsVCdO4jxJIFfBEJY2iZPqGg12KliEEUsY9hWicWkMh7KNeouswSraCWJo+LCvoNjc
         taVyq3/WVs2Z5GWx6+N4KnUqC+dYKFbOsurkG5eN/el6HdAQnMUs4Gkg1950BK5Ly/VQ
         Zlhq/3Zs8SNmTpzaRxcOqjB60Bz/ERqsA8YTIjUC7+KLPmrvIbHGwUbaqxIcwWt03Ez9
         bbbsq4ID87j7F/DHfwQNOZFJyZlO+Vxcv2BAveke81SnXr7+XzH855Gxw+jnKmmPRGPp
         gWVWYon3tb4fuhBV3cs0oI3fFIZwG+HDZz0uTiYH8ZQQ9fBlwSKk/8tGDuH4ghLYeyt6
         YDIQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=jPSEH+AzhLnejyJgvUoX+DOy/Gpz5ytBdInrHhyhk2g=;
        fh=0KZfjkVFrBJ1A8P/k5PTY2PAUr+/l0FquzWeYmXM7tg=;
        b=cLN92uxlmDApXzC8GAhKV0bhwru8ube4//wMAA4j2T5meypXCFNN3JiiuL0PPqrFeU
         GGguuQaC6zodzxx/PSzcgAS2fDvL3jMobNSUkpYiWvhNZOkkie1IoWaQgErt8cYHrVRi
         VmhNPfIgh723noLvqLKYPBoxtRf/zoMggVRcdaGS5/CMBdpy1vrvrITSiLpJyTKWWSeg
         zkR36tdb5MpHA0kd/oriynXSOKQVnH5ctmCEd7dBzQUYqVgvY78DNuSNoF19ofikSTcu
         +bxDn/ztmJHdCUUsmSmUc3ES9oImyuB/8WwZOjOLmFXWiYvGQzvi+cZO3khNzvI8FP1s
         iAzw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Hkj6jwvL;
       spf=pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-544914717b4si844418e0c.3.2025.09.05.09.50.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 05 Sep 2025 09:50:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 1C43F43A6C;
	Fri,  5 Sep 2025 16:50:58 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 291F0C4CEF1;
	Fri,  5 Sep 2025 16:50:57 +0000 (UTC)
Date: Fri, 5 Sep 2025 19:50:51 +0300
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Jason Gunthorpe <jgg@nvidia.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	David Hildenbrand <david@redhat.com>, iommu@lists.linux.dev,
	Jason Wang <jasowang@redhat.com>, Jens Axboe <axboe@kernel.dk>,
	Joerg Roedel <joro@8bytes.org>, Jonathan Corbet <corbet@lwn.net>,
	Juergen Gross <jgross@suse.com>, kasan-dev@googlegroups.com,
	Keith Busch <kbusch@kernel.org>, linux-block@vger.kernel.org,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-nvme@lists.infradead.org,
	linuxppc-dev@lists.ozlabs.org, linux-trace-kernel@vger.kernel.org,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Michael Ellerman <mpe@ellerman.id.au>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Robin Murphy <robin.murphy@arm.com>, rust-for-linux@vger.kernel.org,
	Sagi Grimberg <sagi@grimberg.me>,
	Stefano Stabellini <sstabellini@kernel.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	virtualization@lists.linux.dev, Will Deacon <will@kernel.org>,
	xen-devel@lists.xenproject.org
Subject: Re: [PATCH v5 07/16] dma-mapping: convert dma_direct_*map_page to be
 phys_addr_t based
Message-ID: <20250905165051.GA25881@unreal>
References: <cover.1756822782.git.leon@kernel.org>
 <CGME20250902144935eucas1p253de9e94315de54325cc61dea9c76490@eucas1p2.samsung.com>
 <6b2f4cb436c98d6342db69e965a5621707b9711f.1756822782.git.leon@kernel.org>
 <087e7f3d-1e0d-4efe-822f-72d16d161a60@samsung.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <087e7f3d-1e0d-4efe-822f-72d16d161a60@samsung.com>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Hkj6jwvL;       spf=pass
 (google.com: domain of leon@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Leon Romanovsky <leon@kernel.org>
Reply-To: Leon Romanovsky <leon@kernel.org>
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

On Fri, Sep 05, 2025 at 06:21:44PM +0200, Marek Szyprowski wrote:
> On 02.09.2025 16:48, Leon Romanovsky wrote:
> > From: Leon Romanovsky <leonro@nvidia.com>
> >
> > Convert the DMA direct mapping functions to accept physical addresses
> > directly instead of page+offset parameters. The functions were already
> > operating on physical addresses internally, so this change eliminates
> > the redundant page-to-physical conversion at the API boundary.
> >
> > The functions dma_direct_map_page() and dma_direct_unmap_page() are
> > renamed to dma_direct_map_phys() and dma_direct_unmap_phys() respectively,
> > with their calling convention changed from (struct page *page,
> > unsigned long offset) to (phys_addr_t phys).
> >
> > Architecture-specific functions arch_dma_map_page_direct() and
> > arch_dma_unmap_page_direct() are similarly renamed to
> > arch_dma_map_phys_direct() and arch_dma_unmap_phys_direct().
> >
> > The is_pci_p2pdma_page() checks are replaced with DMA_ATTR_MMIO checks
> > to allow integration with dma_direct_map_resource and dma_direct_map_phys()
> > is extended to support MMIO path either.
> >
> > Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
> > Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
> > ---
> >   arch/powerpc/kernel/dma-iommu.c |  4 +--
> >   include/linux/dma-map-ops.h     |  8 ++---
> >   kernel/dma/direct.c             |  6 ++--
> >   kernel/dma/direct.h             | 57 +++++++++++++++++++++------------
> >   kernel/dma/mapping.c            |  8 ++---
> >   5 files changed, 49 insertions(+), 34 deletions(-)

<...>

> > -	if (unlikely(!dma_capable(dev, dma_addr, size, true)) ||
> > -	    dma_kmalloc_needs_bounce(dev, size, dir)) {
> > -		if (is_pci_p2pdma_page(page))
> > -			return DMA_MAPPING_ERROR;
> > -		if (is_swiotlb_active(dev))
> > -			return swiotlb_map(dev, phys, size, dir, attrs);
> > -
> > -		dev_WARN_ONCE(dev, 1,
> > -			     "DMA addr %pad+%zu overflow (mask %llx, bus limit %llx).\n",
> > -			     &dma_addr, size, *dev->dma_mask, dev->bus_dma_limit);
> > -		return DMA_MAPPING_ERROR;
> > +	if (attrs & DMA_ATTR_MMIO) {
> > +		dma_addr = phys;
> > +		if (unlikely(dma_capable(dev, dma_addr, size, false)))
> 
> "!dma_capable(dev, dma_addr, size, false)" in the above line.
> 
> It took me a while to find this after noticing that this patchset breaks booting some of me test systems.

Ohh, sorry, I overlooked it. Do you expect from me v6?

Thanks

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250905165051.GA25881%40unreal.
