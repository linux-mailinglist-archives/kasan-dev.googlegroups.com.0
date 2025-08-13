Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBLOU6LCAMGQEQR4JUEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id E917AB24CD3
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 17:07:27 +0200 (CEST)
Received: by mail-pf1-x438.google.com with SMTP id d2e1a72fcca58-76e26746008sf486662b3a.3
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Aug 2025 08:07:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755097646; cv=pass;
        d=google.com; s=arc-20240605;
        b=O3LAvvMqRJF7sDNUervmEOPAU+FX+T6SJuM13qnZHabBfCZOfJpru5iqWroAwWpvVS
         V3oplyhxs1Rrlu/yisnu803pa/coTDuFkTfKxaeunwsMPvnY3U+t9Vob2YShrCUd4O69
         PlKvCh/tSMCqF8z4It9SjKt5BM8UZLQYJ16CDwsHpb1Qii59yVrAsjGWMoU+8G+FjPmX
         risoHTgJah8jLJNJqBDNwXcz/mTovllULAaeg1RaJvCG/Lz9i8T/lI+8zRkVP9AvOXDp
         aZp0UKflxgFRTWh7abwEVldEneDQtp/eZDZpWfN3UviOQh7tedZry/fHPh9H1m+YyofR
         u2Wg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=zkmg9TTmpDqNRBWqj+EB/VNABO8rK220WBDW0bwNNKo=;
        fh=Qz7bK8/h925cC3MKRa1qmULfDrMMOJFMJtTf1nXyGKw=;
        b=VD3Ry5tCt9hrOxdKCyhsaZRRLkkTm/tY+CUA2vakEJCV5JteGN9hLWkxZXoEtepWW9
         aff2kOiSVW00ykhdztRmKlK9r6l8TTY1AFzxyOJIAwkyC45KmtCmJ59cV5sAwh0qiJra
         mBT4EL3WrSdOp9HZZKwrE9z0OfaHa0DU+y35sFZ32uzqlpz0WQ4EZN0l3QtbmROc9il4
         ti3pXo4WnOz7//S1Obp4AL3+rTQiSJgP1JHvu6Rkc4ek/aDcN1WhX+lhnPUZ3Wuxtsbp
         Gj4JY3PIrxKG6V3n8u6gRnQav9rxwIyMz254W4EnsCZgKGLngSatJ8ZaQasbp/r1JNB0
         5hPw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YENt6LTm;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755097646; x=1755702446; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=zkmg9TTmpDqNRBWqj+EB/VNABO8rK220WBDW0bwNNKo=;
        b=KSuRbj0SjLclvYoLF/7rACe66mhy0l4TfEKFcdJAESMCPbXegCUuvlZ9ZqGWbcptut
         IT82SXJoc5W0D9W8xZhnrQ1EnJ+MpZY/u1yevsr6QzNTpwb6arLR9J5lJ5hH4wBicZqJ
         9igQ5iH0dnxghdLu5gERGSS2J83J4LLPngLe5deR2s+B3RAdYDgOFrJQKBDBcOgdD8UA
         N5uEg86TxIZSi/gnjAuitNW0iJEeOLDiFNJMihZv4Nfyy+F8jUumdVtTmPqQm395f755
         J7CyI9FcxuwaVI8EfJGKsQVdCkUb8+pDj9JHRmLq1g8mOtx8qUySBdApoBjnutfqi0Nv
         xUoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755097646; x=1755702446;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zkmg9TTmpDqNRBWqj+EB/VNABO8rK220WBDW0bwNNKo=;
        b=vgqBeiQW3nI3WMb17aL3g7glWC532JqCaPD30yBm2jmOJvM02Hhcm80Qdmopi+xoyE
         OgH+HgWYlLewPqNE5sAXj6ISR05ApFRNS8ltfy+zze0bGd5HbVnCBg142gl7yCSsFUR6
         p573WeO6QI32e7lMOcrxxFc/Numj2dwBDrzOvkpF7uYhGQEfdz7oA/vXwj6oM052vHLx
         Otzzm6tvBeY7gdVCjDMaY6P/0dDOBxjYCcXA2LR6+NTNLm5PjfYvWNxS//drD/zbqxdM
         Ace2YujFfaIydbgDW5zx1FpLXa/Qd04dVrbXPrnIza727FLTkuRxeg7Ei2pyoBPzfizM
         jZIg==
X-Forwarded-Encrypted: i=2; AJvYcCWbjgcXcnCaVjXjMrqfRQm7NVml0yd1uO1HawKhfv4TaE+4HIGa3VYH2QV8f75G1modx8znnw==@lfdr.de
X-Gm-Message-State: AOJu0Yz6DUGg60z43g2p5e8rrYBsIo/K7uO0iYHz0HTqBz6JNGJhduXq
	mkt9ruGqxg8H7gJsRvIVTLNMqfeie+dmq25RBCd7so78zo2jS1XKuSUT
X-Google-Smtp-Source: AGHT+IEGvcwE40ZOz6InZeGvTu4o0GgEYwLQulBTozZOIQ/Kd6v4xbsS8EP4DB34Ij0LHBeMtJriVg==
X-Received: by 2002:a05:6300:218a:b0:23d:491b:76a6 with SMTP id adf61e73a8af0-240a8ad3b87mr6085232637.20.1755097645802;
        Wed, 13 Aug 2025 08:07:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcKdEhSt207SCepk4dVYLtzz9jjMshYr5eQl5eahgiBTA==
Received: by 2002:a05:6a00:2aa:b0:769:ebe1:e489 with SMTP id
 d2e1a72fcca58-76e2e54ce36ls18082b3a.2.-pod-prod-02-us; Wed, 13 Aug 2025
 08:07:24 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV/wDWCJ4+zuhvtvj49Cd+win17jVf9zA/TvnpavOteO0uh1vlH7j6uBqdWkybofrt/J1e5piMHoGw=@googlegroups.com
X-Received: by 2002:a17:903:3c2c:b0:240:99e6:6bc3 with SMTP id d9443c01a7336-2430d108381mr53141235ad.20.1755097644255;
        Wed, 13 Aug 2025 08:07:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755097644; cv=none;
        d=google.com; s=arc-20240605;
        b=hOnd3rEo6ZI4+fRLRMaS/7mHPRI+EhAQPvG20XSEeZYjHVQYuxgr5Cg7XGdMRcJ6Sm
         3fHa5M2S82nGBjs9WWA6SFA7Ytk1hHB36FPlrM9UwRkcCqswNuC5Qir6wLT2b2tPtlle
         2wy1lU+ZbPbJ4tga9zoshaEkeb2qEafi+2MhWXk+ahdEGEdAqT69tjGUf+ZHScBqg8E2
         e5wv831cDpF5/ZcINfWolY8U1swbeYQUxVGgaydkN+RboeOw9/vgiYqpAHfdtL9R01cA
         84agb5G5vnYckB0gyTOHoZ8BvHNlvyAX9/fxbDMK10i48LrzrbQKQM+DfHqbkqBpQQO/
         KC6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=ySXGLynnR++p6RuXca+nTN6nGsk03DV3QSK1ER01nvY=;
        fh=Em3yvq2zMsfyYtekL77bXM163wy++1f+rgqYXqx5CqE=;
        b=KvJHT5iHcbUalJkItoVN6FqrlwpXTfgO/Khz7eS7DT+BrULspJ1KdQ2YlwCIgFD1Se
         jtO9/U9paW2N9o/eYyCFUUPIKwwuGYnzt7SMgyVpzTvJS5LvO2IMRVchq83u+zPcx9F1
         kS1ZKWzTRIVHCLaWaXtxErO8ZgA5H69znzheLfi4kFMXVWI1Lvp6X1jAQFTKh/ihpi9g
         YL6yWlBg2P/9yUegsOrFpRKF79JFh5gHKjEId1OFlG/O+tPQhZHFQzHn4dlfY3Pkp6t8
         Q+IkGrojfSwYceY4reb/T1dAvGA6+puVQ6lhH+oXN4ciPggaO4EJe1vSYkMVryNw8fbm
         KB1g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YENt6LTm;
       spf=pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from tor.source.kernel.org (tor.source.kernel.org. [172.105.4.254])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-241e893b7casi13791225ad.7.2025.08.13.08.07.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 13 Aug 2025 08:07:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted sender) client-ip=172.105.4.254;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by tor.source.kernel.org (Postfix) with ESMTP id 2F0C06112D;
	Wed, 13 Aug 2025 15:07:23 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 1B711C4CEF1;
	Wed, 13 Aug 2025 15:07:22 +0000 (UTC)
Date: Wed, 13 Aug 2025 18:07:18 +0300
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jason Gunthorpe <jgg@nvidia.com>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>,
	Jonathan Corbet <corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com, Keith Busch <kbusch@kernel.org>,
	linux-block@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	linux-nvme@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	linux-trace-kernel@vger.kernel.org,
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
Subject: Re: [PATCH v1 08/16] kmsan: convert kmsan_handle_dma to use physical
 addresses
Message-ID: <20250813150718.GB310013@unreal>
References: <cover.1754292567.git.leon@kernel.org>
 <5b40377b621e49ff4107fa10646c828ccc94e53e.1754292567.git.leon@kernel.org>
 <20250807122115.GH184255@nvidia.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250807122115.GH184255@nvidia.com>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=YENt6LTm;       spf=pass
 (google.com: domain of leon@kernel.org designates 172.105.4.254 as permitted
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

On Thu, Aug 07, 2025 at 09:21:15AM -0300, Jason Gunthorpe wrote:
> On Mon, Aug 04, 2025 at 03:42:42PM +0300, Leon Romanovsky wrote:
> > From: Leon Romanovsky <leonro@nvidia.com>
> > 
> > Convert the KMSAN DMA handling function from page-based to physical
> > address-based interface.
> > 
> > The refactoring renames kmsan_handle_dma() parameters from accepting
> > (struct page *page, size_t offset, size_t size) to (phys_addr_t phys,
> > size_t size). A PFN_VALID check is added to prevent KMSAN operations
> > on non-page memory, preventing from non struct page backed address,
> > 
> > As part of this change, support for highmem addresses is implemented
> > using kmap_local_page() to handle both lowmem and highmem regions
> > properly. All callers throughout the codebase are updated to use the
> > new phys_addr_t based interface.
> 
> Use the function Matthew pointed at kmap_local_pfn()
> 
> Maybe introduce the kmap_local_phys() he suggested too.

At this point it gives nothing.

> 
> >  /* Helper function to handle DMA data transfers. */
> > -void kmsan_handle_dma(struct page *page, size_t offset, size_t size,
> > +void kmsan_handle_dma(phys_addr_t phys, size_t size,
> >  		      enum dma_data_direction dir)
> >  {
> >  	u64 page_offset, to_go, addr;
> > +	struct page *page;
> > +	void *kaddr;
> >  
> > -	if (PageHighMem(page))
> > +	if (!pfn_valid(PHYS_PFN(phys)))
> >  		return;
> 
> Not needed, the caller must pass in a phys that is kmap
> compatible. Maybe just leave a comment. FWIW today this is also not
> checking for P2P or DEVICE non-kmap struct pages either, so it should
> be fine without checks.

It is not true as we will call to kmsan_handle_dma() unconditionally in
dma_map_phys(). The reason to it is that kmsan_handle_dma() is guarded
with debug kconfig options and cost of pfn_valid() can be accommodated
in that case. It gives more clean DMA code.

   155 dma_addr_t dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
   156                 enum dma_data_direction dir, unsigned long attrs)
   157 {
   <...>
   187
   188         kmsan_handle_dma(phys, size, dir);
   189         trace_dma_map_phys(dev, phys, addr, size, dir, attrs);
   190         debug_dma_map_phys(dev, phys, size, dir, addr, attrs);
   191
   192         return addr;
   193 }
   194 EXPORT_SYMBOL_GPL(dma_map_phys);

So let's keep this patch as is.

Thanks

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250813150718.GB310013%40unreal.
