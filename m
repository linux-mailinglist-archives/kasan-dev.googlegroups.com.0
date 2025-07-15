Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBDV53HBQMGQEDEZNERQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf37.google.com (mail-qv1-xf37.google.com [IPv6:2607:f8b0:4864:20::f37])
	by mail.lfdr.de (Postfix) with ESMTPS id B532CB05EF8
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jul 2025 15:58:40 +0200 (CEST)
Received: by mail-qv1-xf37.google.com with SMTP id 6a1803df08f44-702b5e87d98sf105643346d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Jul 2025 06:58:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752587919; cv=pass;
        d=google.com; s=arc-20240605;
        b=W+MlMgQcopMdn6qDtkstsVDQ+DwJT2AmFcFN4TLoN5EzYD9KtL6fooh3NRU2W/Zdxx
         2JUg4SLqHAH1ArSFNymDFgJETD5MLy50HKK0a70aMAu8Hvsx5OOltCf1g9Ho0bsET4b3
         gDQZjRaVMcaTRLMAxRhF4Vn8G7uQEQyrcrhVfO2MGm3MSjbXEm/c2L9QK8P7h4NdUR+L
         ywcDQyK/mx6FbdgcQwkZdljOi0auOU10xqFnymItB1G9QP9sOodfH9V0dvj1MjQ9CkE1
         2gAOqAXRLpLMUser7Ekl961JupZb7wVUYgJMgL/hqo84pXdZh+cbFGG8yKJ+SBpwa0Q1
         VbBQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ErmV7AYAWHUMneEKkPSekoDxXW6HgYiTKPXlKW1n6jI=;
        fh=WdojdIiapkrTHI7vpgWMYao8j6TaUiaHzutEymUr3IE=;
        b=iQSmMyoL5A0ZuUgJhTwtKCbeBOFZr6aA+en8kh5w3WTa/rgzzgAqzLaudvi+YXFhda
         B12jo204Z6/EEcdQXnmUaV3Qr2qjZ2E04QBgZkzIU5oC7/OqvDGctFEgoWopQFtVawuV
         LLv4AtPOCJjD8Byg8EeLUwqQ4VAw3BZuRNigeICGxR8tnpKywzKJqbK8He050XyUNvUt
         noqiaOMDuAu6NZOB/t1r8K1jcqeH6NYVh3lZESUD+cWkSZakhkZbhOQsbqkAl1hPGj3D
         bd2U2RsEBktXkm+airyU4MZzTfudFxlH41CYfU6xUT+zdAfIsUGkshCKq5LRkOGZW/S4
         Tj4Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=l4Vizggn;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752587919; x=1753192719; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ErmV7AYAWHUMneEKkPSekoDxXW6HgYiTKPXlKW1n6jI=;
        b=GJ3Za6O2V+2oJRdzBnYRPdIqAz9YDMW7msdXbBkZTVx6TjeHjTGZpfZ8n2DY+pj5cl
         S7Ygk4y3uB7uTpqkwUL2oQ48BZZPtZIoxm4O4fum/30gKdx5mXEkO73JKuPIB7OyDk8I
         6wYB7+RLXoK+6KV7kDJnGgBZOHxGgNOKV31s4LtY3QrHwhyJ4p/nI4dD1QB2hCThhgLN
         YFxFUkT7B06fJur6Uqj4nmPgvKN2uibKvOOEoe8iYDs9+ugtwlQwByNgav+XMkYMgxG7
         nMpDXmD3ZjUuAy88u3bdHgC9ap3vHmcCEvZiuZCW463wPEY6vYFs3GccoRI3o67Gv326
         n/0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752587919; x=1753192719;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ErmV7AYAWHUMneEKkPSekoDxXW6HgYiTKPXlKW1n6jI=;
        b=GdH/NgSGGHgySYDegb8+KPDzExGYq3zYN4DNCmBBdDgcj1r/RqCABBAl+Mav/Agq6O
         xx2wsqr4sFMIAvulknDOoXTTmG7cEdJRQzlpzyBdMe+joArpB95gb1o8v5cSBew86EHT
         x9p1oR67bj2JKO5TrLPpJOPF1RUv69zk76PKeS4ppXYQtiKXEDmZG55nkOH6/eKnTGFY
         N69tD4JFyUTa29UqVyvMAJlR7O1FTz4p4wfR7NMfFg8Em/o8qB8nBjg8OGq3+5da2CFu
         8RjIoFQmGJyklBDPX1bQjgB9DpIPFQEK98WPw9vzhfJcJaw19I80ewH27txtieHAPnMh
         /DrQ==
X-Forwarded-Encrypted: i=2; AJvYcCXiQ/VGvF6NdRSPkzymp89AeaNfTCGNQ5r9BuR1JWdEOMc9vcKUmoYvne4wG0EsV5Vd0u4pUw==@lfdr.de
X-Gm-Message-State: AOJu0Yx27ZePu1n1ihDc6z7rEpFFzC7MlxiVIkxSrZLDm31X7nPJQpd6
	ugF0xmnuK11Ju+2RV9nsHFnwuooxqz3p/OVblFqNOuqCktqIO1A8ErTl
X-Google-Smtp-Source: AGHT+IH1Ox6diKj7cbpIgje/uM9327F9vElv9rfsCpXzv55CIscidwmgHuPZmwFVNNF8Ipg5L4QBug==
X-Received: by 2002:a05:6214:2f0c:b0:702:da74:d022 with SMTP id 6a1803df08f44-704a39ced42mr225489346d6.35.1752587919101;
        Tue, 15 Jul 2025 06:58:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfS/i3k/enJ0TdEypvwIYEkFFQMy0TgPFk6lRq8v1a1Sw==
Received: by 2002:a05:6214:1c48:b0:6fa:c4e4:78b3 with SMTP id
 6a1803df08f44-70495733a50ls85481206d6.1.-pod-prod-03-us; Tue, 15 Jul 2025
 06:58:37 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWoUBpF053sXaHdZvZIbOgBmpNMU3g1G5GAnOD8KgrZuaH9e4vMPbdDI8e8DHfcveHe228YNoXeN9k=@googlegroups.com
X-Received: by 2002:ad4:4ead:0:b0:704:95e4:c23b with SMTP id 6a1803df08f44-704a3a864f3mr250157366d6.38.1752587913869;
        Tue, 15 Jul 2025 06:58:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752587913; cv=none;
        d=google.com; s=arc-20240605;
        b=hSpa+Se0ltoO98fL1OHkVk9DRAqNuQNDyxCI7rwiQ6o59ZAM8xDYgX7QgxEu5PMEF2
         bIkUHQcwuyRJhWO7je8WyjPKVt+f+zLBCL+jsJoKo5fhEtTCdlFeyXsgx9rvn3QdGSX2
         XhrGsn/LXmgsW/uhXUL2zPkhXIegrk+kfW8jIPEM0VbnOeW7c/sn7Ob1tzjt8AqTk/d1
         53AY+CUFi5GiKeiiR3h9paeXLASXVMKkxgvHeYzH7e9pN8uKAz50UdqXFRFkJKAl7QP5
         Ar8+2Wa9FrVm2cmuNMHA3xPJ7iOSYIw2jw94/jFzqkYyXUoaH1TyEXk2sIaRMa5//fR3
         o18A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=6nnCBwHTAKrHqcmaMGyNrB/ejXN9Xrce25gHVuAIWJI=;
        fh=L9OnLYFM4/ceVFyopXeapKIQTbdJeBrEWBBNGktj1jA=;
        b=DM5x5Tg1l0K5CXz6YyAtAK942yrJJoyI6U0mLdc9dIrhL2sFStC4AMrt6wPqhSnLNt
         ElcsRNMB0TcLUSMy77FpNm4/XB1FDmtp6froK33+cguqzSqK27pQiN8HpG4ekA1HiGFd
         4itMPBuxJIr+bcNnIGQXkIaqYrSCGuYtHIHwz5OMYVuogGuUgeB155IOK6oqFRf7Gmwd
         dhVasjrFqbUwxDrIz1yNkSadpDedi2d5zNVBh72sz/AAW6189X2q7L70eMau9t3SpS62
         noaUG7iZynH3z22xtCKn4c8kNmW9m+J16V++kHDnPKt6uPUleOlE35BPuQbxOrZmH7cQ
         ppug==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=l4Vizggn;
       spf=pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [147.75.193.91])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70497d7fa21si5834976d6.6.2025.07.15.06.58.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Jul 2025 06:58:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted sender) client-ip=147.75.193.91;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 9366FA5710B;
	Tue, 15 Jul 2025 13:58:33 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 6E39CC4CEE3;
	Tue, 15 Jul 2025 13:58:32 +0000 (UTC)
Date: Tue, 15 Jul 2025 16:58:28 +0300
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Will Deacon <will@kernel.org>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
	Christoph Hellwig <hch@lst.de>, Jonathan Corbet <corbet@lwn.net>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Robin Murphy <robin.murphy@arm.com>, Joerg Roedel <joro@8bytes.org>,
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
	linux-trace-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH 8/8] mm/hmm: migrate to physical address-based DMA
 mapping API
Message-ID: <20250715135828.GE5882@unreal>
References: <cover.1750854543.git.leon@kernel.org>
 <8a85f4450905fcb6b17d146cc86c11410d522de4.1750854543.git.leon@kernel.org>
 <aHZWlu7Td9ijFhhh@willie-the-truck>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <aHZWlu7Td9ijFhhh@willie-the-truck>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=l4Vizggn;       spf=pass
 (google.com: domain of leon@kernel.org designates 147.75.193.91 as permitted
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

On Tue, Jul 15, 2025 at 02:24:38PM +0100, Will Deacon wrote:
> Hi Leon,
> 
> On Wed, Jun 25, 2025 at 04:19:05PM +0300, Leon Romanovsky wrote:
> > From: Leon Romanovsky <leonro@nvidia.com>
> > 
> > Convert HMM DMA operations from the legacy page-based API to the new
> > physical address-based dma_map_phys() and dma_unmap_phys() functions.
> > This demonstrates the preferred approach for new code that should use
> > physical addresses directly rather than page+offset parameters.
> > 
> > The change replaces dma_map_page() and dma_unmap_page() calls with
> > dma_map_phys() and dma_unmap_phys() respectively, using the physical
> > address that was already available in the code. This eliminates the
> > redundant page-to-physical address conversion and aligns with the
> > DMA subsystem's move toward physical address-centric interfaces.
> > 
> > This serves as an example of how new code should be written to leverage
> > the more efficient physical address API, which provides cleaner interfaces
> > for drivers that already have access to physical addresses.
> 
> I'm struggling a little to see how this is cleaner or more efficient
> than the old code.

It is not, the main reason for hmm conversion is to show how the API is
used. HMM is built around struct page.

> 
> From what I can tell, dma_map_page_attrs() takes a 'struct page *' and
> converts it to a physical address using page_to_phys() whilst your new
> dma_map_phys() interface takes a physical address and converts it to
> a 'struct page *' using phys_to_page(). In both cases, hmm_dma_map_pfn()
> still needs the page for other reasons. If anything, existing users of
> dma_map_page_attrs() now end up with a redundant page-to-phys-to-page
> conversion which hopefully the compiler folds away.
> 
> I'm assuming there's future work which builds on top of the new API
> and removes the reliance on 'struct page' entirely, is that right? If
> so, it would've been nicer to be clearer about that as, on its own, I'm
> not really sure this patch series achieves an awful lot and the
> efficiency argument looks quite weak to me.

Yes, there is ongoing work, which is built on top of dma_map_phys() API
and can't be built without DMA phys.

My WIP branch, where I'm using it can be found here:
https://git.kernel.org/pub/scm/linux/kernel/git/leon/linux-rdma.git/log/?h=dmabuf-vfio

In that branch, we save one phys_to_page conversion in block datapath:
block-dma: migrate to dma_map_phys instead of map_page

and implement DMABUF exporter for MMIO pages:
vfio/pci: Allow MMIO regions to be exported through dma-buf
see vfio_pci_dma_buf_map() function.

Thanks

> 
> Cheers,
> 
> Will
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250715135828.GE5882%40unreal.
