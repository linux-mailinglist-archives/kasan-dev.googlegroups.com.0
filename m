Return-Path: <kasan-dev+bncBDG6PF6SSYDRBIE45TCQMGQEMQUCMAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 62C8CB45DE2
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Sep 2025 18:21:54 +0200 (CEST)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-55f69cf4bf7sf990306e87.3
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Sep 2025 09:21:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757089313; cv=pass;
        d=google.com; s=arc-20240605;
        b=b3cmDr5jOVHt+h5CuN2ZKdzgDUAZzg/S5wh4ugigOzsxGbzr0Pue7K+BuXVnZriJq8
         fsS1uhxDtzO+WIr0NOCQUhS3XvK7ZMGMFPbyidAcjZlVZUepZtJBHk4XiFJRuCDXJpOT
         C/o3+l0vbAa2wbs/Is4T6mclbPO/SERe39L+u1HO9KWpqVn3dy+VyEfNWkGKrl30H3FN
         1XGc++jsea4IatC+hx9UA6grU9MGk3WfOz82rLjW9reXzKA9YxJ8LkircCN7sFiPBYCj
         /1YXitpj6tvsQkgloPUPn0gxRhBOHIYmeqMgiqDJZAz6ptwqtTMX89RhGOqQZvzLi3Uy
         lvSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-filter:sender:dkim-signature;
        bh=b0PeoigdtlU6tcle9dnOHfjfA4iPRSgmq9cRFjWCNRE=;
        fh=D4Wh3zFFPcm+okHBpZO2esoFP9KMT+wtN4tvaw50SFw=;
        b=KVz63NRYRouF3fiQmS5CarPyTYzv+E6DMoIXRSXEUy+Sb12LwcdeFaokl5qsTfBKJp
         ara1ruV/C2cP1wLfWj9GjC6k1rowyoCq/BATDu5Vhc8UW+bZTAFfXr//iKO3Q40dLXO9
         ibsISFnCVZGPi+QFqL+35N5Ubrd+Otx4lnYsuYptoJAaYzYVZRVsKU3iNtkfPf8He/MF
         bbU8YtJtAeKYzAtKit9wypJIW3QrI1C6A26tf0bTsbnYs7Cm1IDtTTsqlyzwHHDOYzou
         +n3+2gTNrhfpuoXEwr/DC7oP1ModZQcCiWG45PkJ2gT3XvM9lGF5hwEnAjA1BjQ+6bwN
         yHdg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=TMub8T2A;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757089313; x=1757694113; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:in-reply-to:from:content-language:cc
         :to:subject:user-agent:mime-version:date:message-id:dkim-filter
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=b0PeoigdtlU6tcle9dnOHfjfA4iPRSgmq9cRFjWCNRE=;
        b=YW52IFW+NC6Pm0BEuJX8eC9u9oDbTrxvF8xvmPP0cXNJEwQgHC0czalIJFtzCwGrC/
         XmMPgx7+O8cJNxKvIl97CO/k5ee5TxX0EsDheiFUdHVHyEZf/7E0vc4MMmGVKiO7lZlE
         ZwpDwVnyVSZVUyQHHuaKeK6M2rQeigsPCFDbttMJ5+H6D14C3HlIcvqIFhqiLFwQxteA
         FjdxryRc2+dU2ax/r7OMiAG3jnraaSEV3W5JEXEhKp6DyLWZuKtc5/McCKFVkjl7zXMl
         fDRwARiQHDb4DY7LiQN2e6nQpdQQ8tJ7x4e4AC/kByA0Z7DgOdB7y5Hp4A4JRbE110sQ
         L0gQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757089313; x=1757694113;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:from:content-language:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-filter:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=b0PeoigdtlU6tcle9dnOHfjfA4iPRSgmq9cRFjWCNRE=;
        b=iH1U3pgQFLageMloAU2cp37lMIxwSaCi3nWNGSl/jqxiCeeBBvlRbGdHj63gth2s/1
         ityM9C8Z5fwf7g9XHoTiLsWhS2Fw1UDEhwu0kp9pZz6fOwLYNbj7Qw/0m2pL5+yNkqFZ
         cVXLq51NezTcZgxYFqY5uVoX6iS2EQDq2JVLqJSMvuem3C58x5fEQNNkkqWWIYLLKOj7
         u9MDTRQVueatgjWHczqjAu5Okot5rMGj7FXpwk6xTh+60IbNzzCV+p2QmUbhbla5i0/z
         e7E3X0MOFJGvI4fko+c4/o6yUxoNAlamlWBYLKz2OgYEJJXsUnKda4t6nf0ULtdcOPah
         r1Ig==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUXHvWkXNF/1nosai8t+F7JQp7UazREdQXNBp40t8pMvt0vW/r/x+yVJZ+syhq5WoPcM0NFzg==@lfdr.de
X-Gm-Message-State: AOJu0YyFbqXHoO4b9rwLcsSYVAaEw88fpBu9II0B3T42Zxsu2gosrvOo
	JRZHQ5hZo4aCl6p2gaEdfv0zbMUvVH6/+/IAFD3fKQmlmURfMyJGuBF7
X-Google-Smtp-Source: AGHT+IHyWLk+ZiupPkIQImB76QgkuWOTD3W56GnLKY67NTufmODvgwZpPU85D4RjO6tS/4roSOlXUg==
X-Received: by 2002:ac2:4c50:0:b0:55f:394e:36 with SMTP id 2adb3069b0e04-55f70954e40mr7335392e87.47.1757089313079;
        Fri, 05 Sep 2025 09:21:53 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcyhZhWURdulMbO11c08LpwX582BT6ZAso5xfCX0R3iGg==
Received: by 2002:ac2:5bdc:0:b0:560:99a2:96c1 with SMTP id 2adb3069b0e04-5615bacb920ls159943e87.1.-pod-prod-03-eu;
 Fri, 05 Sep 2025 09:21:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVyXtsADzktDLp3lErcOhMFSh3km2gU2TNw8KQBHcsBOHD/OWaYRkkToeB9hCX5VZ4G0gVUk+0zGdc=@googlegroups.com
X-Received: by 2002:a05:6512:660e:b0:55f:5526:602a with SMTP id 2adb3069b0e04-55f708b6b64mr6100655e87.15.1757089310106;
        Fri, 05 Sep 2025 09:21:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757089310; cv=none;
        d=google.com; s=arc-20240605;
        b=LNlD05N0DVWYPAxffvIbDNOeC6hoEfTqUUSdWXyw/KMrdsZAnKH/QyIz8FWZiga1Ky
         LA01TIaOzT4WGVtkEhbVWoqc0z15W8CTMQCmHj5zfE+N5CAv7C67XvF191gRiXjxeK5M
         TH0xdrEKJJMTZkfwV6L6xYjYVR2B4VEHk1Ks8kcnPDY9MvwEhF8kf3bzFbk/EKmyn+7r
         YeBml2BMa/DdULDgOCw6vKJ+UCJRw1X3aX0gUGyuDdUaf/piTpOfVSQrNYWPLkqDvBij
         /OVRajch5kLLjD8ECG7ZLI8NOvG6MGy3aO2WkMy8gTncrNZJodKUBZtnfPE3v3nEqTAI
         Qu/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:content-transfer-encoding:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-filter;
        bh=SihwygswkUbDkI6TEnNcbeL2/U8m9DIalmjgcknmvOM=;
        fh=OrMujXTewyvzYmcfWSc12Lkv5kQcm7TAYfZXBi77AsM=;
        b=OUHl2j7N6R2L11d739Ged4mr9S1mAIFjyj61NKPmtox4blS8Jkd+bKCb5+UnRJ/jb/
         sH9p7ehOYrOlZsdQUW44radZisAIl3eV8E5LpOC2j7L3C0C0NiZnSrzArZ2IOv10En4Q
         ESxXxZitX9FVrADKyHspcZTLYZceyEWLZ/nKyBYY5EfPFNl16l4fksedVILRtq4olUhw
         ifH+2j2pRrSnTKktkBthpLpe0hG09Vi2ma3mOHncdAPRKboAM3xf45Q5fM1hoLKQbgA4
         nGXcL/ghvm04gYYV1tY2jGdvHzzt1LF4VwNNfqtVNCMypIfBFRjZo6OLWM6IsvwyAoq8
         NKhA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=TMub8T2A;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout2.w1.samsung.com (mailout2.w1.samsung.com. [210.118.77.12])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5608acb5e9fsi142135e87.6.2025.09.05.09.21.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 05 Sep 2025 09:21:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) client-ip=210.118.77.12;
Received: from eucas1p2.samsung.com (unknown [182.198.249.207])
	by mailout2.w1.samsung.com (KnoxPortal) with ESMTP id 20250905162148euoutp02604d107873dc75c605be1c2733dda215~ib2qaX6dY1912019120euoutp02_;
	Fri,  5 Sep 2025 16:21:48 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout2.w1.samsung.com 20250905162148euoutp02604d107873dc75c605be1c2733dda215~ib2qaX6dY1912019120euoutp02_
Received: from eusmtip2.samsung.com (unknown [203.254.199.222]) by
	eucas1p2.samsung.com (KnoxPortal) with ESMTPA id
	20250905162147eucas1p221ca4e33b0e6396d02908377c6c5b919~ib2pcEwbH0974409744eucas1p2p;
	Fri,  5 Sep 2025 16:21:47 +0000 (GMT)
Received: from [106.210.134.192] (unknown [106.210.134.192]) by
	eusmtip2.samsung.com (KnoxPortal) with ESMTPA id
	20250905162145eusmtip2342879dbc38ddfe0bbff0062e179f725~ib2nn8yb40979609796eusmtip2i;
	Fri,  5 Sep 2025 16:21:45 +0000 (GMT)
Message-ID: <087e7f3d-1e0d-4efe-822f-72d16d161a60@samsung.com>
Date: Fri, 5 Sep 2025 18:21:44 +0200
MIME-Version: 1.0
User-Agent: Betterbird (Windows)
Subject: Re: [PATCH v5 07/16] dma-mapping: convert dma_direct_*map_page to
 be phys_addr_t based
To: Leon Romanovsky <leon@kernel.org>
Cc: Leon Romanovsky <leonro@nvidia.com>, Jason Gunthorpe <jgg@nvidia.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>, Alexander Potapenko
	<glider@google.com>, Alex Gaynor <alex.gaynor@gmail.com>, Andrew Morton
	<akpm@linux-foundation.org>, Christoph Hellwig <hch@lst.de>, Danilo
	Krummrich <dakr@kernel.org>, David Hildenbrand <david@redhat.com>,
	iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>, Jens Axboe
	<axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>, Jonathan Corbet
	<corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com, Keith Busch <kbusch@kernel.org>,
	linux-block@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	linux-nvme@lists.infradead.org, linuxppc-dev@lists.ozlabs.org,
	linux-trace-kernel@vger.kernel.org, Madhavan Srinivasan
	<maddy@linux.ibm.com>, Masami Hiramatsu <mhiramat@kernel.org>, Michael
	Ellerman <mpe@ellerman.id.au>, "Michael S. Tsirkin" <mst@redhat.com>, Miguel
	Ojeda <ojeda@kernel.org>, Robin Murphy <robin.murphy@arm.com>,
	rust-for-linux@vger.kernel.org, Sagi Grimberg <sagi@grimberg.me>, Stefano
	Stabellini <sstabellini@kernel.org>, Steven Rostedt <rostedt@goodmis.org>,
	virtualization@lists.linux.dev, Will Deacon <will@kernel.org>,
	xen-devel@lists.xenproject.org
Content-Language: en-US
From: Marek Szyprowski <m.szyprowski@samsung.com>
In-Reply-To: <6b2f4cb436c98d6342db69e965a5621707b9711f.1756822782.git.leon@kernel.org>
X-CMS-MailID: 20250905162147eucas1p221ca4e33b0e6396d02908377c6c5b919
X-Msg-Generator: CA
Content-Type: text/plain; charset="UTF-8"
X-RootMTR: 20250902144935eucas1p253de9e94315de54325cc61dea9c76490
X-EPHeader: CA
X-CMS-RootMailID: 20250902144935eucas1p253de9e94315de54325cc61dea9c76490
References: <cover.1756822782.git.leon@kernel.org>
	<CGME20250902144935eucas1p253de9e94315de54325cc61dea9c76490@eucas1p2.samsung.com>
	<6b2f4cb436c98d6342db69e965a5621707b9711f.1756822782.git.leon@kernel.org>
X-Original-Sender: m.szyprowski@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=TMub8T2A;       spf=pass
 (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as
 permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=samsung.com
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

On 02.09.2025 16:48, Leon Romanovsky wrote:
> From: Leon Romanovsky <leonro@nvidia.com>
>
> Convert the DMA direct mapping functions to accept physical addresses
> directly instead of page+offset parameters. The functions were already
> operating on physical addresses internally, so this change eliminates
> the redundant page-to-physical conversion at the API boundary.
>
> The functions dma_direct_map_page() and dma_direct_unmap_page() are
> renamed to dma_direct_map_phys() and dma_direct_unmap_phys() respectively,
> with their calling convention changed from (struct page *page,
> unsigned long offset) to (phys_addr_t phys).
>
> Architecture-specific functions arch_dma_map_page_direct() and
> arch_dma_unmap_page_direct() are similarly renamed to
> arch_dma_map_phys_direct() and arch_dma_unmap_phys_direct().
>
> The is_pci_p2pdma_page() checks are replaced with DMA_ATTR_MMIO checks
> to allow integration with dma_direct_map_resource and dma_direct_map_phys()
> is extended to support MMIO path either.
>
> Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
> Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
> ---
>   arch/powerpc/kernel/dma-iommu.c |  4 +--
>   include/linux/dma-map-ops.h     |  8 ++---
>   kernel/dma/direct.c             |  6 ++--
>   kernel/dma/direct.h             | 57 +++++++++++++++++++++------------
>   kernel/dma/mapping.c            |  8 ++---
>   5 files changed, 49 insertions(+), 34 deletions(-)
>
> diff --git a/arch/powerpc/kernel/dma-iommu.c b/arch/powerpc/kernel/dma-iommu.c
> index 4d64a5db50f3..0359ab72cd3b 100644
> --- a/arch/powerpc/kernel/dma-iommu.c
> +++ b/arch/powerpc/kernel/dma-iommu.c
> @@ -14,7 +14,7 @@
>   #define can_map_direct(dev, addr) \
>   	((dev)->bus_dma_limit >= phys_to_dma((dev), (addr)))
>   
> -bool arch_dma_map_page_direct(struct device *dev, phys_addr_t addr)
> +bool arch_dma_map_phys_direct(struct device *dev, phys_addr_t addr)
>   {
>   	if (likely(!dev->bus_dma_limit))
>   		return false;
> @@ -24,7 +24,7 @@ bool arch_dma_map_page_direct(struct device *dev, phys_addr_t addr)
>   
>   #define is_direct_handle(dev, h) ((h) >= (dev)->archdata.dma_offset)
>   
> -bool arch_dma_unmap_page_direct(struct device *dev, dma_addr_t dma_handle)
> +bool arch_dma_unmap_phys_direct(struct device *dev, dma_addr_t dma_handle)
>   {
>   	if (likely(!dev->bus_dma_limit))
>   		return false;
> diff --git a/include/linux/dma-map-ops.h b/include/linux/dma-map-ops.h
> index f48e5fb88bd5..71f5b3025415 100644
> --- a/include/linux/dma-map-ops.h
> +++ b/include/linux/dma-map-ops.h
> @@ -392,15 +392,15 @@ void *arch_dma_set_uncached(void *addr, size_t size);
>   void arch_dma_clear_uncached(void *addr, size_t size);
>   
>   #ifdef CONFIG_ARCH_HAS_DMA_MAP_DIRECT
> -bool arch_dma_map_page_direct(struct device *dev, phys_addr_t addr);
> -bool arch_dma_unmap_page_direct(struct device *dev, dma_addr_t dma_handle);
> +bool arch_dma_map_phys_direct(struct device *dev, phys_addr_t addr);
> +bool arch_dma_unmap_phys_direct(struct device *dev, dma_addr_t dma_handle);
>   bool arch_dma_map_sg_direct(struct device *dev, struct scatterlist *sg,
>   		int nents);
>   bool arch_dma_unmap_sg_direct(struct device *dev, struct scatterlist *sg,
>   		int nents);
>   #else
> -#define arch_dma_map_page_direct(d, a)		(false)
> -#define arch_dma_unmap_page_direct(d, a)	(false)
> +#define arch_dma_map_phys_direct(d, a)		(false)
> +#define arch_dma_unmap_phys_direct(d, a)	(false)
>   #define arch_dma_map_sg_direct(d, s, n)		(false)
>   #define arch_dma_unmap_sg_direct(d, s, n)	(false)
>   #endif
> diff --git a/kernel/dma/direct.c b/kernel/dma/direct.c
> index 24c359d9c879..fa75e3070073 100644
> --- a/kernel/dma/direct.c
> +++ b/kernel/dma/direct.c
> @@ -453,7 +453,7 @@ void dma_direct_unmap_sg(struct device *dev, struct scatterlist *sgl,
>   		if (sg_dma_is_bus_address(sg))
>   			sg_dma_unmark_bus_address(sg);
>   		else
> -			dma_direct_unmap_page(dev, sg->dma_address,
> +			dma_direct_unmap_phys(dev, sg->dma_address,
>   					      sg_dma_len(sg), dir, attrs);
>   	}
>   }
> @@ -476,8 +476,8 @@ int dma_direct_map_sg(struct device *dev, struct scatterlist *sgl, int nents,
>   			 */
>   			break;
>   		case PCI_P2PDMA_MAP_NONE:
> -			sg->dma_address = dma_direct_map_page(dev, sg_page(sg),
> -					sg->offset, sg->length, dir, attrs);
> +			sg->dma_address = dma_direct_map_phys(dev, sg_phys(sg),
> +					sg->length, dir, attrs);
>   			if (sg->dma_address == DMA_MAPPING_ERROR) {
>   				ret = -EIO;
>   				goto out_unmap;
> diff --git a/kernel/dma/direct.h b/kernel/dma/direct.h
> index d2c0b7e632fc..3f4792910604 100644
> --- a/kernel/dma/direct.h
> +++ b/kernel/dma/direct.h
> @@ -80,42 +80,57 @@ static inline void dma_direct_sync_single_for_cpu(struct device *dev,
>   		arch_dma_mark_clean(paddr, size);
>   }
>   
> -static inline dma_addr_t dma_direct_map_page(struct device *dev,
> -		struct page *page, unsigned long offset, size_t size,
> -		enum dma_data_direction dir, unsigned long attrs)
> +static inline dma_addr_t dma_direct_map_phys(struct device *dev,
> +		phys_addr_t phys, size_t size, enum dma_data_direction dir,
> +		unsigned long attrs)
>   {
> -	phys_addr_t phys = page_to_phys(page) + offset;
> -	dma_addr_t dma_addr = phys_to_dma(dev, phys);
> +	dma_addr_t dma_addr;
>   
>   	if (is_swiotlb_force_bounce(dev)) {
> -		if (is_pci_p2pdma_page(page))
> -			return DMA_MAPPING_ERROR;
> +		if (attrs & DMA_ATTR_MMIO)
> +			goto err_overflow;
> +
>   		return swiotlb_map(dev, phys, size, dir, attrs);
>   	}
>   
> -	if (unlikely(!dma_capable(dev, dma_addr, size, true)) ||
> -	    dma_kmalloc_needs_bounce(dev, size, dir)) {
> -		if (is_pci_p2pdma_page(page))
> -			return DMA_MAPPING_ERROR;
> -		if (is_swiotlb_active(dev))
> -			return swiotlb_map(dev, phys, size, dir, attrs);
> -
> -		dev_WARN_ONCE(dev, 1,
> -			     "DMA addr %pad+%zu overflow (mask %llx, bus limit %llx).\n",
> -			     &dma_addr, size, *dev->dma_mask, dev->bus_dma_limit);
> -		return DMA_MAPPING_ERROR;
> +	if (attrs & DMA_ATTR_MMIO) {
> +		dma_addr = phys;
> +		if (unlikely(dma_capable(dev, dma_addr, size, false)))

"!dma_capable(dev, dma_addr, size, false)" in the above line.

It took me a while to find this after noticing that this patchset breaks booting some of me test systems.


> +			goto err_overflow;
> +	} else {
> +		dma_addr = phys_to_dma(dev, phys);
> +		if (unlikely(!dma_capable(dev, dma_addr, size, true)) ||
> +		    dma_kmalloc_needs_bounce(dev, size, dir)) {
> +			if (is_swiotlb_active(dev))
> +				return swiotlb_map(dev, phys, size, dir, attrs);
> +
> +			goto err_overflow;
> +		}
>   	}
>   
> -	if (!dev_is_dma_coherent(dev) && !(attrs & DMA_ATTR_SKIP_CPU_SYNC))
> +	if (!dev_is_dma_coherent(dev) &&
> +	    !(attrs & (DMA_ATTR_SKIP_CPU_SYNC | DMA_ATTR_MMIO)))
>   		arch_sync_dma_for_device(phys, size, dir);
>   	return dma_addr;
> +
> +err_overflow:
> +	dev_WARN_ONCE(
> +		dev, 1,
> +		"DMA addr %pad+%zu overflow (mask %llx, bus limit %llx).\n",
> +		&dma_addr, size, *dev->dma_mask, dev->bus_dma_limit);
> +	return DMA_MAPPING_ERROR;
>   }
>   
> -static inline void dma_direct_unmap_page(struct device *dev, dma_addr_t addr,
> +static inline void dma_direct_unmap_phys(struct device *dev, dma_addr_t addr,
>   		size_t size, enum dma_data_direction dir, unsigned long attrs)
>   {
> -	phys_addr_t phys = dma_to_phys(dev, addr);
> +	phys_addr_t phys;
> +
> +	if (attrs & DMA_ATTR_MMIO)
> +		/* nothing to do: uncached and no swiotlb */
> +		return;
>   
> +	phys = dma_to_phys(dev, addr);
>   	if (!(attrs & DMA_ATTR_SKIP_CPU_SYNC))
>   		dma_direct_sync_single_for_cpu(dev, addr, size, dir);
>   
> diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
> index 58482536db9b..80481a873340 100644
> --- a/kernel/dma/mapping.c
> +++ b/kernel/dma/mapping.c
> @@ -166,8 +166,8 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
>   		return DMA_MAPPING_ERROR;
>   
>   	if (dma_map_direct(dev, ops) ||
> -	    arch_dma_map_page_direct(dev, phys + size))
> -		addr = dma_direct_map_page(dev, page, offset, size, dir, attrs);
> +	    arch_dma_map_phys_direct(dev, phys + size))
> +		addr = dma_direct_map_phys(dev, phys, size, dir, attrs);
>   	else if (use_dma_iommu(dev))
>   		addr = iommu_dma_map_phys(dev, phys, size, dir, attrs);
>   	else
> @@ -187,8 +187,8 @@ void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
>   
>   	BUG_ON(!valid_dma_direction(dir));
>   	if (dma_map_direct(dev, ops) ||
> -	    arch_dma_unmap_page_direct(dev, addr + size))
> -		dma_direct_unmap_page(dev, addr, size, dir, attrs);
> +	    arch_dma_unmap_phys_direct(dev, addr + size))
> +		dma_direct_unmap_phys(dev, addr, size, dir, attrs);
>   	else if (use_dma_iommu(dev))
>   		iommu_dma_unmap_phys(dev, addr, size, dir, attrs);
>   	else

Best regards
-- 
Marek Szyprowski, PhD
Samsung R&D Institute Poland

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/087e7f3d-1e0d-4efe-822f-72d16d161a60%40samsung.com.
