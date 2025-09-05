Return-Path: <kasan-dev+bncBDG6PF6SSYDRBVM65TCQMGQERYB6EUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33a.google.com (mail-wm1-x33a.google.com [IPv6:2a00:1450:4864:20::33a])
	by mail.lfdr.de (Postfix) with ESMTPS id D3F15B45E17
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Sep 2025 18:27:02 +0200 (CEST)
Received: by mail-wm1-x33a.google.com with SMTP id 5b1f17b1804b1-45b98de0e34sf18989865e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Sep 2025 09:27:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757089622; cv=pass;
        d=google.com; s=arc-20240605;
        b=dVG1m6l5JAy8Y8wjEeUc7iw36VMUq6Il/mRHG+sKQd6r+p9GmvsmSk9Dwn93O+dE6T
         mdu+Z+j6EBXetGV9Sx/ZBiXpRxQ5cUjNiFE8EMMggwiX+fLE8Mrrq0mqx446WUpFTFPI
         DXRCSyiPlQat36Q24an5OnZay77S6DfPaKTNUdRx9vNEm0CVtROnLvejdovZna4rXS4c
         Mgob1pbWp9F/2kAq8tFly5JMPGTiW5XQ87SvIL+YT0ioTROmWPTzk11fJ7ZYaRAx+BRY
         GKJxrzeY/0zVOM/CX/8P++VaFOMojqbgF/UeHwYifv3imOxkJe7KsSkQBz5r+bShZCft
         woIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-filter:sender:dkim-signature;
        bh=TZ/YQfWeAVRUHAWPr38/QBNp4pezEqAiK2Vqu+UYFso=;
        fh=Zuud4qXFlxO+u1BM96xK9l+zX+2JCgcONkWQ1UdlVuY=;
        b=Lyxlii2hD7SlZ+ubabYb1LaMbtrDsLVoNOnEPLAP6JVW0uBPpSblsyT6E+xCTze5J8
         NuEreM8Lo8I44DEg3/WDMaWyXjqiRpj7mmKCCZazRTKOxfjDEOkpeUHxJ6JK04kcYcoo
         DD4dMen+Tqfqo7RWok3umL9toF7M4uAUAmnUeLLg6BmFWCDi1FXxCOMlk8ND/nPqpgsu
         6v5Yn0F5QsdAk/TNsxBwt5BmJPcKFJ6SDpOUT30cifUrw+YASqTmj32WMN4swdtcgi7Z
         87B7P1PRKvVRqSYmB9xn/fwD8qemBUKjJMCiQQQ8CExmgli/Vn528ZbD2Qv6g+sM08Cs
         dQYg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b="k7Zmm/l4";
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757089622; x=1757694422; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:in-reply-to:from:content-language:cc
         :to:subject:user-agent:mime-version:date:message-id:dkim-filter
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=TZ/YQfWeAVRUHAWPr38/QBNp4pezEqAiK2Vqu+UYFso=;
        b=TwUWAPh1XEEQ917Ey06o0VUoUXabM7ZH9ru2JTPu8k9oB1tddperFehVxt2Kp9ZZzV
         TxFwlgSSpvB1YB9uGQNnWC4Ezr2XfWAOI+9SNVPN8PiCMhaF/BnEdifpqCRTTbKEialb
         QzrwZFI0v/fsalWkaQuRCQfibSJWTgIaqnij0Srd6qTWVJslHR/k3AC2o2MymmKsyr5a
         JM+neKr2YOPE9RmDs930DbtPOiG4PPe9Fkk8753LR1PggMLRN2oLNht7HbxYZVePSD82
         IjPXrvvywVBESySUwAzwg84/9DRxwrPf1lTlRQj4e8BIwsHw15WqYI812U90CPpi1Pqe
         U/ew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757089622; x=1757694422;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:from:content-language:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-filter:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=TZ/YQfWeAVRUHAWPr38/QBNp4pezEqAiK2Vqu+UYFso=;
        b=Rxti+mUGkL+fIvo47GIGc5g/FKH8YUf9PCMZRpqK8XJ+S8dRFC/4Q5wyPkf8U7BWJA
         Dx+iZm4l/k/Pg6iIIkA8NaSf1O4j9fLK7ArFx0Z75mGN05p2hG+DcjhEKvXA9f3i/28Z
         C9qqeObPssZjcw6qkxdFopNvm9Pzjm2IdTTm9VupA3sD3jyTHxrV4aaJuuAJz8ycP9Dc
         BbH7BHT7gvwCJMYMmuVIEf/mj9PLemVyy8qor6/7cht+mHs42ND3hXujWh03hfQeWtGZ
         ip45W0owDbgJTk071rVoltHjZJW5r2Y8c1wz/vsOtIzsZTBzxNEDQrHJxbSbt1jqmvcj
         CvdQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUoSKQEsnrNxOW+hVvVZBdD9slNCbUWJJ860oUhGQzaH1D2fwrNC6rU1iOgNJF0/f+7Akibxw==@lfdr.de
X-Gm-Message-State: AOJu0YzASbtrfgda5onkCJQ9K7iVutoZ7X59mk/gLxQOkm4P2+oMC6ob
	jbu/+h8q3iyprrY6zt4DKICWWzs7zkuQoxC6wWe2so+ICuMuFjC3jLVS
X-Google-Smtp-Source: AGHT+IENNCVHgkH2KX+9RzShin619r6/TaAV7vM0+zqRk/kIUbSGZB49w3sc4INcgzL2Bs1LTZ1fFg==
X-Received: by 2002:a05:600c:3f0c:b0:45d:d88b:cbc with SMTP id 5b1f17b1804b1-45dd88b149emr31863095e9.30.1757089622146;
        Fri, 05 Sep 2025 09:27:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfn6pvqZRNT4sTGzRrGXWHar3uId6Nv9Ta90gjO0fMpEQ==
Received: by 2002:a05:600c:6215:b0:459:def4:3d79 with SMTP id
 5b1f17b1804b1-45dd84103d3ls6108885e9.2.-pod-prod-02-eu; Fri, 05 Sep 2025
 09:26:59 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXMtoEU/RTZMZBezF5MkSmoaYkfGrMoRpOIpmSHEnqpNAIy1RVJ0pi3Lk+J69OrIZt3tcFMzK3pVa4=@googlegroups.com
X-Received: by 2002:a05:6000:230f:b0:3dc:eb5:501e with SMTP id ffacd0b85a97d-3dc0eb5534cmr7613106f8f.18.1757089619414;
        Fri, 05 Sep 2025 09:26:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757089619; cv=none;
        d=google.com; s=arc-20240605;
        b=X6lnMs1N3r3nC8SgfyBTY0Nv5UhzY00xlMD51MZIdg00IPJiuvC4WLuYg4IsdFAgXY
         e70Slc/CAgb7vT+EpOpj/nUCgXt5flQc3fMUa4/+VFc7O+qd9UBWU4MOGo7vzh37giBZ
         hih5NRbFyH/7f8JaoueBB02jhlzRIbJ7zCrC+FzYAxPIyHSov9lE9nqr4PIl+fhKoyk4
         3h0l2XxF1T+q8/C7X4bJ7X31jwMRNlhl/8jGageK+b5Lc9pceuk55wXLsAS5vTcJ4xgJ
         0rErR7BbGaN/Qv8G+U8BvHGFNgmZq9XTxOBCfYSJ+GInt/4oCgnK67R0mMJxDycw+CvB
         sScw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:content-transfer-encoding:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-filter;
        bh=JratdkJhfp1iQGSSFRxxu72lgWMqyE2NX54DSFPZHRY=;
        fh=qouSimbGsfsbp9vvvKqWVrIL5wjbkT0wdVVzJXaGfLg=;
        b=K6ji11FsSlktUC+7DYFj23FcFGiiLIzkjc2fZqZwkf6/D2bl7P9n/q9s2y74MlwplS
         lcq6uo4SSLlVGLK1WfGBnlBQNB0rnKNDPZL+RiYIgLJAFB3I8FlAwJFwewblVS9TOnU/
         dMFp3cYlmF0wieoxFidVSWe144v399QEnZPvRKDtwKLG+Zn5icI6oYZPTmxhe1u5kDF8
         rEooBJiBYXZ28bf9HRzGo02GZyXLK5pjcg77ACb4dmtwV+NlSqZQ6J7BZaIRKNHUGL2T
         fbK93SrKuA+FnD+kJEEhRBfAyWxSILmUGMS2vGu5e3z7bQwxdZKxL/PfCe4+BI0cf7U+
         iW1g==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b="k7Zmm/l4";
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout2.w1.samsung.com (mailout2.w1.samsung.com. [210.118.77.12])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45cb535ca72si1938195e9.1.2025.09.05.09.26.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 05 Sep 2025 09:26:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.12 as permitted sender) client-ip=210.118.77.12;
Received: from eucas1p1.samsung.com (unknown [182.198.249.206])
	by mailout2.w1.samsung.com (KnoxPortal) with ESMTP id 20250905162659euoutp0209439914e512e98f87c7003f3b7cb2ad~ib7L2Tvq02121121211euoutp02j;
	Fri,  5 Sep 2025 16:26:59 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout2.w1.samsung.com 20250905162659euoutp0209439914e512e98f87c7003f3b7cb2ad~ib7L2Tvq02121121211euoutp02j
Received: from eusmtip2.samsung.com (unknown [203.254.199.222]) by
	eucas1p1.samsung.com (KnoxPortal) with ESMTPA id
	20250905162658eucas1p1a568426150516afc440f0b45dae6597c~ib7LZwBNr2591525915eucas1p15;
	Fri,  5 Sep 2025 16:26:58 +0000 (GMT)
Received: from [106.210.134.192] (unknown [106.210.134.192]) by
	eusmtip2.samsung.com (KnoxPortal) with ESMTPA id
	20250905162656eusmtip2af2311515d499a88f1b631068b965d1d~ib7JPIWTy2564625646eusmtip2E;
	Fri,  5 Sep 2025 16:26:56 +0000 (GMT)
Message-ID: <afcd9cd4-d563-41c3-9e50-7440365b9152@samsung.com>
Date: Fri, 5 Sep 2025 18:26:55 +0200
MIME-Version: 1.0
User-Agent: Betterbird (Windows)
Subject: Re: [PATCH v4 03/16] dma-debug: refactor to use physical addresses
 for page mapping
To: Leon Romanovsky <leon@kernel.org>
Cc: Leon Romanovsky <leonro@nvidia.com>, Jason Gunthorpe <jgg@nvidia.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>, Alexander Potapenko
	<glider@google.com>, Alex Gaynor <alex.gaynor@gmail.com>, Andrew Morton
	<akpm@linux-foundation.org>, Christoph Hellwig <hch@lst.de>, Danilo
	Krummrich <dakr@kernel.org>, iommu@lists.linux.dev, Jason Wang
	<jasowang@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joerg Roedel
	<joro@8bytes.org>, Jonathan Corbet <corbet@lwn.net>, Juergen Gross
	<jgross@suse.com>, kasan-dev@googlegroups.com, Keith Busch
	<kbusch@kernel.org>, linux-block@vger.kernel.org, linux-doc@vger.kernel.org,
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
In-Reply-To: <478d5b7135008b3c82f100faa9d3830839fc6562.1755624249.git.leon@kernel.org>
X-CMS-MailID: 20250905162658eucas1p1a568426150516afc440f0b45dae6597c
X-Msg-Generator: CA
Content-Type: text/plain; charset="UTF-8"
X-RootMTR: 20250819173739eucas1p104ee9e80546f92ef250115edd799fc6d
X-EPHeader: CA
X-CMS-RootMailID: 20250819173739eucas1p104ee9e80546f92ef250115edd799fc6d
References: <cover.1755624249.git.leon@kernel.org>
	<CGME20250819173739eucas1p104ee9e80546f92ef250115edd799fc6d@eucas1p1.samsung.com>
	<478d5b7135008b3c82f100faa9d3830839fc6562.1755624249.git.leon@kernel.org>
X-Original-Sender: m.szyprowski@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b="k7Zmm/l4";
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates
 210.118.77.12 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
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

On 19.08.2025 19:36, Leon Romanovsky wrote:
> From: Leon Romanovsky <leonro@nvidia.com>
>
> Convert the DMA debug infrastructure from page-based to physical address-based
> mapping as a preparation to rely on physical address for DMA mapping routines.
>
> The refactoring renames debug_dma_map_page() to debug_dma_map_phys() and
> changes its signature to accept a phys_addr_t parameter instead of struct page
> and offset. Similarly, debug_dma_unmap_page() becomes debug_dma_unmap_phys().
> A new dma_debug_phy type is introduced to distinguish physical address mappings
> from other debug entry types. All callers throughout the codebase are updated
> to pass physical addresses directly, eliminating the need for page-to-physical
> conversion in the debug layer.
>
> This refactoring eliminates the need to convert between page pointers and
> physical addresses in the debug layer, making the code more efficient and
> consistent with the DMA mapping API's physical address focus.
>
> Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
> Signed-off-by: Leon Romanovsky <leonro@nvidia.com>

This change needs to be based on top of this patch 
https://lore.kernel.org/all/20250828-dma-debug-fix-noncoherent-dma-check-v1-1-76e9be0dd7fc@oss.qualcomm.com 
so the easiest way would be to rebase this patchset onto 
https://web.git.kernel.org/pub/scm/linux/kernel/git/mszyprowski/linux.git/log/?h=dma-mapping-fixes 
branch (resolving conflicts is trivial) for the next version.

> ---
>   Documentation/core-api/dma-api.rst |  4 ++--
>   kernel/dma/debug.c                 | 28 +++++++++++++++++-----------
>   kernel/dma/debug.h                 | 16 +++++++---------
>   kernel/dma/mapping.c               | 15 ++++++++-------
>   4 files changed, 34 insertions(+), 29 deletions(-)
>
> diff --git a/Documentation/core-api/dma-api.rst b/Documentation/core-api/dma-api.rst
> index 3087bea715ed..ca75b3541679 100644
> --- a/Documentation/core-api/dma-api.rst
> +++ b/Documentation/core-api/dma-api.rst
> @@ -761,7 +761,7 @@ example warning message may look like this::
>   	[<ffffffff80235177>] find_busiest_group+0x207/0x8a0
>   	[<ffffffff8064784f>] _spin_lock_irqsave+0x1f/0x50
>   	[<ffffffff803c7ea3>] check_unmap+0x203/0x490
> -	[<ffffffff803c8259>] debug_dma_unmap_page+0x49/0x50
> +	[<ffffffff803c8259>] debug_dma_unmap_phys+0x49/0x50
>   	[<ffffffff80485f26>] nv_tx_done_optimized+0xc6/0x2c0
>   	[<ffffffff80486c13>] nv_nic_irq_optimized+0x73/0x2b0
>   	[<ffffffff8026df84>] handle_IRQ_event+0x34/0x70
> @@ -855,7 +855,7 @@ that a driver may be leaking mappings.
>   dma-debug interface debug_dma_mapping_error() to debug drivers that fail
>   to check DMA mapping errors on addresses returned by dma_map_single() and
>   dma_map_page() interfaces. This interface clears a flag set by
> -debug_dma_map_page() to indicate that dma_mapping_error() has been called by
> +debug_dma_map_phys() to indicate that dma_mapping_error() has been called by
>   the driver. When driver does unmap, debug_dma_unmap() checks the flag and if
>   this flag is still set, prints warning message that includes call trace that
>   leads up to the unmap. This interface can be called from dma_mapping_error()
> diff --git a/kernel/dma/debug.c b/kernel/dma/debug.c
> index e43c6de2bce4..da6734e3a4ce 100644
> --- a/kernel/dma/debug.c
> +++ b/kernel/dma/debug.c
> @@ -39,6 +39,7 @@ enum {
>   	dma_debug_sg,
>   	dma_debug_coherent,
>   	dma_debug_resource,
> +	dma_debug_phy,
>   };
>   
>   enum map_err_types {
> @@ -141,6 +142,7 @@ static const char *type2name[] = {
>   	[dma_debug_sg] = "scatter-gather",
>   	[dma_debug_coherent] = "coherent",
>   	[dma_debug_resource] = "resource",
> +	[dma_debug_phy] = "phy",
>   };
>   
>   static const char *dir2name[] = {
> @@ -1201,9 +1203,8 @@ void debug_dma_map_single(struct device *dev, const void *addr,
>   }
>   EXPORT_SYMBOL(debug_dma_map_single);
>   
> -void debug_dma_map_page(struct device *dev, struct page *page, size_t offset,
> -			size_t size, int direction, dma_addr_t dma_addr,
> -			unsigned long attrs)
> +void debug_dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
> +		int direction, dma_addr_t dma_addr, unsigned long attrs)
>   {
>   	struct dma_debug_entry *entry;
>   
> @@ -1218,19 +1219,24 @@ void debug_dma_map_page(struct device *dev, struct page *page, size_t offset,
>   		return;
>   
>   	entry->dev       = dev;
> -	entry->type      = dma_debug_single;
> -	entry->paddr	 = page_to_phys(page) + offset;
> +	entry->type      = dma_debug_phy;
> +	entry->paddr	 = phys;
>   	entry->dev_addr  = dma_addr;
>   	entry->size      = size;
>   	entry->direction = direction;
>   	entry->map_err_type = MAP_ERR_NOT_CHECKED;
>   
> -	check_for_stack(dev, page, offset);
> +	if (!(attrs & DMA_ATTR_MMIO)) {
> +		struct page *page = phys_to_page(phys);
> +		size_t offset = offset_in_page(page);
>   
> -	if (!PageHighMem(page)) {
> -		void *addr = page_address(page) + offset;
> +		check_for_stack(dev, page, offset);
>   
> -		check_for_illegal_area(dev, addr, size);
> +		if (!PageHighMem(page)) {
> +			void *addr = page_address(page) + offset;
> +
> +			check_for_illegal_area(dev, addr, size);
> +		}
>   	}
>   
>   	add_dma_entry(entry, attrs);
> @@ -1274,11 +1280,11 @@ void debug_dma_mapping_error(struct device *dev, dma_addr_t dma_addr)
>   }
>   EXPORT_SYMBOL(debug_dma_mapping_error);
>   
> -void debug_dma_unmap_page(struct device *dev, dma_addr_t dma_addr,
> +void debug_dma_unmap_phys(struct device *dev, dma_addr_t dma_addr,
>   			  size_t size, int direction)
>   {
>   	struct dma_debug_entry ref = {
> -		.type           = dma_debug_single,
> +		.type           = dma_debug_phy,
>   		.dev            = dev,
>   		.dev_addr       = dma_addr,
>   		.size           = size,
> diff --git a/kernel/dma/debug.h b/kernel/dma/debug.h
> index f525197d3cae..76adb42bffd5 100644
> --- a/kernel/dma/debug.h
> +++ b/kernel/dma/debug.h
> @@ -9,12 +9,11 @@
>   #define _KERNEL_DMA_DEBUG_H
>   
>   #ifdef CONFIG_DMA_API_DEBUG
> -extern void debug_dma_map_page(struct device *dev, struct page *page,
> -			       size_t offset, size_t size,
> -			       int direction, dma_addr_t dma_addr,
> +extern void debug_dma_map_phys(struct device *dev, phys_addr_t phys,
> +			       size_t size, int direction, dma_addr_t dma_addr,
>   			       unsigned long attrs);
>   
> -extern void debug_dma_unmap_page(struct device *dev, dma_addr_t addr,
> +extern void debug_dma_unmap_phys(struct device *dev, dma_addr_t addr,
>   				 size_t size, int direction);
>   
>   extern void debug_dma_map_sg(struct device *dev, struct scatterlist *sg,
> @@ -55,14 +54,13 @@ extern void debug_dma_sync_sg_for_device(struct device *dev,
>   					 struct scatterlist *sg,
>   					 int nelems, int direction);
>   #else /* CONFIG_DMA_API_DEBUG */
> -static inline void debug_dma_map_page(struct device *dev, struct page *page,
> -				      size_t offset, size_t size,
> -				      int direction, dma_addr_t dma_addr,
> -				      unsigned long attrs)
> +static inline void debug_dma_map_phys(struct device *dev, phys_addr_t phys,
> +				      size_t size, int direction,
> +				      dma_addr_t dma_addr, unsigned long attrs)
>   {
>   }
>   
> -static inline void debug_dma_unmap_page(struct device *dev, dma_addr_t addr,
> +static inline void debug_dma_unmap_phys(struct device *dev, dma_addr_t addr,
>   					size_t size, int direction)
>   {
>   }
> diff --git a/kernel/dma/mapping.c b/kernel/dma/mapping.c
> index 107e4a4d251d..4c1dfbabb8ae 100644
> --- a/kernel/dma/mapping.c
> +++ b/kernel/dma/mapping.c
> @@ -157,6 +157,7 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
>   		unsigned long attrs)
>   {
>   	const struct dma_map_ops *ops = get_dma_ops(dev);
> +	phys_addr_t phys = page_to_phys(page) + offset;
>   	dma_addr_t addr;
>   
>   	BUG_ON(!valid_dma_direction(dir));
> @@ -165,16 +166,15 @@ dma_addr_t dma_map_page_attrs(struct device *dev, struct page *page,
>   		return DMA_MAPPING_ERROR;
>   
>   	if (dma_map_direct(dev, ops) ||
> -	    arch_dma_map_page_direct(dev, page_to_phys(page) + offset + size))
> +	    arch_dma_map_page_direct(dev, phys + size))
>   		addr = dma_direct_map_page(dev, page, offset, size, dir, attrs);
>   	else if (use_dma_iommu(dev))
>   		addr = iommu_dma_map_page(dev, page, offset, size, dir, attrs);
>   	else
>   		addr = ops->map_page(dev, page, offset, size, dir, attrs);
>   	kmsan_handle_dma(page, offset, size, dir);
> -	trace_dma_map_page(dev, page_to_phys(page) + offset, addr, size, dir,
> -			   attrs);
> -	debug_dma_map_page(dev, page, offset, size, dir, addr, attrs);
> +	trace_dma_map_page(dev, phys, addr, size, dir, attrs);
> +	debug_dma_map_phys(dev, phys, size, dir, addr, attrs);
>   
>   	return addr;
>   }
> @@ -194,7 +194,7 @@ void dma_unmap_page_attrs(struct device *dev, dma_addr_t addr, size_t size,
>   	else
>   		ops->unmap_page(dev, addr, size, dir, attrs);
>   	trace_dma_unmap_page(dev, addr, size, dir, attrs);
> -	debug_dma_unmap_page(dev, addr, size, dir);
> +	debug_dma_unmap_phys(dev, addr, size, dir);
>   }
>   EXPORT_SYMBOL(dma_unmap_page_attrs);
>   
> @@ -712,7 +712,8 @@ struct page *dma_alloc_pages(struct device *dev, size_t size,
>   	if (page) {
>   		trace_dma_alloc_pages(dev, page_to_virt(page), *dma_handle,
>   				      size, dir, gfp, 0);
> -		debug_dma_map_page(dev, page, 0, size, dir, *dma_handle, 0);
> +		debug_dma_map_phys(dev, page_to_phys(page), size, dir,
> +				   *dma_handle, 0);
>   	} else {
>   		trace_dma_alloc_pages(dev, NULL, 0, size, dir, gfp, 0);
>   	}
> @@ -738,7 +739,7 @@ void dma_free_pages(struct device *dev, size_t size, struct page *page,
>   		dma_addr_t dma_handle, enum dma_data_direction dir)
>   {
>   	trace_dma_free_pages(dev, page_to_virt(page), dma_handle, size, dir, 0);
> -	debug_dma_unmap_page(dev, dma_handle, size, dir);
> +	debug_dma_unmap_phys(dev, dma_handle, size, dir);
>   	__dma_free_pages(dev, size, page, dma_handle, dir);
>   }
>   EXPORT_SYMBOL_GPL(dma_free_pages);

Best regards
-- 
Marek Szyprowski, PhD
Samsung R&D Institute Poland

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/afcd9cd4-d563-41c3-9e50-7440365b9152%40samsung.com.
