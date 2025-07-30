Return-Path: <kasan-dev+bncBCUO3AHUWUIRBBOYVDCAMGQED5TIU4A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73a.google.com (mail-qk1-x73a.google.com [IPv6:2607:f8b0:4864:20::73a])
	by mail.lfdr.de (Postfix) with ESMTPS id CE5E7B162C3
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Jul 2025 16:28:23 +0200 (CEST)
Received: by mail-qk1-x73a.google.com with SMTP id af79cd13be357-7e32df3ace0sf587398685a.0
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Jul 2025 07:28:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753885702; cv=pass;
        d=google.com; s=arc-20240605;
        b=Uu1JyynVboKvPS0vQ8U8IHGojaFwRvgY7Mq+4xshpITjPmATMcZOM0qFcZFUYXaurF
         HBfABVvVZWACDhV5ioQ66slxMavt0noDFHC8/NXZ3ICtU3NSSm/NGjLZLhIKAp2SMvA6
         7SXbhuX1skyUK2DXjKBIz2vmRshfuRP7cJ6aUCPtbTfd1ZkIeAg+znzeUrYvOjuVIdDf
         /YdRP8gtYE0jx9Z6ow3RAy0HLUzQmkA161k+ZVkdaxybnnkFdf70abxgD9rA0QTXtyEU
         JOvEZpJblWbR/Ul4n95l3a7N+rgx0uK2AkUvKStj/ZJ+9aDaLorDMDwls1b9BwUNiVCe
         zHQQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=34kneYeydp+ov9Y2sb/JmKfPJHQ1bzu3kEmL2Ia9Duc=;
        fh=s/s/VlsvugBNNjf5Py6aPM46FIRnS3wPw4jkEps+IyY=;
        b=jQSlUgnruBVORK0EtqbS7OLVTe2m4qj6/rHdkVkr9oPMIhTbKozRoI91Ev905KLGhk
         cLOQa97fW8bLOzGYwzvDIOJ2tSgAOlVo5XdP2/jzgX7wEDZb35ZhNv7+OQGJVbun63zp
         kJl3l3VMnXvMSXOlelZ/VQ0HcnyNwd1LEfkQusGaZdzpbxd3tawEL5gtuM9fkxFWSZm9
         mFfPPD7F3k9P6Vm0xDXhaDDiFbowc80ayU8dDyiuiat6htvyq0jdhmqlBJASjhf0g8Xa
         1d2O91UlzQ4+a+4LJnwLpG6CvNzgGj9pc1eN9EqXNGYT0Fph02ST5mFs2KhyK6m6/8Rj
         r4zA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ziepe.ca header.s=google header.b=fMonTXHA;
       spf=pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=jgg@ziepe.ca;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753885702; x=1754490502; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=34kneYeydp+ov9Y2sb/JmKfPJHQ1bzu3kEmL2Ia9Duc=;
        b=SXahs/RRo4F7Xg+OzB/iVQvOhI6cJ5p52i0GoqqjLN50PW/zQ4c10oW4Qaj3Qe6GCW
         7stETkuyo+gx4miDSdoytZsczT4wQklkRHoOfG1UdrEsDobaJg3adyWZuM0clO4Vuits
         ERRXsswiBaHJfPxbUwSD9GyMsjEDbx0TVQNlXdi+5+LdGVIsZB6JXsiKdosBElAT8O9x
         ysqWZNqa5VfCufNTF8XvGrCcMomYdNKtZjaVfgJQEqcwbZRb2A0PzhILDcCEUGO6u2TC
         xY9hKjteJ7n73DHCQRHbli96JRUFVfdCvZlfRat7DokAlXiRyBhF3pa+POldtA9srzHX
         1PyQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753885702; x=1754490502;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=34kneYeydp+ov9Y2sb/JmKfPJHQ1bzu3kEmL2Ia9Duc=;
        b=WvxWq0BDhE8AVt0xGPMshLKXMoOjoIiTrsU8kYGsPPvBlfnXtGtp/TDzXRmyxeSU28
         XFYvz9q/7UhU1hmxhosDdcqHuBaedmySjAv2OqhKCyZdyqtLmvMqtVim2NR+jip2B06h
         QFlaK45Uxp66n5MUwr4mlhWgbiNLFfWzMkPNznU3ZK3gnO7Qxs4dMgIt6QZsr0aJFIaM
         o09nRxoluGn1/oa+hFIwedk9GFy1w3H3PzPPQuYXS67AZmWtT4E0GC4QwU0NWdVhLMpu
         TZgIpz1lZo4RlQfHEPDtX0pLjCW317M0EHswbOd9wZ4/cZpgNfm8IcDeInNxE35bhTVr
         czOw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXyr08r9XwPQ6fuBOAecXUOaiWlChRhzfAoNdo4EdConXsx7nuuLOcuS4svROL95AmX7BTC+w==@lfdr.de
X-Gm-Message-State: AOJu0YzMXa48WglKG4lf3Pa6rW8bD0d3PBE3FgpFGMa4gerEU7y+o3TP
	oSSF4FI4MnyVJS0AbZMkWIzKjr/KveWhjXxv5MpH64u8pUqMbmei+cDY
X-Google-Smtp-Source: AGHT+IE+dUg9N1HGq/tzHTHUZbxeEfCaLZ+01PgT9D1kcZijABlq86Qmn0g1GJ+Q4pkkyDCjONnnXg==
X-Received: by 2002:a05:620a:3198:b0:7e3:4416:fd6 with SMTP id af79cd13be357-7e66f3ea581mr520905785a.61.1753885701875;
        Wed, 30 Jul 2025 07:28:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZecXrdD6Gr9G7NawXVk5xYTwFW3QKZ/r6WuxTOPsRW0Xw==
Received: by 2002:ac8:5702:0:b0:4ab:70e4:7a4a with SMTP id d75a77b69052e-4ae7bd64649ls112714411cf.2.-pod-prod-08-us;
 Wed, 30 Jul 2025 07:28:21 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUJ3F0T2BBXwysPcvTFWMcMK9wmpfzneaefx2+X8XBpJAKB0QkEdEiVdnODXW97eYp2T0ZMyCZ9lwI=@googlegroups.com
X-Received: by 2002:ac8:7f56:0:b0:4a7:2f49:37d6 with SMTP id d75a77b69052e-4aedb98177emr50256011cf.5.1753885701132;
        Wed, 30 Jul 2025 07:28:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753885701; cv=none;
        d=google.com; s=arc-20240605;
        b=ArNmD4xYY+a+WnTv0lXeu+WO0VHC3At4dMJPQtuVR84i74IrC65uQUcnCLuIeEbZVa
         g+4ELS2mHUebNUUfI/Uo2uJnASx2YmSiHV0nEmZP1iwNMcvHoGR8ctNFtVntNtgsroj1
         pfinMWG47AZXcQHo3KvIPC9sp/Ief6FZEbmNm6loKRalSidq5srJuzqoRwraYH7dYvh6
         1a/CPtTnyEokaBqjOf314mmxLIYznejGlml/eBSdDYFyuGdbY3MtsfvNLU+pBHQY8W8L
         ZGwAq+vJdW97hfRSYpJ881zN2S0LDywOPh8sYrobBqDhHDkVaCK35Goi1zigxO+keYf5
         Sv4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=yXicpotvi3lyQ9AOXQWfwG3KeaAtrSGGP0WC4PeRJ0I=;
        fh=swQjXkXT06rHhPU0EenO1TGWb3tmLfzf1Nq8y1C3iF4=;
        b=ljlS2cuCnGA0OCZdMbAHoDm37XykqjWZI3NAVqhzKyTF6bWnoz8tj6VZ3o4iwA7CiR
         hsa4aqNeaKxsOcFyisAC1t5MH7+IDFd08MPQw+ELPudwGIaIEoq2caB7fMr7RzgCpk9A
         G/RVl9ZmtLfj0IT4fchmnZBT86ZIC1cFWjOVrSe8zAp9t5S9GecT37ZDWH4Ph0it0NsJ
         GbuMWNdhU3uWyqu8qwS8wuuYag9V3p8NHvOfp39zLFvWBmrxuZX9dSte8WrPz3GC42CN
         QOcS/L8t6h/JIM327z5p3M2qaG6UjJD5iSzBVwiHLq9KbxTlL4bBm2HuVgIuG0IJ3sRi
         SCmg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ziepe.ca header.s=google header.b=fMonTXHA;
       spf=pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::832 as permitted sender) smtp.mailfrom=jgg@ziepe.ca;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x832.google.com (mail-qt1-x832.google.com. [2607:f8b0:4864:20::832])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4ae98e035b7si1571471cf.2.2025.07.30.07.28.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 30 Jul 2025 07:28:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::832 as permitted sender) client-ip=2607:f8b0:4864:20::832;
Received: by mail-qt1-x832.google.com with SMTP id d75a77b69052e-4aaaf1a63c1so47428981cf.3
        for <kasan-dev@googlegroups.com>; Wed, 30 Jul 2025 07:28:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXt66E9hKrHb5arUCDJMijSxHNlpD2mfXoS5z3bJ3JHxF5idjytAqWfJKtohQaC7URLcJT2YKOxBxo=@googlegroups.com
X-Gm-Gg: ASbGnctn6MGFTT8fryfW1ftieb8t2qeIQ/2g9ex70eDPSLAvFrX+cMPu+0l7fJlBPtf
	aRG97R6p6nAokso+SeW2ma8dfs6W9WHW5+rKmcKKtOal2ON1KxrMfBpoF8i2EtlDRzT4we4xRtu
	4gNHPEYvX+zYz47CQAGEDBF2Bip+jDwCHvozCwoPscv1bGtx9kYcR7RBBNULCcHb4/wYe8iIfvP
	xapJRuU22HqeFu/W0SQ3vIJAf8mjk/J1qT1x4KUusNUdVEAzrbmEn+3FY5/LU/9ruEDcUHWUqEM
	2JypSsZTFR/iL+nQuMKkIhxUT1RzGtzq7H6cvG7Rp17nocuFoH2Hh+4DzcV/ZD/X08nE4U0gFyl
	hUwk/lkFJ6v40EuKxdV1VNscayupzC1c8ziZJ/8jw65N8MMnZ7N9yIvUbJcBZUwWYi1/s
X-Received: by 2002:a05:622a:48:b0:4a9:cff3:68a2 with SMTP id d75a77b69052e-4aedbc3c0dbmr55369321cf.37.1753885700213;
        Wed, 30 Jul 2025 07:28:20 -0700 (PDT)
Received: from ziepe.ca (hlfxns017vw-47-55-120-4.dhcp-dynamic.fibreop.ns.bellaliant.net. [47.55.120.4])
        by smtp.gmail.com with ESMTPSA id d75a77b69052e-4ae9963b6f9sm67178931cf.35.2025.07.30.07.28.19
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Jul 2025 07:28:19 -0700 (PDT)
Received: from jgg by wakko with local (Exim 4.97)
	(envelope-from <jgg@ziepe.ca>)
	id 1uh7n0-00000000RbZ-432A;
	Wed, 30 Jul 2025 11:28:18 -0300
Date: Wed, 30 Jul 2025 11:28:18 -0300
From: Jason Gunthorpe <jgg@ziepe.ca>
To: Leon Romanovsky <leon@kernel.org>, Matthew Wilcox <willy@infradead.org>,
	David Hildenbrand <david@redhat.com>
Cc: Robin Murphy <robin.murphy@arm.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Christoph Hellwig <hch@lst.de>, Jonathan Corbet <corbet@lwn.net>,
	Madhavan Srinivasan <maddy@linux.ibm.com>,
	Michael Ellerman <mpe@ellerman.id.au>,
	Nicholas Piggin <npiggin@gmail.com>,
	Christophe Leroy <christophe.leroy@csgroup.eu>,
	Joerg Roedel <joro@8bytes.org>, Will Deacon <will@kernel.org>,
	"Michael S. Tsirkin" <mst@redhat.com>,
	Jason Wang <jasowang@redhat.com>,
	Xuan Zhuo <xuanzhuo@linux.alibaba.com>,
	Eugenio =?utf-8?B?UMOpcmV6?= <eperezma@redhat.com>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Masami Hiramatsu <mhiramat@kernel.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	=?utf-8?B?SsOpcsO0bWU=?= Glisse <jglisse@redhat.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org,
	linuxppc-dev@lists.ozlabs.org, iommu@lists.linux.dev,
	virtualization@lists.linux.dev, kasan-dev@googlegroups.com,
	linux-trace-kernel@vger.kernel.org, linux-mm@kvack.org
Subject: Re: [PATCH 0/8] dma-mapping: migrate to physical address-based API
Message-ID: <20250730142818.GL26511@ziepe.ca>
References: <CGME20250625131920eucas1p271b196cde042bd39ac08fb12beff5baf@eucas1p2.samsung.com>
 <cover.1750854543.git.leon@kernel.org>
 <35df6f2a-0010-41fe-b490-f52693fe4778@samsung.com>
 <20250627170213.GL17401@unreal>
 <20250630133839.GA26981@lst.de>
 <69b177dc-c149-40d3-bbde-3f6bad0efd0e@samsung.com>
 <f912c446-1ae9-4390-9c11-00dce7bf0fd3@arm.com>
 <20250730134026.GQ402218@unreal>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250730134026.GQ402218@unreal>
X-Original-Sender: jgg@ziepe.ca
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ziepe.ca header.s=google header.b=fMonTXHA;       spf=pass
 (google.com: domain of jgg@ziepe.ca designates 2607:f8b0:4864:20::832 as
 permitted sender) smtp.mailfrom=jgg@ziepe.ca;       dara=pass header.i=@googlegroups.com
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

On Wed, Jul 30, 2025 at 04:40:26PM +0300, Leon Romanovsky wrote:

> > The natural working unit for whatever replaces dma_map_page() will be
> > whatever the replacement for alloc_pages() returns, and the replacement for
> > kmap_atomic() operates on. Until that exists (and I simply cannot believe it
> > would be an unadorned physical address) there cannot be any
> > *meaningful*

alloc_pages becomes legacy.

There will be some new API 'memdesc alloc'. If I understand Matthew's
plan properly - here is a sketch of changing iommu-pages:

--- a/drivers/iommu/iommu-pages.c
+++ b/drivers/iommu/iommu-pages.c
@@ -36,9 +36,10 @@ static_assert(sizeof(struct ioptdesc) <= sizeof(struct page));
  */
 void *iommu_alloc_pages_node_sz(int nid, gfp_t gfp, size_t size)
 {
+       struct ioptdesc *desc;
        unsigned long pgcnt;
-       struct folio *folio;
        unsigned int order;
+       void *addr;
 
        /* This uses page_address() on the memory. */
        if (WARN_ON(gfp & __GFP_HIGHMEM))
@@ -56,8 +57,8 @@ void *iommu_alloc_pages_node_sz(int nid, gfp_t gfp, size_t size)
        if (nid == NUMA_NO_NODE)
                nid = numa_mem_id();
 
-       folio = __folio_alloc_node(gfp | __GFP_ZERO, order, nid);
-       if (unlikely(!folio))
+       addr = memdesc_alloc_pages(&desc, gfp | __GFP_ZERO, order, nid);
+       if (unlikely(!addr))
                return NULL;
 
        /*
@@ -73,7 +74,7 @@ void *iommu_alloc_pages_node_sz(int nid, gfp_t gfp, size_t size)
        mod_node_page_state(folio_pgdat(folio), NR_IOMMU_PAGES, pgcnt);
        lruvec_stat_mod_folio(folio, NR_SECONDARY_PAGETABLE, pgcnt);
 
-       return folio_address(folio);
+       return addr;
 }

Where the memdesc_alloc_pages() will kmalloc a 'struct ioptdesc' and
some other change so that virt_to_ioptdesc() indirects through a new
memdesc. See here:

https://kernelnewbies.org/MatthewWilcox/Memdescs

We don't end up with some kind of catch-all struct to mean 'cachable
CPU memory' anymore because every user gets their own unique "struct
XXXdesc". So the thinking has been that the phys_addr_t is the best
option. I guess the alternative would be the memdesc as a handle, but
I'm not sure that is such a good idea. 

People still express a desire to be able to do IO to cachable memory
that has a KVA through phys_to_virt but no memdesc/page allocation. I
don't know if this will happen but it doesn't seem like a good idea to
make it impossible by forcing memdesc types into low level APIs that
don't use them.

Also, the bio/scatterlist code between pin_user_pages() and DMA
mapping is consolidating physical contiguity. This runs faster if you
don't have to to page_to_phys() because everything is already
phys_addr_t.

> > progress made towards removing the struct page dependency from the DMA API.
> > If there is also a goal to kill off highmem before then, then logically we
> > should just wait for that to land, then revert back to dma_map_single()
> > being the first-class interface, and dma_map_page() can turn into a trivial
> > page_to_virt() wrapper for the long tail of caller conversions.

As I said there are many many projects related here and we can
meaningfully make progress in parts. It is not functionally harmful to
do the phys to page conversion before calling the legacy
dma_ops/SWIOTLB etc. This avoids creating patch dependencies with
highmem removal and other projects.

So long as the legacy things (highmem, dma_ops, etc) continue to work
I think it is OK to accept some obfuscation to allow the modern things
to work better. The majority flow - no highmem, no dma ops, no
swiotlb, does not require struct page. Having to do

  PTE -> phys -> page -> phys -> DMA

Does have a cost.

> The most reasonable way to prevent DMA_ATTR_SKIP_CPU_SYNC leakage is to
> introduce new DMA attribute (let's call it DMA_ATTR_MMIO for now) and
> pass it to both dma_map_phys() and dma_iova_link(). This flag will
> indicate that p2p type is PCI_P2PDMA_MAP_THRU_HOST_BRIDGE and call to
> right callbacks which will set IOMMU_MMIO flag and skip CPU sync,

So the idea is if the memory is non-cachable, no-KVA you'd call
dma_iova_link(phys_addr, DMA_ATTR_MMIO) and dma_map_phys(phys_addr,
DMA_ATTR_MMIO) ?

And then internally the dma_ops and dma_iommu would use the existing
map_page/map_resource variations based on the flag, thus ensuring that
MMIO is never kmap'd or cache flushed?

dma_map_resource is really then just
dma_map_phys(phys_addr, DMA_ATTR_MMIO)?

I like this, I think it well addresses the concerns.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250730142818.GL26511%40ziepe.ca.
