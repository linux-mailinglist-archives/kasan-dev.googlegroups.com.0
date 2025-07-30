Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBUWBVDCAMGQELVB4RNA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id A7A54B161AE
	for <lists+kasan-dev@lfdr.de>; Wed, 30 Jul 2025 15:40:36 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id 3f1490d57ef6-e73290d75a8sf1539640276.1
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Jul 2025 06:40:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753882835; cv=pass;
        d=google.com; s=arc-20240605;
        b=TQ1q83qFJFwMZYStggonbJvPkp7kbLAVmMDgEHGF6TS0POt77mpG4qNgo33nqvf6YL
         KFowZSGPHr9wB9Z6ngVkCHSNu8s+0hK4cD07QpVcwjd6zskAO4NZNHGwiGf+KAoW/lRS
         RX98RmC8xeP3fwkKZjqtEzNWxedvniSP6PeRFX2mbcI+23w+k9CsW0iL38qaXV1gfFSX
         JSu6fsiW5VkLYmlFtzhQwGegSTEJVU7HBT0XnqTewNCm9UIZ7OkTd2aRoTlQ0Q4XJ3Qk
         ZHNlmVf8rygDne7MyN3BAv/XRSj4YOk49DPhoNDPTcKkp2wUe3H+faa3azI/orEZKoms
         M3kQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=ZB64VXJu2TWxv+tf2MHz2yCfGylRkfOZ4HSfjiWDz3Q=;
        fh=Cl6UKBFg9Nv1G+lcOLO+E8hJj5H3fV4G1PBOcINVcvA=;
        b=JyGRzTKAkks8ntwcMyP1r+r7u3WtBZ7Ux4crtoo+C5+4aLBH1iPrIxn5CjeqPcYVe/
         Vj0c7XZm4ZcPgcgUyQu6h0amESknwM/2yGPvAhkfVB+wRwoW7pfXBYXcAnDOnW2NYUd3
         zh/vZ3OY0ix9zuGZ+jJ74CTo2u+D/Fiox1ZJsjcFA+ie1a6CO9VWh8PV8q51kKRH64LE
         /gnbmWqi4wigyznU5gGaB1a37JPQkOjVYOP/Nb/tcTO1lWCJetKVJkRs5rcM/03ZFgF4
         qYYCGF4LI2mipWiqbXbbBAFNGy1XW3P3h6Wk9lwIMw1WXG04jLcXC6bDKhIJc9HmPWha
         HR/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=m8TgLaML;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753882835; x=1754487635; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=ZB64VXJu2TWxv+tf2MHz2yCfGylRkfOZ4HSfjiWDz3Q=;
        b=le8Ldc/5r9RbDdf0J/4QYI39Fy12L65OdIEXQ63+LtJhtF0xwza4UNAj0mu0zfrszW
         v35rLDJkjz9Yjtqnr0dHAg005PiKExmw/Gchh+KrraNUkWiEDkLbjWmVQFQM8xNx73HA
         /wSnoFexGeqh4GSkIm30xJ3S/tn5gg2GcIBRzCzwSbgqKPXRZuWoMooM1+pnYyHBUC6M
         dt1eq310pUkBRE4A7FVlatcBEuUld01Kj65A8wFwPa8EK73OmiJNupOixTMp5uJ0RxUI
         bRa4IbzB2nu1ATeL3AbS59F+LLraJmkRlj3x6hyH6BVyw/YCOmCx3nEEJYqal4cVddZZ
         YGew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753882835; x=1754487635;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ZB64VXJu2TWxv+tf2MHz2yCfGylRkfOZ4HSfjiWDz3Q=;
        b=DVjjJy93zxpcEicUi4F8phwnQ8J9M1tOpcSyigOQ2iyyn+NVkO91zxj4FsUW3qyhA0
         2O/GhUAfR+X5/yH9h8WYIajMC96NqExbsSxVVdj3NT4Ih9oLanP7xCgwcY6yJCFTOPHb
         sf2N+/dkZrg7oF8PKvybtBT3Chm6fH0WgDZ92AYInWxetTFJUt+19zRI7kMcOJzZQp8U
         PRnYzBns0RaMPGOZx8ei7wVYA3wjCJLd7IwtAqnBn9us0TFm802UB6pb/jBbxGnkA5Sz
         nFqdVRdglDWmvn9BGBMJ6bjl48OpAXnm6ri/FTCWstsEUz4HX4fviR/6zyjfMkheM0LB
         6mOw==
X-Forwarded-Encrypted: i=2; AJvYcCXU/UbSeAIz+XZvV2YeJGqU+0/ykaXKtL9c7cTumpiRjxBjHtcOXGRwXBwniqsauThauU50kg==@lfdr.de
X-Gm-Message-State: AOJu0Ywvz3or/x37URJGiRU8q3vLC2nKg+Ul9WT7mAyR32pdyXKCQJfn
	H7Yv81fm6rQua/uH0kqR7LzdiaKnHemCX3gXR0i2vuHARv5qzx3rSmmw
X-Google-Smtp-Source: AGHT+IHENmB9MAFM9OORVd9AftrdcY3At1cXExaGgqheFSJPfnYGI30bzhbwtgDk+g7Lq0roJAXilw==
X-Received: by 2002:a05:6902:2484:b0:e8b:5465:fd73 with SMTP id 3f1490d57ef6-e8e3148441emr3700890276.4.1753882834944;
        Wed, 30 Jul 2025 06:40:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcaYZcCSp1mapI07lz8T7Dmy1m0+pL9xhNNupJVWNvxPg==
Received: by 2002:a25:350a:0:b0:e8e:1672:b04e with SMTP id 3f1490d57ef6-e8e1672fd3als2837270276.2.-pod-prod-01-us;
 Wed, 30 Jul 2025 06:40:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVKO1vDGJdr6s69xt13nnJJ2uz7TCQRqMBJqRluEdooP8707tUR/743SEyDIPo/Gip+75XXL5FCI7M=@googlegroups.com
X-Received: by 2002:a05:690c:c08:b0:719:559f:3320 with SMTP id 00721157ae682-71a4656d453mr46008977b3.14.1753882833785;
        Wed, 30 Jul 2025 06:40:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753882833; cv=none;
        d=google.com; s=arc-20240605;
        b=RXOAcCEWgXSykGpQws9pw6In5URwRC7mVjvjJ51ajnrnnXfcvz48Qj0mBGfYSLBh9+
         XdDwO3ccvVBpFiGglytasq7MKaUaNbg1ju6fJaNEMAIt2DQ7MooGY2FwacjE7rg0kach
         gp4YO4d/HXVVKGUV70uoIis9kVn2IrAZZpePBnKvdG6RlosaWB3YtIm/qPzIdRey6+1V
         bHjyDjDUhyjUutnrEgtfSMzhFnIR1gA7LqT9sS2qzU0E8E6g/ov2UCZkmXvgY7mBAD6l
         56tcCGw21V2tTPfV7mQGCLdGFn5/t6SRGfA7GHuGkXbXmOF0TJOzMAbn26odeHfxh7n5
         xdjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=DwI8HW24x7jyl46fjynmA/WxmX0LnPGEQIHuMkllTKQ=;
        fh=NUaCMTTkjQWu0it4bf5GqqEpNV5PLtKEbTvHyNurJss=;
        b=GEEL9tn3J3G9+8wRYKwY/yMjbIyo5WAtDKuKemyMYZ6t/bwY1s3jqwkxEOo5/nc6Jx
         YsGxlV0rgW9RBSoTLqk2r4dvgNYpn/sX51IsrAEsbIy5CHvDtdDwPfghcBUXdH79cT75
         bUF2Jngz7zlt3QmSdaMO/cbeLBtVzBhbkcCU6Zzok14i0FAoqurOfV0fHb6cWRA6kg7A
         d+PVPB1Ytbs0Hn5ENamw4kMK87WoBoy9JG5L9W4nMofWI17BiFb6PG3dKqAEpLCWwDBJ
         CcAUQa4GktPswjzXZaIeGiCewvbdUc5/JaM5ieZU6GP3Pd+9kT1EOZ0dBhIGY2avhqsM
         m7Yg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=m8TgLaML;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from nyc.source.kernel.org (nyc.source.kernel.org. [2604:1380:45d1:ec00::3])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-71a26a02b82si4312287b3.0.2025.07.30.06.40.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Jul 2025 06:40:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2604:1380:45d1:ec00::3 as permitted sender) client-ip=2604:1380:45d1:ec00::3;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by nyc.source.kernel.org (Postfix) with ESMTP id 67A16A5525C;
	Wed, 30 Jul 2025 13:40:33 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 640CCC4CEE7;
	Wed, 30 Jul 2025 13:40:32 +0000 (UTC)
Date: Wed, 30 Jul 2025 16:40:26 +0300
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Robin Murphy <robin.murphy@arm.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Christoph Hellwig <hch@lst.de>, Jonathan Corbet <corbet@lwn.net>,
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
Message-ID: <20250730134026.GQ402218@unreal>
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
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=m8TgLaML;       spf=pass
 (google.com: domain of leon@kernel.org designates 2604:1380:45d1:ec00::3 as
 permitted sender) smtp.mailfrom=leon@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
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

On Wed, Jul 30, 2025 at 12:11:32PM +0100, Robin Murphy wrote:
> On 2025-07-08 11:27 am, Marek Szyprowski wrote:
> > On 30.06.2025 15:38, Christoph Hellwig wrote:
> > > On Fri, Jun 27, 2025 at 08:02:13PM +0300, Leon Romanovsky wrote:
> > > > > Thanks for this rework! I assume that the next step is to add map_phys
> > > > > callback also to the dma_map_ops and teach various dma-mapping providers
> > > > > to use it to avoid more phys-to-page-to-phys conversions.
> > > > Probably Christoph will say yes, however I personally don't see any
> > > > benefit in this. Maybe I wrong here, but all existing .map_page()
> > > > implementation platforms don't support p2p anyway. They won't benefit
> > > > from this such conversion.
> > > I think that conversion should eventually happen, and rather sooner than
> > > later.
> > 
> > Agreed.
> > 
> > Applied patches 1-7 to my dma-mapping-next branch. Let me know if one
> > needs a stable branch with it.
> 
> As the maintainer of iommu-dma, please drop the iommu-dma patch because it
> is broken. It does not in any way remove the struct page dependency from
> iommu-dma, it merely hides it so things can crash more easily in
> circumstances that clearly nobody's bothered to test.
> 
> > Leon, it would be great if You could also prepare an incremental patch
> > adding map_phys callback to the dma_maps_ops, so the individual
> > arch-specific dma-mapping providers can be then converted (or simplified
> > in many cases) too.
> 
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
> 
> Simply obfuscating the struct page dependency today by dressing it up as a
> phys_addr_t with implicit baggage is not not in any way helpful. It only
> makes the code harder to understand and more bug-prone. Despite the
> disingenuous claims, it is quite blatantly the opposite of "efficient" for
> callers to do extra work to throw away useful information with
> page_to_phys(), and the implementation then have to re-derive that
> information with pfn_valid()/phys_to_page().
> 
> And by "bug-prone" I also include greater distractions like this misguided
> idea that the same API could somehow work for non-memory addresses too, so
> then everyone can move on bikeshedding VFIO while overlooking the
> fundamental flaws in the whole premise. I mean, besides all the issues I've
> already pointed out in that regard, not least the glaring fact that it's
> literally just a worse version of *an API we already have*, as DMA API
> maintainer do you *really* approve of a design that depends on callers
> abusing DMA_ATTR_SKIP_CPU_SYNC, yet will still readily blow up if they did
> then call a dma_sync op?

Robin, Marek

I would like to ask you to do not drop this series and allow me to
gradually change the code during my VFIO DMABUF adventure.

The most reasonable way to prevent DMA_ATTR_SKIP_CPU_SYNC leakage is to
introduce new DMA attribute (let's call it DMA_ATTR_MMIO for now) and
pass it to both dma_map_phys() and dma_iova_link(). This flag will
indicate that p2p type is PCI_P2PDMA_MAP_THRU_HOST_BRIDGE and call to
right callbacks which will set IOMMU_MMIO flag and skip CPU sync,

dma_map_phys() isn't entirely wrong, it just needs an extra tweaks.

Thanks

> 
> Thanks,
> Robin.
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250730134026.GQ402218%40unreal.
