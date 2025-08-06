Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBLOCZ3CAMGQEPYTTVDQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 31049B1CC04
	for <lists+kasan-dev@lfdr.de>; Wed,  6 Aug 2025 20:38:40 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-31ea10f801asf355448a91.3
        for <lists+kasan-dev@lfdr.de>; Wed, 06 Aug 2025 11:38:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754505518; cv=pass;
        d=google.com; s=arc-20240605;
        b=CaSiW+eynyV1JBDil9ExsJK1YCrI9E9PczaozSYFsbRFnQyCMgYa4/3DbkYyeBazy0
         sV7sNpdram2MJEkgHhkO1qYfBhMKGX4hlNQWqOUnvY2P610vdvygXWyNWgU+x0WOUfSt
         j5UiTaEtVqoAqGwXwPOrfnQKDijfI8FYbaYG8HdU4zxLxqTKTOiej/iTg79bm3zf9ZuN
         YaegBfbFGPvi+kX9KlKZbNoZ7SLe5rY9ZBuEblUBF16dEn12LHBfd0XyfNbB1C5eSD6Q
         HqiIt0micoWs7KLPZCGaXUUSygPhNCoqL1RQ0DbzigWnn6HLIgsjLJenHEuHj9tidFF0
         V6+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=+YFpXW3yrjECJx7vi7MVyVNrhkpT/7G3DrMzdSM8sxQ=;
        fh=HmrnEAfkbuTcZtYGyqgZRv7aV98NFdqXcVUUEbs55cs=;
        b=Ocfr8y7qsPjP1NsdCDcv718rlM0LDHPPJhpyUDA+qL200HnJkJsmXfAIvW/knksUuX
         D4NQqXz73gwY5aAOmyhdPVWeXyVS+QbAqNf9940HcivU9BY4O//s27vNW+4Hp0Y5YS2d
         VZdup4SOe/PlTq1kEzTl2nMZyXx3x0t7+ovMm0VtRucYjTji2gX/3Pgqnz3eujZEH6vP
         O2pm32EfpUGRbla4ei/rehADprJVU1QCwThRxYnFgCtuADNX8jtb8z0M2OJSiua7eKUr
         Swg92sEGno9xQq7GJiWWWXTvncYfHvYvBET8CHuIWz8OT+QZjseyo0i3qweNUcSkUZ6b
         VAuw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ge50qjue;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754505518; x=1755110318; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=+YFpXW3yrjECJx7vi7MVyVNrhkpT/7G3DrMzdSM8sxQ=;
        b=oa2kKD4s3i5X+yGVQkmUaSqM2rMiABc9ewQAATXMquS+/zTPrME1EDGCZE+y3zEwXC
         ujao5LzPr+eU+/OxGJtk5YUK+7lE+KrQjqV8O/ge8OvdsPfvilN0cXdWpKlwcXfxcm+s
         xurH8nNkhW2z6bEXMECSfnBH3oFc3OrhLc/gLjmi90qDb+WvISFI3wiXRq/U8CGxEXIe
         jhfwWB3qDOKRs3WM1qYEj6iIWf8mu2pnkXyI+h9v/8qO7M3ZBJNZdkFy24XneQvVnlhL
         dqyEZnEl0G5clYvY4s/GzWAJd9YHic+0fBc7+DPbrqoUvAXIY8vXG8QJ9srnmcASycDj
         YJ3Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754505518; x=1755110318;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=+YFpXW3yrjECJx7vi7MVyVNrhkpT/7G3DrMzdSM8sxQ=;
        b=GJIy620HUwmEmH696jxvWAQQItXKWxVUYvzEr33uSgOs4WDN3CWUMQfyx0qjN9WziH
         nfiYuAgoRcqAyxRKVyhU3hSci2Gg0ODatiqeVGBjdPCD1cnN2btidzeKcSwS1jnfHFgk
         X9gmMwbyvDi4IijqcRPY/1lAierlmFwwcVeRem9ydwQslnrRv6IY6Q/g3kkHozdFEe+T
         GWK9HX5Tnir/BLePjMJJb8igwbxsEQpizKF/dYL0Sp9BvPbGnMXLzGKo2adMRBz5qDBF
         WilQwFPeBGJAOCOA4j94Vxs/DPdcdFxhO5e6zYhzYizpJmbQxwLKpMKgFhiycR1wJ4VT
         HTvQ==
X-Forwarded-Encrypted: i=2; AJvYcCUZvee0IrfNVKtQw7JQxLA/D3u6dwgzc5QHTcm4o6qIasqOSOyssOq6oWEB2aYJjL4RH6jKSA==@lfdr.de
X-Gm-Message-State: AOJu0YzhsGmzSz3HUaiLHNoJaAoDNCoOHux1f4Ot/nUYRK8OoMlSILq7
	ZQ8XAvO1bd0H7VkvbZRPiGNKOyFsll5yFSc/sQ/m9Bktdx3/AxzaMZP3
X-Google-Smtp-Source: AGHT+IHPNcV1C4rKIHBl+tXGjaVEcg816PkO5VN+GqrlbPx1M7Z39oG+Z0nQZSzhQUHmMEnlNSJM4w==
X-Received: by 2002:a17:90a:dfc8:b0:31f:16ee:5dcc with SMTP id 98e67ed59e1d1-32166c29204mr4779780a91.14.1754505518278;
        Wed, 06 Aug 2025 11:38:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZekmt1atgEPZL3RPvqBXjbzx5HN7R3KQMnQ8uk+rQR+ow==
Received: by 2002:a17:90a:f02:b0:321:6d3f:d047 with SMTP id
 98e67ed59e1d1-3217509d9b3ls139613a91.2.-pod-prod-06-us; Wed, 06 Aug 2025
 11:38:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX2FagK8h20BN1ItGsPV4lATR2sIKwzkVfkLFeCoRLiSp3sFxD5nZfFS8dOqzwLVTUA52n0/7n2ShA=@googlegroups.com
X-Received: by 2002:a17:90a:e7d0:b0:312:ea46:3e66 with SMTP id 98e67ed59e1d1-32166ca3f0bmr5095890a91.21.1754505516213;
        Wed, 06 Aug 2025 11:38:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754505516; cv=none;
        d=google.com; s=arc-20240605;
        b=W1bkoWsq2qyovw6nhPzTCvgka+3nfFl3X06ig0ubn1jTdu33pkEuHRa45yqZjahTF4
         we+SdLrIbY0NsSeqI8AoUDwFRKcZqv7EgbpYLdMWL6bARmtEVQq8RgZHvCrUGhADHBrU
         Eifu2r0D4dtztdSN5P8Cr5x9nExdXeWJKnafdSGCuWGpOFktxECtH5/JNfBI4AFPAGvd
         YCuLo0LooZWNdbwG3NCIxZ5uoCX2HNFkMxpYqpRKUDTTCTw5gjdzzHT+zgSTgp3eoRyk
         2txCRwEYNehr8BHWQVzyBa7MsWbiw9wGoRHc71ucglMBJJEFRZq728D9/VWuxudHcToc
         P1Ug==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=1x3Q7Y/VrhoNVJRSqy0Fcj4XeiXf5SuLbr9bYLsjRI8=;
        fh=Em3yvq2zMsfyYtekL77bXM163wy++1f+rgqYXqx5CqE=;
        b=dKNSM5/CWPnIHrfMmILdpnoldmP8GEl7rZgWh+zpHvZS1eBWih1NRtdT0DLnPjXDJh
         l0Aj8uyqCvu1o5fnfeVIhexVl7ntgkpfMldIQOdMPiYl3ZUUWvzUVvHwZ7vpwWz+znoe
         vQQ2Aim59E0nk1/t67Wb8IvtUSOyk/zNn2/KIsGh0kgbxYtsNVw+Z+d7kUiA7JDSBtcf
         jAGf1vsChEp2CVMC4/glZFUsS9X1L6IhGMd+6HYgauue1Xe6TVE4laR17v7HgQMTpuby
         s8bEMB8Kyb2rbIEjuPeOzsrvAi9C3vSeBQGOnv8KYOexUa9dqrD3wYbnv/fhLkEpjiFM
         2ldg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Ge50qjue;
       spf=pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-321028690e7si475766a91.0.2025.08.06.11.38.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 06 Aug 2025 11:38:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 534C15C5889;
	Wed,  6 Aug 2025 18:38:35 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 410C2C4CEE7;
	Wed,  6 Aug 2025 18:38:34 +0000 (UTC)
Date: Wed, 6 Aug 2025 21:38:31 +0300
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
Subject: Re: [PATCH v1 03/16] dma-debug: refactor to use physical addresses
 for page mapping
Message-ID: <20250806183831.GW402218@unreal>
References: <cover.1754292567.git.leon@kernel.org>
 <9ba84c387ce67389cd80f374408eebb58326c448.1754292567.git.leon@kernel.org>
 <20250806182630.GC184255@nvidia.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250806182630.GC184255@nvidia.com>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Ge50qjue;       spf=pass
 (google.com: domain of leon@kernel.org designates 139.178.84.217 as permitted
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

On Wed, Aug 06, 2025 at 03:26:30PM -0300, Jason Gunthorpe wrote:
> On Mon, Aug 04, 2025 at 03:42:37PM +0300, Leon Romanovsky wrote:
> > +void debug_dma_map_phys(struct device *dev, phys_addr_t phys, size_t size,
> > +		int direction, dma_addr_t dma_addr, unsigned long attrs)
> >  {
> >  	struct dma_debug_entry *entry;
> 
> Should this patch should also absorb debug_dma_map_resource() into
> here as well and we can have the caller of dma_dma_map_resource() call
> debug_dma_map_page with ATTR_MMIO?

It is done in "[PATCH v1 11/16] dma-mapping: export new dma_*map_phys() interface".

Thanks

> 
> If not, this looks OK
> 
> Reviewed-by: Jason Gunthorpe <jgg@nvidia.com>
> 
> Jason
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250806183831.GW402218%40unreal.
