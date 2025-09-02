Return-Path: <kasan-dev+bncBD56ZXUYQUBRBTWR3XCQMGQEF2RCDGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id B1B27B40FAF
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 23:59:44 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-32b58eeb874sf304715a91.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 14:59:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756850383; cv=pass;
        d=google.com; s=arc-20240605;
        b=O5FpHChAALS6bogRahRrMfxSDd5cGRVbAXJrOkn4iRoGzvtPh7V0sDQpb5iX3SGjKK
         0eZH5UIGJB4WF0Y0bmpzGw1BcJEDBBTg85fxxKa3xkw1qO6dkY8tGeZKdYMzSPnlEi/Q
         zh78NZuBGPUeuqyjJxLrS9KTF9uYTzi+9f6P1g80yv4j99MPrW9ctLKVE4sXnRmWIB2a
         fd8M1x+OXDHur5p6d1dmdT8ZPmpKLJ9Dm4+NZ5xK/3sfV2pAuYZk7EwDMDPDD0AYkgI6
         7tItqhgJFigfJTfMRkTcuBW9b9K1eLh8jafJ7H9mon08NsvygnW7JgWB+zh5sQsHHaf0
         fA1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=F9/eAqF8U9aX89dPiHSnkRv7tnfLMN7+eWGcmhjYjI0=;
        fh=4oBxhS5PRicVmsoqDo4hAbxxZ9ewiupJt0JY+cJ4AU8=;
        b=X+bKUIbh8ruL2lJw2MdS/DPoDK6abZabWP9j0pXBflEODNwXMybAW1aUXZoLubXh9m
         F1jHoxR8FbWbpAyzm/0mEOA5sk8AyzAtk5pYvcLc+r0ED0nN+zbNB2WGgXIOGJJO63yV
         ePHciwgLpQnrk8+GjLRkbpMiJBV3Z3ZFEqseNxKqfAiMWlb9iteI1r5xWTp1X+YqhxlK
         SHTMhRAgy12cYAqMuCUKJdAcZ0l01J3MQnzr/aDillODoabCdtBPETzmBAjwi8FPzPOz
         TId4JopkImGOqq/sK6QaZSmeeAxkNHkiysIqD/Mnt0fO7eMZZ0rLkgPVkGwytCU9x+Of
         2pIg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="t/Eu3Rve";
       spf=pass (google.com: domain of kbusch@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756850383; x=1757455183; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=F9/eAqF8U9aX89dPiHSnkRv7tnfLMN7+eWGcmhjYjI0=;
        b=Pf2xqc9NierlTP/QGa/ympWyQMVjpirXRD9ixNdfmw2hAcs0K/snNE7EGIAIcXka8c
         eqoSmGVaV8dDsgRutzLcaA4cfs1FxEDukpN1xIXLbEAorXmw8HaNE6FmPsI49mi9d4dj
         JLyJZMVAiTi+ncZGACETJsYtd/kSCvNYWa0FEAkGoJXEbL4786sVn9/F0eyVCwr5Wp0Z
         C0dBfPPNrmtI6ctcWQ8SmufzN2DzPj5nK6PNwDmyOgZhWKTmS516M2vbsnfC4ODa3q+x
         iTHX8V69iDVL30F1o22tEz2mRNEYpzKLRhCxIMi1OoaHvoy79FH+WmsUYlebDR8iJbhf
         AIQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756850383; x=1757455183;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=F9/eAqF8U9aX89dPiHSnkRv7tnfLMN7+eWGcmhjYjI0=;
        b=jslNNlCaROhFUuCcZikpn6/hWmqOnUi62dlbYMQrpNNHdxEUV1lbFyMXRS6VD8j90d
         dHaZbS8cf3Zgu0D7iw7E6GJhy0PgXFJHsm4yoIsnc0vKx9XwWIheMhZvcxidrVAzkE29
         q7d0k+G1beNancwW0T3qJ8LNZRejHgvNFeLrl79GkTi6JsEA3m/MTmZ1IwMl29osk4dX
         v6d6fD8htQkC7T1KRN89CmWB20yyZpuTYG9vM4imobZSd3rNLPtU2KcStI2yX2rdwOYt
         Dp0X403jePnXQ/R5q8a3UT+IeVQBb6b3jhXgrjBtfETLp2NN0wuHsUIUgKsadX5XuFyI
         vo6A==
X-Forwarded-Encrypted: i=2; AJvYcCW/BvnZ6vk+ftabC9u5HazEq2tszK2TDrLXlBG+5H1TgPg4bJQUW70kc9jeSGIGyYPEaBdE4A==@lfdr.de
X-Gm-Message-State: AOJu0YwWyB0IEa9MfeXd4T8L0NYDIBjoCrTIbviRT25UJAAmmzI/UDnG
	kr3c2Yn47XNZniQKvefhTNNkD9N5pVcQi54+3vMrVE00/0Nwe7TVlQrl
X-Google-Smtp-Source: AGHT+IFyusw3Rr0xqKO76SMreNwuaZ9g1LY0iHiDzNCNUarhMpvTN/4KZgfEczLUt5wx3C6vNPemjA==
X-Received: by 2002:a17:90b:1dcc:b0:327:b321:b514 with SMTP id 98e67ed59e1d1-32815412acfmr16020983a91.2.1756850383181;
        Tue, 02 Sep 2025 14:59:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcxfo2u4Kp/RUjuLprQSRZQTJF5PqpW8kxGReIBfZobbg==
Received: by 2002:a17:90b:2ec3:b0:329:f229:7c45 with SMTP id
 98e67ed59e1d1-329f2297c6bls713785a91.1.-pod-prod-01-us; Tue, 02 Sep 2025
 14:59:42 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUpktI94Eg0rM+W1zuEa7pYTG5bWhteHQJnjw4e3SPBgJvXrWnW/e6iWj5TI+DCmsaJFsMGrrTkQro=@googlegroups.com
X-Received: by 2002:a17:90b:2792:b0:328:126:3505 with SMTP id 98e67ed59e1d1-3281531d40emr16811584a91.0.1756850381749;
        Tue, 02 Sep 2025 14:59:41 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756850381; cv=none;
        d=google.com; s=arc-20240605;
        b=JlMM+SU3AN8fN0RZucqTs5QyNYSkajLbg/F8Mt/t3Ltmo05XG8VuTWWnRLbYhyRQ0p
         WqopoGp458w/zbxX7P5lubbsvq1Awwz2RF3pODI7mHFdFO/hta3Mqejw50oWuXVd1A2S
         v+TPmc0f9b9C2NqE0833ZX5w6jO4wHyTWCRtYXdVx12rKFudvA+8C2GT/2roeETST/9x
         b3xe+8bF57VMkwns+nCjbSBAiVV+iCR0Rfd//Apk7wAQvs+rXj86fJ7CXgQlbOXrOrgr
         8gCRba2cmB877g+yi2eZpAu0LiLFurm1xBW3iVu58aJLJ8C7JjxRvQhBgbKMEA/iGDFV
         X+/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=wxLWaOMzyFn1TCsduloGVD+a0ZYJgwe6TduwxzO1EKw=;
        fh=wRVJSY7gFXOfRPLDV5w0uIQod/zUCtirUS50kky7Fbs=;
        b=dJXXMS/k16TfeQmIehOXbvcjKW07pDAbIUGjKXC+XOfmx18g2R7e9RDQfhzb4hJvIV
         WTX6PiqFTWxvr0CKeNcWQgEFzq5CEI5bA6s3w8NnHZDyc6w+VgvMhdVVyWrGhRRIAJDh
         CJrTSeTE/FohtGOWkVZTdIgxevxVXdd4ZMkjU0DHbosvTsDJk8iViLSKkSE/nsxy0LJj
         IaChfETyy11KK0kxlclVS5Vun2vku6/k7ds+UPlZ/4HhPgyEI7MmtW0qUCSxoTeVvFJ1
         lTMUVFcN0oEdDHV+6+Hl7lpthB+iR4FX4b0ztgXNimydwLpRZx7RBZ3e9ToWAp4Th3k/
         +2TQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b="t/Eu3Rve";
       spf=pass (google.com: domain of kbusch@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b4e861f79bbsi356912a12.0.2025.09.02.14.59.41
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 02 Sep 2025 14:59:41 -0700 (PDT)
Received-SPF: pass (google.com: domain of kbusch@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 55E3F405D0;
	Tue,  2 Sep 2025 21:59:41 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id A15CEC4CEED;
	Tue,  2 Sep 2025 21:59:39 +0000 (UTC)
Date: Tue, 2 Sep 2025 15:59:37 -0600
From: "'Keith Busch' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marek Szyprowski <m.szyprowski@samsung.com>
Cc: Leon Romanovsky <leon@kernel.org>, Leon Romanovsky <leonro@nvidia.com>,
	Jason Gunthorpe <jgg@nvidia.com>,
	Abdiel Janulgue <abdiel.janulgue@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Alex Gaynor <alex.gaynor@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Christoph Hellwig <hch@lst.de>, Danilo Krummrich <dakr@kernel.org>,
	iommu@lists.linux.dev, Jason Wang <jasowang@redhat.com>,
	Jens Axboe <axboe@kernel.dk>, Joerg Roedel <joro@8bytes.org>,
	Jonathan Corbet <corbet@lwn.net>, Juergen Gross <jgross@suse.com>,
	kasan-dev@googlegroups.com, linux-block@vger.kernel.org,
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
Subject: Re: [PATCH v4 14/16] block-dma: migrate to dma_map_phys instead of
 map_page
Message-ID: <aLdoyWevrQMQUGyz@kbusch-mbp>
References: <cover.1755624249.git.leon@kernel.org>
 <CGME20250819173845eucas1p221cd6842839f5e7130f131cd341df566@eucas1p2.samsung.com>
 <22b824931bc8ba090979ab902e4c1c2ec8327b65.1755624249.git.leon@kernel.org>
 <2d8e67b2-4ab2-4c1f-9ef3-470810f99d07@samsung.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <2d8e67b2-4ab2-4c1f-9ef3-470810f99d07@samsung.com>
X-Original-Sender: kbusch@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b="t/Eu3Rve";       spf=pass
 (google.com: domain of kbusch@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25
 as permitted sender) smtp.mailfrom=kbusch@kernel.org;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Keith Busch <kbusch@kernel.org>
Reply-To: Keith Busch <kbusch@kernel.org>
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

On Tue, Sep 02, 2025 at 10:49:48PM +0200, Marek Szyprowski wrote:
> On 19.08.2025 19:36, Leon Romanovsky wrote:
> > @@ -87,8 +87,8 @@ static bool blk_dma_map_bus(struct blk_dma_iter *iter, struct phys_vec *vec)
> >   static bool blk_dma_map_direct(struct request *req, struct device *dma_dev,
> >   		struct blk_dma_iter *iter, struct phys_vec *vec)
> >   {
> > -	iter->addr = dma_map_page(dma_dev, phys_to_page(vec->paddr),
> > -			offset_in_page(vec->paddr), vec->len, rq_dma_dir(req));
> > +	iter->addr = dma_map_phys(dma_dev, vec->paddr, vec->len,
> > +			rq_dma_dir(req), 0);
> >   	if (dma_mapping_error(dma_dev, iter->addr)) {
> >   		iter->status = BLK_STS_RESOURCE;
> >   		return false;
> 
> I wonder where is the corresponding dma_unmap_page() call and its change 
> to dma_unmap_phys()...

You can't do that in the generic layer, so it's up to the caller. The
dma addrs that blk_dma_iter yield are used in a caller specific
structure. For example, for NVMe, it goes into an NVMe PRP. The generic
layer doesn't know what that is, so the driver has to provide the
unmapping.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aLdoyWevrQMQUGyz%40kbusch-mbp.
