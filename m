Return-Path: <kasan-dev+bncBD56ZXUYQUBRBLU5YLCQMGQEBZGH63Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103a.google.com (mail-pj1-x103a.google.com [IPv6:2607:f8b0:4864:20::103a])
	by mail.lfdr.de (Postfix) with ESMTPS id 86182B3A774
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 19:15:28 +0200 (CEST)
Received: by mail-pj1-x103a.google.com with SMTP id 98e67ed59e1d1-325e31cecd6sf1072162a91.3
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 10:15:28 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756401327; cv=pass;
        d=google.com; s=arc-20240605;
        b=cyzLGhwo8roy5OrbS86PCLKohucxfizMqjoB+w5Nl/HV9Hv8n+iVeminrkB7qEqN0b
         CnhLzUTMddUuxzDWwu3eFfdTtrBn+qBTiB/qOSvUgDeQD8wbPkKGs5hxlBunOB+Z1cd8
         YgKn2apx0bil+S9g7XG3FFC/Em6ymxaYghsjOlDS0zzRnM0BkksgNXzp3QBlvoaXcsmO
         lCdE4egtMF5esB2gK4Jjt453gHBG1mwcjP8/jtJjfCwDDGBO+CcNlQQ7QfYCOptygk2y
         uV3HgpJzXJWoVSZfA7PEgO362s+biKMwdYq9KoJ6+7dpzq6y1CEM0uzRlQ6dEyoKi7SI
         jGwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=4mP/C7mStCnse6uqnL4d6H8N81bEjt8gCYOgEqVTpbM=;
        fh=REor16JLiH4VffQ+IoXLrmmi2X1XIY9HfGfukuIjS3U=;
        b=OJxaFbcXanm4u46k0cjyp1jAHLeYnqsfnMpRrM5VOnxxJStlzu0wrmKHhiJK6AVZP2
         nT+r7rOVyzj96kKDkbhdKhgxY6UYt+xcGylYEsM7ML2krlr6sDqlHdkXl41d99nyrTKD
         Viygnmxfsa+dx2ABCxrGcUgoSFHPJc/SZLn0ICKeF9bvzqf9IJtTcqmZJi2TUirBqyi/
         1p9A0zhdeQJyd/Kahucz1VvoVrclUjEO6pdqO+HxTROjvnjfJFXxSKJPjKofDhhEbfIg
         2Pc+N9TbIWDzd/J2JwRaFk2OBKek0+RIbOZuyIERACinrcyEzk/LzZLq5RV77QTtzRuQ
         rStQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fnmNyIm6;
       spf=pass (google.com: domain of kbusch@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756401327; x=1757006127; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=4mP/C7mStCnse6uqnL4d6H8N81bEjt8gCYOgEqVTpbM=;
        b=Dl5xPOGLQVfRHVQkOzq4B6AlwKV95QqSXhRrGsXe+VUo3TSg2VNzWuqpRvcTE+wj/W
         kvqsTm/tRExetbCWR9NW+OgwZoU7wIA8mgHS7cEZKywUSHsbttMnZj3Ooyu9RLXrzvaA
         uF7cpUzQwdNo2CrtAy4ZMrcSW9KTB52sVniGssq3oLZyqWEu88MsCbiT/unHbSX4Gz1H
         AvBUvz8ng0xypJV4xGp/9JexBSSPyN9mz4KBmYmImxwXve+QNw42+ZtFj+KuE5gQ4aM9
         f1H8EqqHArJAsIetDA9wX4IxzaOB9bndNSj02a6KdxXWv+SVDGdU93BmrVQgC7Uy7t3z
         PkrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756401327; x=1757006127;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4mP/C7mStCnse6uqnL4d6H8N81bEjt8gCYOgEqVTpbM=;
        b=EI47gewWNIVVGMFglgLf5gRe8s+DLBnBT9zwxATqvtPIZr1MRxRVfldIN0S6k4A+Lc
         /rbtGc2/G+MjyAxsMSn/9Qqyay6PykrYEzLFD6XiDcbIIcI+ceq7ziNGYO8TbMdTWylr
         HyZmrTG2AyFplWb5HKwg+fK4qVxnT6mLmX2Mb++Ej8Sdz+rrhZC7gDxksJjQMqZnBNQX
         GyEM7OmU9QGRVICRcVVtJn/ii/Lq1arjVWqNLsntIsu4lZfBUMm4tRLlbdXtT4OOJrHk
         qoKxh2rRJb+nQWK7QCwApW7IfsRffQug13RbUsaFclOBwg+w6Zer8jPV11F51wQ4RHLb
         2Fcw==
X-Forwarded-Encrypted: i=2; AJvYcCWKzP8MBk8RFYj2yQ90F9NBTbojqkD8432LXc/j9hugc0b76/gVfabX96Zzk70PJ3UJUsxaHw==@lfdr.de
X-Gm-Message-State: AOJu0Yz8kJ5JCASQ3Ry2USyGTwsPC+j+B1CO0JAWyOCITKIWbmJCAqLn
	54Cor4FXmQ4rwlfmudG0Y5zba46nXPUXG1v0AmXfsmr3pj+dswJEtLhv
X-Google-Smtp-Source: AGHT+IHxVlVG78Bdt3YlplMFdGQMVtBjqO70zgWjPKOou+cN4FKGea1V1UNvShH2zD4OAPnpurtB3g==
X-Received: by 2002:a17:90b:1fcc:b0:327:6823:bfe with SMTP id 98e67ed59e1d1-32768230e60mr10022402a91.8.1756401326787;
        Thu, 28 Aug 2025 10:15:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdGXUrfnnqmNPwSd9kpSoWkwxpo1Qj+oALM6vk15iKFBg==
Received: by 2002:a17:90a:ac2:b0:31e:cf05:e731 with SMTP id
 98e67ed59e1d1-327aa8db21els999355a91.0.-pod-prod-07-us; Thu, 28 Aug 2025
 10:15:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUuv8U1OsAYUDeoECJ2+HusHzcWLYxvrC8roqOos73AZY5mW2AMN6x1i0FFwNIj/ko0IEelE7q1G8A=@googlegroups.com
X-Received: by 2002:a17:90b:3889:b0:327:b30d:9b7f with SMTP id 98e67ed59e1d1-327b30d9cdbmr5041987a91.12.1756401325260;
        Thu, 28 Aug 2025 10:15:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756401325; cv=none;
        d=google.com; s=arc-20240605;
        b=OQzrTlv8HKYMKsZsXiwAaszLGvWGCN/uUqXpnfCUV9KnCui+SqQRtn1kW7q+041QaH
         RicSeKwIl8BAcgHHbjt7lfbxz2vY7C6qeYB1l09+augc0vGeH61nDTF86dwGsqmAWB2I
         9T5brKijzbmcoVEtSVBjz8I7Mrndrhhp99NwvvEvMfM1fsu991f++64aQj5tQPbCM+uJ
         24vZUIyuJrBfqfF1McNQRSpleY9pRSMPe3PpSTmCxilIk4ph0z5Ngd6xD2DtA3EVt1Z9
         wjLUzj4QyJsOFzv8NeJB3diuDCkKZLnRmjYu0/wzvN2cfX9Phi0EV5O8CP11OwN0QA9z
         d6XA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=KCRt+XDfxBj5z23z/FYOBSKOJE6UKgt5OADwYjTTtQI=;
        fh=W7DSKePbZ1WZKWrs+67hMFMVYqT2DMjWSPurIAohox0=;
        b=T0H70/tEKARbchlOXezLJRYDXQRfqHAmtOOe+fL4vuf+Nhmix5gQCmSPzRf3LAwr4u
         YTZNA4pJ/rVtnEG/fKNRBK8oFOpk9NAOPTbX4NnnK8UA3vjmkY9kkqrRkV9XoLtfvQpn
         /5waAWRCVpyuC/L2MK9+l8gd5C7bwXx3PiO6m8CXjkzxlaSturX5rk5e64k64dl47XI+
         vA6/R5I3+K5va+3CgvxnDFex6C7j1eVEXiuyy2S61OWOcQfM+NTuQ6n93nX8wuSz8PWg
         mT3yw2MuQTdEfrbOVHIyWylpGd1lme+xH6m8Qx8uNt0+4NhXAsET9Qm0VM0Y5dxFnf0L
         pURQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=fnmNyIm6;
       spf=pass (google.com: domain of kbusch@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kbusch@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b4c7ea9a206si26973a12.4.2025.08.28.10.15.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 28 Aug 2025 10:15:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of kbusch@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id ECDE644C27;
	Thu, 28 Aug 2025 17:15:24 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 4A72BC4CEF4;
	Thu, 28 Aug 2025 17:15:23 +0000 (UTC)
Date: Thu, 28 Aug 2025 11:15:20 -0600
From: "'Keith Busch' via kasan-dev" <kasan-dev@googlegroups.com>
To: Leon Romanovsky <leon@kernel.org>
Cc: Marek Szyprowski <m.szyprowski@samsung.com>,
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
Subject: Re: [PATCH v4 15/16] block-dma: properly take MMIO path
Message-ID: <aLCOqIaoaKUEOdeh@kbusch-mbp>
References: <cover.1755624249.git.leon@kernel.org>
 <642dbeb7aa94257eaea71ec63c06e3f939270023.1755624249.git.leon@kernel.org>
 <aLBzeMNT3WOrjprC@kbusch-mbp>
 <20250828165427.GB10073@unreal>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250828165427.GB10073@unreal>
X-Original-Sender: kbusch@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=fnmNyIm6;       spf=pass
 (google.com: domain of kbusch@kernel.org designates 172.234.252.31 as
 permitted sender) smtp.mailfrom=kbusch@kernel.org;       dmarc=pass
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

On Thu, Aug 28, 2025 at 07:54:27PM +0300, Leon Romanovsky wrote:
> On Thu, Aug 28, 2025 at 09:19:20AM -0600, Keith Busch wrote:
> > On Tue, Aug 19, 2025 at 08:36:59PM +0300, Leon Romanovsky wrote:
> > > diff --git a/include/linux/blk_types.h b/include/linux/blk_types.h
> > > index 09b99d52fd36..283058bcb5b1 100644
> > > --- a/include/linux/blk_types.h
> > > +++ b/include/linux/blk_types.h
> > > @@ -387,6 +387,7 @@ enum req_flag_bits {
> > >  	__REQ_FS_PRIVATE,	/* for file system (submitter) use */
> > >  	__REQ_ATOMIC,		/* for atomic write operations */
> > >  	__REQ_P2PDMA,		/* contains P2P DMA pages */
> > > +	__REQ_MMIO,		/* contains MMIO memory */
> > >  	/*
> > >  	 * Command specific flags, keep last:
> > >  	 */
> > > @@ -420,6 +421,7 @@ enum req_flag_bits {
> > >  #define REQ_FS_PRIVATE	(__force blk_opf_t)(1ULL << __REQ_FS_PRIVATE)
> > >  #define REQ_ATOMIC	(__force blk_opf_t)(1ULL << __REQ_ATOMIC)
> > >  #define REQ_P2PDMA	(__force blk_opf_t)(1ULL << __REQ_P2PDMA)
> > > +#define REQ_MMIO	(__force blk_opf_t)(1ULL << __REQ_MMIO)
> > 
> > Now that my integrity metadata DMA series is staged, I don't think we
> > can use REQ flags like this because data and metadata may have different
> > mapping types. I think we should add a flags field to the dma_iova_state
> > instead.
> 
> Before integrity metadata code was merged, the assumption was that request is
> only one type or p2p or host. Is it still holding now?

I don't think that was ever the case. Metadata is allocated
independently of the data payload, usually by the kernel in
bio_integrity_prep() just before dispatching the request. The bio may
have a p2p data payload, but the integrity metadata is just a kmalloc
buf in that path.

> And we can't store in dma_iova_state() as HMM/RDMA code works in page-based
> granularity and one dma_iova_state() can mix different types.

I see.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aLCOqIaoaKUEOdeh%40kbusch-mbp.
