Return-Path: <kasan-dev+bncBC3ZLA5BYIFBBNENVTCAMGQETEJEMTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 972A3B16BD1
	for <lists+kasan-dev@lfdr.de>; Thu, 31 Jul 2025 08:01:25 +0200 (CEST)
Received: by mail-qt1-x83f.google.com with SMTP id d75a77b69052e-4ab701d5317sf978491cf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 30 Jul 2025 23:01:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753941684; cv=pass;
        d=google.com; s=arc-20240605;
        b=lHvyZyfXADv/VO2priOAtuZGxXdEIXND2gqRO/rJE5A9xH4gzKSKO88mYOQK/7vzyp
         xMrZVz3uvWq1Sj91HBWjYf7PJpbqelJHcX2NryVlUpnavLQDt9nouDRrsKFS9GrkFFYp
         hoSDkGsNZ+3Lh0B+rjJCf0UwDfAWwMU1v5TJawVgS2b5lJz/2BUV1dNpTI2wcM76jOgc
         2mgq0be0qY7OAQvt0x/ZhqMuO+dfjH6RSTmivchfXFqnl2RtdqOw8Cd9Fmb0agDP7WrP
         JNqMuYD3OhHpmbxLKPSQP/UZLBt6IOB5yumqybbqlinLsQ5Y6ejeGGpl+CxyuXP+tCEP
         +cMg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=QwVpoXAm4eW1HFniF8xhN96zV1QjZKXHP9IYXrRCIjs=;
        fh=u68rbZNulugn918tc8SPR0+cbNis6BHoYLTOa3Vfv4k=;
        b=BWbhnVY70YWgiEnZYoryjqVLQC2aJEYlx/epMU38jVnBCQYvA0qQG3FXtoRz088SP9
         zEyE7ky0FPU/eKO1ZgY0m9LtA1RJu55U9ionl8QjACRKI5WkFVOQF0a62MT1EHK1XrNA
         RDpTWkyl3RKVOGEGqzAIqqalrS67GH1qJSJwr9pi21J0PRX6Bwa17vGkbR2OqcMplefZ
         66XoMr9rG3G3LKAp1ehoQiyHobQBdQPPiFnaDkCDkHysyJXcegBvPsXGJXXZEsbuGcTz
         CmUrBmug7Njwm72yQtFNe+frAvd4zANwxScSJKYrngM9grNGrmUiFHiRb3zq+1tW7eqZ
         3nag==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DKKF3Cek;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753941684; x=1754546484; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:from:to:cc:subject:date:message-id:reply-to;
        bh=QwVpoXAm4eW1HFniF8xhN96zV1QjZKXHP9IYXrRCIjs=;
        b=xn+4gwOqUvNIAMC9cW3J0x+DC93T4AYppZNMVnGIfQSSr3eoo5Yn1grDennWkCSNTu
         oaw3tUMaW4HuDUcbmYxSNR/khNsBszKPXjuLw8bOtEGv01GYU9Wgs6CKc3N0BfOmHGax
         5irjrc1KLfkXdVdWih65ACxBk6bYqM7YCNFVOF7WBP1XXvvITwp5hsm8cmUd/b7hNsEj
         ybs71Y8NLxcTAwVT70R1PYb1KxLAJaoeOyqNBxrZpu6jYy+i+LBuceY8474MbVK7t/Eg
         4ssNQMtJgWFumbwH5NaAogk134xVl1jCmpkZQ4pTrva5KXc2BFl9H9mzchC7Wr73uZi3
         Aogg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753941684; x=1754546484;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=QwVpoXAm4eW1HFniF8xhN96zV1QjZKXHP9IYXrRCIjs=;
        b=H3SZrS8rhSFIbnGougDr2esih9fT706LM83M53sDg8Jq5hNpuSdgpnEQrwphjX7Vef
         LF4pc0hdueS/PKOavCpVGNHZED60AdNeTlDg25XitZDMpxUBLdwPkdKLDt1NI3KY6GBm
         gtDlrz2ucV7y4HCUqW/0Tfqem4IcEUKvZmhDolS44FHKHKA4qs/l2ufy25fL2mOAXAEd
         YXxS2OMAIo8XZujqJTN57TiusqVeNAo1nSX5jlLcB8V3HQQdcxIsYWRejnH87girtzSD
         yzKRvDecPQ0WHrJkFeRlm+4CudL78nbAt8SzDulW5QgHvSw4FtfRccIK5Nemz1olPOHG
         aEdw==
X-Forwarded-Encrypted: i=2; AJvYcCWFhXY4XuxtFRpXcjuOzj0vajhNv1P59L7wVurJ2suKuFIss8NeZtFdIrnKSnIcotfRcULYjg==@lfdr.de
X-Gm-Message-State: AOJu0Yzz/kIAJw7Ij3uArVya1YVI0TIM1Er8BKoV2+RlpkB83SlJRQlS
	XQrkESZ8AD1HTkq8Xx/HYW9lm3hAD2tzfEhMbw1j+nFEWBnD8TeWh8QB
X-Google-Smtp-Source: AGHT+IEpTN2KEubI9oCbnDvcuNIZqiKDM9XcwHqJ3wXwj3IiWbAudRnJUf0I/k/6BB8A+TmMiQeOqw==
X-Received: by 2002:a05:622a:250:b0:4ab:8d13:7151 with SMTP id d75a77b69052e-4aedb9ab383mr97145171cf.7.1753941684265;
        Wed, 30 Jul 2025 23:01:24 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeLBhaGjV5Acg3GoVX1N9EBCr4N7r4n23v8IkBTIpCeZw==
Received: by 2002:a05:622a:1923:b0:4ab:9462:5bc0 with SMTP id
 d75a77b69052e-4aeef213160ls6907921cf.2.-pod-prod-06-us; Wed, 30 Jul 2025
 23:01:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX0ePRhgJzVRGAQLrScA58aj+DAuS6okEK/J7SZ98E5yuAz+HASBKpDh28i96zsAHrnTvzAeibS4MY=@googlegroups.com
X-Received: by 2002:a05:620a:4096:b0:7e6:27c9:a141 with SMTP id af79cd13be357-7e66f39e8dbmr793199185a.62.1753941683299;
        Wed, 30 Jul 2025 23:01:23 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753941683; cv=none;
        d=google.com; s=arc-20240605;
        b=KUBXOg3YiZDtYts1U+kBV5Z2RCYZbc1Wbj7VBwzsgJG7B6xBnS/+hB9KXfpUUMCzW9
         ETCYzkhws8XYVvl9JLlD8F4tIFWwKz8rcQPdqETdjkVbqevtE6FzTQL/mTSR2gQNmyv2
         LuEkO2WwZ8eGeI7Nkp0h/H7r2mHoqGxkJBC3XQtF0PvPoShnZc0OAZF3a/txLlPEcxhE
         DQe2SajLg5Cltd8vNo23ctZA65FvoCRw0JQpx9L1MiZD5KmE7Onl/VV81mSqP2fZ+9oc
         CXmSQ15DLUzDrHFaK3iSe6FqI1AVn8daBQQHf3KUlMWBBFuDRKaJEqEQzBVTTy0qdg83
         mXtA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=IGpAwwv6EOU3J+szo0L/6K6hjZMUC6+znFU4vGOXvqs=;
        fh=SaRyY+5tj9zqaDfPfPezurTF9CStnsam+MBwVTdmRw4=;
        b=GWse7Vwl12iaXRp//PW0sQmuvpc5ZUE/0i0KxLtXQYvND/Kk4lqhPXpB+a08dZkX+U
         GdcJ+kIEjsgdtDxlHOVoD6jm1MfM4GB05jsWK2COsYMxBAX2SpQyjbtoz000OOYBz0Gs
         YZaVdWFqeiuPaNVaW1P+2vbYDEodHsm3K+X9RG0VKkTsIY12gZfT5B5ymfEy20pRp00J
         4lVyTYyBcIMEwGfgS3U+zLksIq+Kil+Al1CfmwtqogPcnrGeHX4Xzkpr/LeKZvW+qbaM
         pLMAWspGkR4MTimu2CGyLHXMdhxJ/+1r9MjsHGSzqoKW1pWF5NpctWsdbqYvfAG5PAvb
         j1CQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=DKKF3Cek;
       spf=pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=leon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7e67f5283a9si4415785a.6.2025.07.30.23.01.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 30 Jul 2025 23:01:23 -0700 (PDT)
Received-SPF: pass (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id D3EB15C5A6E;
	Thu, 31 Jul 2025 06:01:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id C8ED7C4CEEF;
	Thu, 31 Jul 2025 06:01:21 +0000 (UTC)
Date: Thu, 31 Jul 2025 09:01:17 +0300
From: "'Leon Romanovsky' via kasan-dev" <kasan-dev@googlegroups.com>
To: Jason Gunthorpe <jgg@ziepe.ca>
Cc: Matthew Wilcox <willy@infradead.org>,
	David Hildenbrand <david@redhat.com>,
	Robin Murphy <robin.murphy@arm.com>,
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
Subject: Re: [PATCH 0/8] dma-mapping: migrate to physical address-based API
Message-ID: <20250731060117.GR402218@unreal>
References: <CGME20250625131920eucas1p271b196cde042bd39ac08fb12beff5baf@eucas1p2.samsung.com>
 <cover.1750854543.git.leon@kernel.org>
 <35df6f2a-0010-41fe-b490-f52693fe4778@samsung.com>
 <20250627170213.GL17401@unreal>
 <20250630133839.GA26981@lst.de>
 <69b177dc-c149-40d3-bbde-3f6bad0efd0e@samsung.com>
 <f912c446-1ae9-4390-9c11-00dce7bf0fd3@arm.com>
 <20250730134026.GQ402218@unreal>
 <20250730142818.GL26511@ziepe.ca>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250730142818.GL26511@ziepe.ca>
X-Original-Sender: leon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=DKKF3Cek;       spf=pass
 (google.com: domain of leon@kernel.org designates 2604:1380:4641:c500::1 as
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

On Wed, Jul 30, 2025 at 11:28:18AM -0300, Jason Gunthorpe wrote:
> On Wed, Jul 30, 2025 at 04:40:26PM +0300, Leon Romanovsky wrote:

<...>

> > The most reasonable way to prevent DMA_ATTR_SKIP_CPU_SYNC leakage is to
> > introduce new DMA attribute (let's call it DMA_ATTR_MMIO for now) and
> > pass it to both dma_map_phys() and dma_iova_link(). This flag will
> > indicate that p2p type is PCI_P2PDMA_MAP_THRU_HOST_BRIDGE and call to
> > right callbacks which will set IOMMU_MMIO flag and skip CPU sync,
> 
> So the idea is if the memory is non-cachable, no-KVA you'd call
> dma_iova_link(phys_addr, DMA_ATTR_MMIO) and dma_map_phys(phys_addr,
> DMA_ATTR_MMIO) ?

Yes

> 
> And then internally the dma_ops and dma_iommu would use the existing
> map_page/map_resource variations based on the flag, thus ensuring that
> MMIO is never kmap'd or cache flushed?
> 
> dma_map_resource is really then just
> dma_map_phys(phys_addr, DMA_ATTR_MMIO)?
> 
> I like this, I think it well addresses the concerns.

Yes, I had this idea and implementation before. :(

> 
> Jason
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250731060117.GR402218%40unreal.
