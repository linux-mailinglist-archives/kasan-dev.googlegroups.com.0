Return-Path: <kasan-dev+bncBDUNBGN3R4KRBXMX3CUQMGQEVZXZNPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 417FB7D29DA
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Oct 2023 07:59:59 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id 38308e7fff4ca-2c54b040cf2sf23578681fa.2
        for <lists+kasan-dev@lfdr.de>; Sun, 22 Oct 2023 22:59:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1698040798; cv=pass;
        d=google.com; s=arc-20160816;
        b=LCxwoGPgS/hb8T5JDMBSAaUTsOFD622vgI7+28CBgVarPhxEWQuIEQqXiO6jXHdbXm
         OJfek3kmbkPX3iTPFh0Z/iwo8VUgDYUUZdHqjDzHdBjozd1COdryBXPTZljElLl/S0W2
         dWb+rz1iOXyxtaWbqbxmaEiP7f4biMorDKjNuW7EpyLn9ZzduY1MfevTAIkvTGlihcVa
         S+Trdj0O8HE9I2QG45AThwgR6Z+WurWMrdsKb33u0zN9J35gyvb93fDyw25mtYvZUlJR
         1yXcYsmXwLZ/mupECtQg9It1dL6J8iU5EGiD355gEWfJqz3PDzMsWXcP/k9m4q68pkl8
         flgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=Hm+zWFp6VhYGyBmcPFIQp92I/iQpjeQIjaBOyoRpU6A=;
        fh=kQyL5gm+iu+NbHUl9gS9KaBYat36V8ddnwUaB8aCnBM=;
        b=s+XlZcUSHMqWtVYvDHeMoXxLdn90OU3KqkcgInN5MW557cTncIJm39T4SqVL2DErqu
         g3YoJeE9KqkoR+cAcmhmckTGSSAlyLOmdNlbYr6f4BNfwUh07HHlF2ZkzrBpdlQJOnhH
         nyWmRPi0yS926uaE8I9nIbTsOHiJbJLAfCgBdiNhA25zC13fbE/BqvoF7g5qAos8U6b7
         zehQORNnfW39oQtdJV5NHYYTyeSXATEwRh8PkYzcr+h/yZ3blYzVOraUfGAtIUc7pPsc
         vi+4NDy1q6do19SfsdPEQ5E3R/gu85SOAFtspuMkaoAWvRAs2zpJRzfUwmvhyBVuZFwa
         yO9A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1698040798; x=1698645598; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=Hm+zWFp6VhYGyBmcPFIQp92I/iQpjeQIjaBOyoRpU6A=;
        b=iTyF6liLUlXGn94+1MTyRgF+YD3Kh12CfpnYrDyhOsCtrKN+kck37H8H9SJ1dOAJRR
         cjNdcn6bnieGaGdD9S0EokGx1rSmGNA34k5M39gowoJ7cGG7VCyg9IoEVrobJJs+e++9
         Ij1PaD9fBM4OJyUJ6DMiTT0668hNn/7vgNtIFuWgrZz2SFz0HF17VbuZIyv5O5Lf6WCX
         z7f2J/B6jZaCXtzK1AbrRE5iWg1PL89AuoRZclVBjj/yAiv260Ie8qbPQaeo62A6RWXm
         rP6sTqDfxesTQlicBwggMxAVaec4uI8aPejmL+kYyD6+dBxjgG4dZct2mRF3bCYdmBbv
         mgvA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1698040798; x=1698645598;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=Hm+zWFp6VhYGyBmcPFIQp92I/iQpjeQIjaBOyoRpU6A=;
        b=Q4YI1E0/rWeuGIqgVgZCrLQYrmRuouPc+IrVWy3PK6X49s/Dkxu2JbqTkYOgAzDGLa
         uoACtTHNbiPafl7LrB/Lgm/4fUx0Q33sUc233Zh9usli//1PGIyi5RwoW/IZ1NuQn4xr
         vombRGWsIPhXyME99yZJ0aM98vLwC2J1A6S3pF1s4YelYXb0tkrJ00bUNbehImZ6DJg9
         0fXdm2eFpzBvxbxZfejPYb3ezj/qkbIpt1eg8da4dZ1SaZOHwqKIN8/U7gHCF74ZRjjQ
         YTbhSuNQ2fDg+QELUuR0EcXByuq1+p/B28CtXI31PVV70vQylyLOwpbQfkQswj8depO9
         0vOA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0Ywqzc6kxShckDnxiHaQhpa8xmjFy6bjoj6W35Om5JCtg0ZeiyAv
	Al/FSWhza00Rnksjbp7rWpw=
X-Google-Smtp-Source: AGHT+IHtML6WzCoe7ihu/rbiVRmYTlPu3HwpQiufPGqL2OiyZML8+V6L3MVCmWncgM0VXHA/GzVk8g==
X-Received: by 2002:ac2:5b0f:0:b0:4f8:75cf:fdd7 with SMTP id v15-20020ac25b0f000000b004f875cffdd7mr4517057lfn.22.1698040797306;
        Sun, 22 Oct 2023 22:59:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:4015:b0:507:9614:3957 with SMTP id
 br21-20020a056512401500b0050796143957ls1755585lfb.0.-pod-prod-04-eu; Sun, 22
 Oct 2023 22:59:55 -0700 (PDT)
X-Received: by 2002:a05:6512:4005:b0:500:953b:d112 with SMTP id br5-20020a056512400500b00500953bd112mr7377349lfb.27.1698040795036;
        Sun, 22 Oct 2023 22:59:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1698040795; cv=none;
        d=google.com; s=arc-20160816;
        b=KLj2kyWgAXRSlxjfwo1Bb/KbztnktdYBdJDdCVQnAtS+OWfmyFOn90hfj7UjuhNSZ0
         dWW9N1IxQ2AotTgSaJaMoQ6v/BiNpMS0oazVrXt1Hd4hcgkybI8aUhu5Ivs6mXgDYCtT
         +iGcRZ/MCwqtSnlrf3OAHE3rQ3VCRcQVh95GxGZuYAZYpi4FoJFtn0TXdGp9Fc+i5p8v
         S7jxdtHWqEW6vdWtFqLwF1wiPsBxc9CZuBDNQ4O1S0tiVUmp1zvD7+PtaxBp9/mFVLbl
         JIgUdTqqmdD1+hPqM546oF/xLetu+Umvrr0Nhk+yjze4g9+Cco+twoeI6Agk565wvlA7
         4xRg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=YSpffGsL2jBYJ7k+m5xd2yyUNmMPy0/aIUbM/6Bx0t0=;
        fh=kQyL5gm+iu+NbHUl9gS9KaBYat36V8ddnwUaB8aCnBM=;
        b=id3a7hIwIvazou89Dkrj9sUWerySh2jbKXQUj+Z1P2TYwt5ZO6R4OX7FNBX6fut10i
         LUyc7EwsiILkmUGol2g0MPr8/gtYbeOQgisW1ldCUrC5G933Nos6s0PQ0Bt2hV+asLP5
         91xnvy70lvE8QbiHsLZE5q6oSAvO4UwK6wNAKe8GCR5cx8ZJtd7B7qm1D2wK8nxvMe7z
         SmVSGTnIyktykE5Lrhq1wXbrmyCJ2XYfGestPbfHewrLjVFZ5dObh5WPqRUZqcEdiWOq
         nH809v1GAL6OTI3pKwPR/RNSktUpWsMjH02EADNmmYeKVt2ZbxuDQ6MGDP8Rc8FNoR+7
         jKMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de
Received: from verein.lst.de (verein.lst.de. [213.95.11.211])
        by gmr-mx.google.com with ESMTPS id o19-20020a056512231300b004ffa23b6e2asi262649lfu.5.2023.10.22.22.59.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 22 Oct 2023 22:59:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) client-ip=213.95.11.211;
Received: by verein.lst.de (Postfix, from userid 2407)
	id 2FE7368AA6; Mon, 23 Oct 2023 07:59:52 +0200 (CEST)
Date: Mon, 23 Oct 2023 07:59:51 +0200
From: Christoph Hellwig <hch@lst.de>
To: Robin Murphy <robin.murphy@arm.com>
Cc: Christoph Hellwig <hch@lst.de>, Matthew Wilcox <willy@infradead.org>,
	Chuck Lever <cel@kernel.org>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Chuck Lever <chuck.lever@oracle.com>,
	Alexander Potapenko <glider@google.com>, linux-mm@kvack.org,
	linux-rdma@vger.kernel.org, Jens Axboe <axboe@kernel.dk>,
	kasan-dev@googlegroups.com, David Howells <dhowells@redhat.com>,
	iommu@lists.linux.dev
Subject: Re: [PATCH RFC 0/9] Exploring biovec support in (R)DMA API
Message-ID: <20231023055951.GB11569@lst.de>
References: <169772852492.5232.17148564580779995849.stgit@klimt.1015granger.net> <ZTFRBxVFQIjtQEsP@casper.infradead.org> <20231020045849.GA12269@lst.de> <41218260-1e5f-4d36-8287-fc6f50f3ec00@arm.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <41218260-1e5f-4d36-8287-fc6f50f3ec00@arm.com>
User-Agent: Mutt/1.5.17 (2007-11-01)
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted
 sender) smtp.mailfrom=hch@lst.de
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

On Fri, Oct 20, 2023 at 11:30:06AM +0100, Robin Murphy wrote:
>> Well, we can stage this.  I wish I could find my old proposal about the
>> dma_batch API (I remember Robin commented on it, my he is better at
>> finding it than me).
>
> Heh, the dirty secret is that Office 365 is surprisingly effective at 
> searching 9 years worth of email I haven't deleted :)
>
> https://lore.kernel.org/linux-iommu/79926b59-0eb9-2b88-b1bb-1bd472b10370@arm.com/

Perfect, thanks!

> The other thing that's clear by now is that I think we definitely want 
> distinct APIs for "please map this bunch of disjoint things" for true 
> scatter-gather cases like biovecs where it's largely just convenient to 
> keep them grouped together (but opportunistic merging might still be a 
> bonus), vs. "please give me a linearised DMA mapping of these pages (and 
> fail if you can't)" for the dma-buf style cases.

Hmm, I'm not sure I agree.  For both the iommu and swiotlb case we
get the linear mapping for free with small limitations:

 - for the iommu case the alignment needs to be a multiple of the iommu
   page size
 - for swiotlb the size of each mapping is very limited

If these conditions are matched we can linearize for free, if they aren't
we can't linearize at all.

But maybe I'm missing something?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20231023055951.GB11569%40lst.de.
