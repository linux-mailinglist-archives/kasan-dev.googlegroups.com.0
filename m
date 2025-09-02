Return-Path: <kasan-dev+bncBDG6PF6SSYDRB45Q3XCQMGQEN4VU4NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13a.google.com (mail-lf1-x13a.google.com [IPv6:2a00:1450:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id 59707B40ED4
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Sep 2025 22:49:57 +0200 (CEST)
Received: by mail-lf1-x13a.google.com with SMTP id 2adb3069b0e04-55f6bdc1773sf2427089e87.3
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Sep 2025 13:49:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756846196; cv=pass;
        d=google.com; s=arc-20240605;
        b=k4B2gc01tAmZsRBU6DGJvob1B7uZExObnLTpIHFzqdiUZAStv9f2n9+Ply1qkWS486
         3+1ioz6furkqBfyKVTbRfloPFF9W7I2lz/LLEuxIwMkPssqNyr1zExs3zyob9Rx/LiTo
         nwsxjZ5ibRybLscFB2IYZEcaVuPeaAs+lpHSPypLXigvpJhiviFVSBQ0wg11T1q6hmOK
         PMZjOCu7HUG9sgnn8VHLEqPTc11amlDvvFUx7566ohjgX7HPUY+uR5fIFChLXHh+FAjc
         MgdezDGmmKs7Xyo9ucKfpGhVeD4SFvRvYj5rXiuKobk3TdThVTZJ2Fy68fhNTYuz8oJV
         WuFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-filter:sender:dkim-signature;
        bh=FQn43MBTru8dizzWf3+gbykIdky0n8yxi1O/fBYeIhM=;
        fh=39ohCm8ErrPE3Sg48tg4A920zndP94tRIJUC4Wr48gg=;
        b=X30M2cJ931phPI+d5URgrJQcI7sSNLirttTTMWU1pnzVCXHxkgRjriuVmpqoCmor7D
         3bPj1KNXGzQbaPT220sKeU8tGYPZqgEHMraGvY+wSDHzMLhtSQFQpPbRaRVyvs0ODALq
         Aba7W8cAQP0MjSF3YiDm3hVA3gCTgK+1WHq0npqLsih7TZL2KfSGUvU4LsqDWn1PgjRl
         XsrIK1Nv9fv+k3qyZstm/4pvYT32C+cveip+E1UxK4rwcJsmUSWvCa1pxAz/FjrI4jME
         h2uOVrOkca/0hCGnjC0A1SZ64DAIYI7Wb5bKw1bFl+BzTVBZXAXmHyss5Nq/G0lrO2Wx
         KIHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=TCSDXZF2;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756846196; x=1757450996; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:in-reply-to:from:content-language:cc
         :to:subject:user-agent:mime-version:date:message-id:dkim-filter
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=FQn43MBTru8dizzWf3+gbykIdky0n8yxi1O/fBYeIhM=;
        b=Ioqyn5UtTX5oxaL+199sCRrNiMW4oIiOQW+EAv5Iv2vjuBJUQyKU8SlksyfhYOiO9G
         LsWNJyczGAhDOg7iU1hSzcqRw1/fQwwppad3WYHGbrYzI8zmT69elZ6PKCV9M57OfGFN
         ZAw7mK+XeoBM4FS10S71d+20vsOGvKmMxXzy/tDe/kgtEVazCfaU3Hs0T4akYeTkn+nd
         Cu2AK38cVfRLFZ8W5DHvUWjQ5PtZLULENciy9uMqoGte0vXv6WconJP3CVzjRcJmRPbM
         6+gVf5C36MtFURz46CPvG86OzGrjLerBnH8DweOQ+Eo7sPO4QbOn1zlu2YDLxDS3QOyN
         TgkA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756846196; x=1757450996;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:from:content-language:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-filter:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FQn43MBTru8dizzWf3+gbykIdky0n8yxi1O/fBYeIhM=;
        b=fqess8n1UzwxmkiEcNKlwTR3nsUg4+Js24wznT5JXYa9ddJpc6xzKJDAQaWZrwJ0Zw
         RideD7FmBjSGbV/ZCwRiFwCFrRWFI4aMypY6u8s7XF7geq1w00RDXp+yb0BCGqMULQE1
         LiHV8NhXKXTkSRjQ09Z6lYZpWlFpxl5PF1AYpsUVHG9osSKepo8ye3e9FJqV1Lb+nIrn
         t4D9+RAhL2kSfxOPcY/g4fx/KYzUvXXbsRHFYryhNK4DHXdsESlBSkyNx/d9sfGd6yL9
         B2VgAHt7EJp24+T4sc572y2qrtXHNiRol52pmLvT8ox7jXuw328OvvHxGEF5GZYEPqjZ
         /ReQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX7e8uBintBYCJoDGaDpvd5ixFSz4kP3mnlW/LpmBZu2sUSj8yMnCcGTCeRFd6FQ1oOAyZLbA==@lfdr.de
X-Gm-Message-State: AOJu0YzcR99w/ZD5DD9x0BXXjm/szZKrkSHjvBmOF4MuGJ9kgo6z+b2h
	hH7zPaSjYUe2xiI9mu/eYFITSzqL3usScYZBCuEoJXtD4cUFk6XjTIKT
X-Google-Smtp-Source: AGHT+IGUtyN5apevO3hyQ7+yTSzdXj5RIycldhilJ0mjkzMmkfE1cycEDc7k9VixR5BMV77D5n5dOA==
X-Received: by 2002:a05:6512:3da9:b0:55f:4efe:42b4 with SMTP id 2adb3069b0e04-55f70995a46mr3577875e87.51.1756846196087;
        Tue, 02 Sep 2025 13:49:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfuJEtOVkPAMTjMRuMBli+fepO4B4+12DfA/CP4JyuGnA==
Received: by 2002:a05:6512:638b:10b0:55f:4af2:a57a with SMTP id
 2adb3069b0e04-55f5dd0b27als431892e87.0.-pod-prod-09-eu; Tue, 02 Sep 2025
 13:49:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXItjIIPGLd2iI8gwunapLxaQ2f7hheRrVXAb0zNgAE8MbGkczm93ZCeRwGLHmCXmQlIcfmRJfAf9Q=@googlegroups.com
X-Received: by 2002:a05:6512:6410:b0:55f:6d38:cc9f with SMTP id 2adb3069b0e04-55f708b6b7cmr3898856e87.17.1756846193004;
        Tue, 02 Sep 2025 13:49:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756846192; cv=none;
        d=google.com; s=arc-20240605;
        b=evzFcooFExqDHHglIoSTmQbhLeIY2JP/TW52c58A3wO6ZgQh5vGddex067/aLboFUp
         jZT1gwePsfH0nDfDlBtJVVCh51vzxl1OtelWloGd7hKtLJOEsqDb+iGxicgIC0taISMh
         w7O7QV8Rk+mMTd/15Z8UKQC5gZQ6b0lIZCWhVaWLP8JDBfHfOPJQLfBCQvsx8LN39LDH
         FIJ2zUtGHSx7OZJyVsdiXKRzdrOtt2ZuIEENYd0zvPtC8keKlse93IXG62jHJK90OZlo
         CMLqNRZTixojt2LUBe3n43FEiJwDdWmqYqaG4RsjxSEjJGz6nDSk5dvKauvnqnzVUtla
         5KKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:content-transfer-encoding:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-filter;
        bh=cns0fXIAbt1EqvizSg/wAnSv3SWVs6AXpQ/9VbxT1xc=;
        fh=qouSimbGsfsbp9vvvKqWVrIL5wjbkT0wdVVzJXaGfLg=;
        b=MA/nM9BAXQdXsWCQieMPvlvazh80Y0t0JAzEyKKTUpTyxElOjUedIjPAZr8YLkCLnT
         FhVhQz6p+eAneYr4k23tvXbUaspeuh+BLFjc2mzq+wc/e/4rAtaO2E6oi7BwdpjActO0
         nkHbzqNrnNS+xiGG2PzzdnsV8sjVRNGbpWd0p8lAMUvrxa46Zl+sIYqVEY97gUCIs0ZC
         e4IYFmfp6IMpeYnnWF8z3y2biet4lRu6A1+DS9ddnEm3HvxoNH6RXzGkJxngr4CY/WEA
         vfsart4ZGGxnK7vRyJL9GYyID4jBAyqWwZjSPLriHIGqQuvr2B8cdDAFgfRpFdNJ4tCO
         thcQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=TCSDXZF2;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout1.w1.samsung.com (mailout1.w1.samsung.com. [210.118.77.11])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5608ac88793si2042e87.5.2025.09.02.13.49.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 02 Sep 2025 13:49:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) client-ip=210.118.77.11;
Received: from eucas1p2.samsung.com (unknown [182.198.249.207])
	by mailout1.w1.samsung.com (KnoxPortal) with ESMTP id 20250902204951euoutp019772216366e471dce5ab670ff270a1c3~hkk2PqBI40583005830euoutp01b;
	Tue,  2 Sep 2025 20:49:51 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout1.w1.samsung.com 20250902204951euoutp019772216366e471dce5ab670ff270a1c3~hkk2PqBI40583005830euoutp01b
Received: from eusmtip1.samsung.com (unknown [203.254.199.221]) by
	eucas1p1.samsung.com (KnoxPortal) with ESMTPA id
	20250902204950eucas1p1185c6ab6c55958183bb0c347b0396b5b~hkk1r34Tc3157531575eucas1p1q;
	Tue,  2 Sep 2025 20:49:50 +0000 (GMT)
Received: from [106.210.134.192] (unknown [106.210.134.192]) by
	eusmtip1.samsung.com (KnoxPortal) with ESMTPA id
	20250902204948eusmtip14b51a6d907c8deca19aa6660d162e2c8~hkkz6C6Li1369313693eusmtip1I;
	Tue,  2 Sep 2025 20:49:48 +0000 (GMT)
Message-ID: <2d8e67b2-4ab2-4c1f-9ef3-470810f99d07@samsung.com>
Date: Tue, 2 Sep 2025 22:49:48 +0200
MIME-Version: 1.0
User-Agent: Betterbird (Windows)
Subject: Re: [PATCH v4 14/16] block-dma: migrate to dma_map_phys instead of
 map_page
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
In-Reply-To: <22b824931bc8ba090979ab902e4c1c2ec8327b65.1755624249.git.leon@kernel.org>
X-CMS-MailID: 20250902204950eucas1p1185c6ab6c55958183bb0c347b0396b5b
X-Msg-Generator: CA
Content-Type: text/plain; charset="UTF-8"
X-RootMTR: 20250819173845eucas1p221cd6842839f5e7130f131cd341df566
X-EPHeader: CA
X-CMS-RootMailID: 20250819173845eucas1p221cd6842839f5e7130f131cd341df566
References: <cover.1755624249.git.leon@kernel.org>
	<CGME20250819173845eucas1p221cd6842839f5e7130f131cd341df566@eucas1p2.samsung.com>
	<22b824931bc8ba090979ab902e4c1c2ec8327b65.1755624249.git.leon@kernel.org>
X-Original-Sender: m.szyprowski@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=TCSDXZF2;       spf=pass
 (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as
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

On 19.08.2025 19:36, Leon Romanovsky wrote:
> From: Leon Romanovsky <leonro@nvidia.com>
>
> After introduction of dma_map_phys(), there is no need to convert
> from physical address to struct page in order to map page. So let's
> use it directly.
>
> Signed-off-by: Leon Romanovsky <leonro@nvidia.com>
> ---
>   block/blk-mq-dma.c | 4 ++--
>   1 file changed, 2 insertions(+), 2 deletions(-)
>
> diff --git a/block/blk-mq-dma.c b/block/blk-mq-dma.c
> index ad283017caef..37e2142be4f7 100644
> --- a/block/blk-mq-dma.c
> +++ b/block/blk-mq-dma.c
> @@ -87,8 +87,8 @@ static bool blk_dma_map_bus(struct blk_dma_iter *iter, struct phys_vec *vec)
>   static bool blk_dma_map_direct(struct request *req, struct device *dma_dev,
>   		struct blk_dma_iter *iter, struct phys_vec *vec)
>   {
> -	iter->addr = dma_map_page(dma_dev, phys_to_page(vec->paddr),
> -			offset_in_page(vec->paddr), vec->len, rq_dma_dir(req));
> +	iter->addr = dma_map_phys(dma_dev, vec->paddr, vec->len,
> +			rq_dma_dir(req), 0);
>   	if (dma_mapping_error(dma_dev, iter->addr)) {
>   		iter->status = BLK_STS_RESOURCE;
>   		return false;

I wonder where is the corresponding dma_unmap_page() call and its change 
to dma_unmap_phys()...

Best regards
-- 
Marek Szyprowski, PhD
Samsung R&D Institute Poland

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/2d8e67b2-4ab2-4c1f-9ef3-470810f99d07%40samsung.com.
