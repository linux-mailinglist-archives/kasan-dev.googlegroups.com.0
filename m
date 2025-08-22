Return-Path: <kasan-dev+bncBDG6PF6SSYDRBD6OUDCQMGQEWCA75AA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x238.google.com (mail-lj1-x238.google.com [IPv6:2a00:1450:4864:20::238])
	by mail.lfdr.de (Postfix) with ESMTPS id BED0FB3115D
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 10:15:13 +0200 (CEST)
Received: by mail-lj1-x238.google.com with SMTP id 38308e7fff4ca-333f9196a62sf7187831fa.3
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 01:15:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755850513; cv=pass;
        d=google.com; s=arc-20240605;
        b=izDBd8gCyZYzZ+ytMtKgknqdpCYM1AxwTn+Yx2quH9Q3cCBKSObTm09f2gXyoeDfbh
         vf+/Mtpf0gVQg3BDcf7DCb/9/3e4EfuHie87COf/6XINUMcjsoeRuxNvtpRNE5B/rkkn
         EVkcbewGDN6/GwzzkmdS8dJ3KzP+8V394ak5kjAYC+nIx8fWC18ylskyxCkLBg9uYnls
         l8/iwC1gxEkyLt4+UwSTt8kkF/45Eo5N0dXbrYmuUVVcZ6PXWKpnZunTDv+UIL/mGF2z
         jRrCj56Tc0Z+JgB5s+hUbvUN5K88LFGiAbESGTNBSGukYyBJD+EybVLrUNVTIcQ0cQjz
         439g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-filter:sender:dkim-signature;
        bh=Ej4CB8eteHb/22FtqK1LUgLyI+2ZB6hPD4jW3puSW98=;
        fh=+2IvVidONr4JjT/9c0PLWez6TqsleBxpehA3kNBIRhM=;
        b=Lp1hSmgpBLy8Alfb3mf/9yHeWvLks98NPHV3V11mV8wBzS56I8qC8YNHVIlIJVhqcA
         BNIT2BuLrETNiCcvArlpNrO/K1jKR79nV/YFyjOOwLQqLI1YTIYzs2X1mWHRt7BCi/QR
         mAxFQH7WTvqRz8p4DWN5Zisgxd7OvMsVGP5v/OKNmgSdtMfz4zBqejlhYu0VD5cmz2Y2
         dlZlF5GqeRhtczeVJol1WNwew4Hi9BxrkqIWcSnydWsjL/T8l0Or8r2RPNFXmUG4O372
         4ANJL/u2Qa2PHfvWsbaud3rcMyUir+G1hUZkUfFY0KOAYg+gwLeqgZzI0ot9NGh2Pbsz
         7A8A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=XKfzn3o3;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755850513; x=1756455313; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:in-reply-to:from:content-language:cc
         :to:subject:user-agent:mime-version:date:message-id:dkim-filter
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=Ej4CB8eteHb/22FtqK1LUgLyI+2ZB6hPD4jW3puSW98=;
        b=oDeA2Bujdihq1sh0RX9QO89pCswyZC1b0+s9d9qcZ1mHBXddZtFbaCg+DL9hqUFgg9
         V18Sx9Zm9APqNLoGtiJ5MjIIn6BgiRPp5vJsMXLo3xPjFh3gB0wb6mMQlfeQFDnoLUmV
         CfcmeqCQ06pNWpaB1drS+2lasNFWDCWMUOW6CDT6EnFzZyzS9Qrlye2M8a1r8VpBUKSe
         xAuAcU5T3kaWhddvESi5Xti6t+ENkhr0FZceM/HGZuz5E23JOW0OUVVHsnBmYqd3WTr7
         kWhP+3Gs1Q4iA8Y2j4xNQclJ8Yk/0ahGGFTM82oBUUtZUzqNrSMCU9Pjr4UzJcWwaCY0
         uhVA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755850513; x=1756455313;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:from:content-language:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-filter:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Ej4CB8eteHb/22FtqK1LUgLyI+2ZB6hPD4jW3puSW98=;
        b=eiC0xhe9xzDGIhvKvLm9k/qxIaccTVe9E+DiwIgWm1+lV7xUPPcJ093Sf6XZln4I+2
         VSYIUMshR38kGaIfgthiz9TLPmoJnSDTC1crBwfooMdlnZhU3HhqduHFoouP3zjl7++w
         eA2Oam+lj718bqOpzxWfZDRBAoViw8s3ELaPQ3D6jSeufM20wQ6NEQ/+B9+/wtyZmAx8
         yBOdOd3zQ8+bYR97jQKagdYNUpPbifg+YIMLi+ZGAX33I3szhhYYcdcHASunPynXhq99
         A5HaW4iQ5o+tKl6qbIfMSANrnZPBNPGYxNOEgPB9F9FT1f2hTAEapQkqi7tcccX8s4ce
         YyNw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXG1X3sOQTyh300BeT4tM5OpGWj2m6DrIxe/gp93GtN8Izl3bjb1TGsV6vf7OtBSoXjL3ZbKQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz6TIflteyN7w7JRtLANDV6SWW7HPcldAmoANr7Yrc0noDnlTOF
	2UIxBkSh6Tujq4fgwioOCisDNiLXo6og5HxM41pyhyQJbREvk9+kTZ2c
X-Google-Smtp-Source: AGHT+IEkUDi4nOM9JUZo69bJteSzmQd+JOA09DRp8lUA/7fyLFDQaligZEy05UzwvzomaVnzxMVc0w==
X-Received: by 2002:a2e:be2b:0:b0:333:b1c4:4d8e with SMTP id 38308e7fff4ca-33650f9e9c7mr5529661fa.35.1755850512313;
        Fri, 22 Aug 2025 01:15:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd3xSKbB/tfp27BO3vnNMvPnj4DnQXlxLWZtTeWyVNoUA==
Received: by 2002:a2e:ba02:0:b0:335:1f53:9699 with SMTP id 38308e7fff4ca-33546b1246dls3493321fa.1.-pod-prod-01-eu;
 Fri, 22 Aug 2025 01:15:09 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXexGMgRYZnCliWQpCl4oR/X3tpvGVkk9RmoYzUD2ykmmge494G2okCf2PvVC+fPRByzkIdu2QspZQ=@googlegroups.com
X-Received: by 2002:a05:651c:e0c:b0:333:f936:d9a with SMTP id 38308e7fff4ca-33650f68d70mr4085681fa.32.1755850508983;
        Fri, 22 Aug 2025 01:15:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755850508; cv=none;
        d=google.com; s=arc-20240605;
        b=ZOBJwvaky+U4d667WTb4mAwL27AxFKnIeRqmsYIIq8jmG4uOM2gmXn61FOEuyVnVK8
         c46TiViyCc+Wfy/YhhE2j1nG+l0ISP3yF1yb5b4s3Q9H7TNqMX2JgSTwFNegt2XDAcoN
         Bdlwft0Q5ojEOA+WY5t7vbSF9xMf5avJvEHp8tvQFVa+OPtqNFntB7K0GGs1VC8iLRDl
         a2SJ4rdtDjFSi8+wKr8n1skD8puzRlCXXPRuwahezCK2JjvaUn/wYNPHfLMdVdUgbhv7
         IGj+bntB+EGdbMZL5IMHJs80yz4SKB1jN6PuRRAVTfXdzXhmAZ+8rTgd7v8WxyeGTjs3
         HfJA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:content-transfer-encoding:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-filter;
        bh=8D7LpAOoviBYk7WIQ6GdtJERZ5Q8as878mTjAUnE/1s=;
        fh=434W/smBDAKnzNUInuDGB+/Y5IZcTuwH+TP7CcNzZZk=;
        b=d3vm8wm+gTuwiSxF4faoGi4VU7DLTA1WrwqZBRy38Uog0STfiT2L/S+q8NVcXs3dY2
         ftapFbWY14m52ai4Ad1wxjSBtgD5TQmbKdZk7GMgOHGjpkfZNjF1qurHX4BWbBOLdQVA
         tOI8RTHfD3dcQdiyK4BJhv3f5VewOyhjgMMQ0N5QW/vXp+6JYp3mS5vw/4ZlmZxs7v2E
         WA7LkpMDoPqWJbysCFnK0y78kInBcn4IjsHxOYmIC5AD/JA7bH+7wdBp5CSHPd/b/QFU
         CJXPywMQUOQhxrKW3vCYfMiJ7jMn4asEGl1106H2SGCoC0ekbDPxEKe4it3WynPTtB7H
         HJPg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=XKfzn3o3;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout1.w1.samsung.com (mailout1.w1.samsung.com. [210.118.77.11])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-335ccaa6e84si509961fa.4.2025.08.22.01.15.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 22 Aug 2025 01:15:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) client-ip=210.118.77.11;
Received: from eucas1p1.samsung.com (unknown [182.198.249.206])
	by mailout1.w1.samsung.com (KnoxPortal) with ESMTP id 20250822081507euoutp011eb6e04748c75467354f864a5b13dcb2~eCLvKXWHt0802008020euoutp01T;
	Fri, 22 Aug 2025 08:15:07 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout1.w1.samsung.com 20250822081507euoutp011eb6e04748c75467354f864a5b13dcb2~eCLvKXWHt0802008020euoutp01T
Received: from eusmtip2.samsung.com (unknown [203.254.199.222]) by
	eucas1p2.samsung.com (KnoxPortal) with ESMTPA id
	20250822081507eucas1p2f6977174baf330e1c895de7ac7b91cc1~eCLu2KEdp1444414444eucas1p2a;
	Fri, 22 Aug 2025 08:15:07 +0000 (GMT)
Received: from [106.210.134.192] (unknown [106.210.134.192]) by
	eusmtip2.samsung.com (KnoxPortal) with ESMTPA id
	20250822081502eusmtip2e6ed6d47d5194e587353269471a8bda2~eCLqth-G50411104111eusmtip2L;
	Fri, 22 Aug 2025 08:15:02 +0000 (GMT)
Message-ID: <debc61e1-683c-4fcc-9040-d55324f096f7@samsung.com>
Date: Fri, 22 Aug 2025 10:15:01 +0200
MIME-Version: 1.0
User-Agent: Betterbird (Windows)
Subject: Re: [PATCH RFC 22/35] dma-remap: drop nth_page() in
 dma_common_contiguous_remap()
To: David Hildenbrand <david@redhat.com>, linux-kernel@vger.kernel.org
Cc: Robin Murphy <robin.murphy@arm.com>, Alexander Potapenko
	<glider@google.com>, Andrew Morton <akpm@linux-foundation.org>, Brendan
	Jackman <jackmanb@google.com>, Christoph Lameter <cl@gentwo.org>, Dennis
	Zhou <dennis@kernel.org>, Dmitry Vyukov <dvyukov@google.com>,
	dri-devel@lists.freedesktop.org, intel-gfx@lists.freedesktop.org,
	iommu@lists.linux.dev, io-uring@vger.kernel.org, Jason Gunthorpe
	<jgg@nvidia.com>, Jens Axboe <axboe@kernel.dk>, Johannes Weiner
	<hannes@cmpxchg.org>, John Hubbard <jhubbard@nvidia.com>,
	kasan-dev@googlegroups.com, kvm@vger.kernel.org, "Liam R. Howlett"
	<Liam.Howlett@oracle.com>, Linus Torvalds <torvalds@linux-foundation.org>,
	linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
	linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
	linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
	linux-mmc@vger.kernel.org, linux-mm@kvack.org,
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Marco Elver <elver@google.com>, Michal Hocko <mhocko@suse.com>, Mike
	Rapoport <rppt@kernel.org>, Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>, Peter Xu
	<peterx@redhat.com>, Suren Baghdasaryan <surenb@google.com>, Tejun Heo
	<tj@kernel.org>, virtualization@lists.linux.dev, Vlastimil Babka
	<vbabka@suse.cz>, wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan
	<ziy@nvidia.com>
Content-Language: en-US
From: Marek Szyprowski <m.szyprowski@samsung.com>
In-Reply-To: <20250821200701.1329277-23-david@redhat.com>
X-CMS-MailID: 20250822081507eucas1p2f6977174baf330e1c895de7ac7b91cc1
X-Msg-Generator: CA
Content-Type: text/plain; charset="UTF-8"
X-RootMTR: 20250821200816eucas1p1924e60579da49c1dfed300c945894d83
X-EPHeader: CA
X-CMS-RootMailID: 20250821200816eucas1p1924e60579da49c1dfed300c945894d83
References: <20250821200701.1329277-1-david@redhat.com>
	<CGME20250821200816eucas1p1924e60579da49c1dfed300c945894d83@eucas1p1.samsung.com>
	<20250821200701.1329277-23-david@redhat.com>
X-Original-Sender: m.szyprowski@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=XKfzn3o3;       spf=pass
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

On 21.08.2025 22:06, David Hildenbrand wrote:
> dma_common_contiguous_remap() is used to remap an "allocated contiguous
> region". Within a single allocation, there is no need to use nth_page()
> anymore.
>
> Neither the buddy, nor hugetlb, nor CMA will hand out problematic page
> ranges.
>
> Cc: Marek Szyprowski <m.szyprowski@samsung.com>
> Cc: Robin Murphy <robin.murphy@arm.com>
> Signed-off-by: David Hildenbrand <david@redhat.com>
Acked-by: Marek Szyprowski <m.szyprowski@samsung.com>
> ---
>   kernel/dma/remap.c | 2 +-
>   1 file changed, 1 insertion(+), 1 deletion(-)
>
> diff --git a/kernel/dma/remap.c b/kernel/dma/remap.c
> index 9e2afad1c6152..b7c1c0c92d0c8 100644
> --- a/kernel/dma/remap.c
> +++ b/kernel/dma/remap.c
> @@ -49,7 +49,7 @@ void *dma_common_contiguous_remap(struct page *page, size_t size,
>   	if (!pages)
>   		return NULL;
>   	for (i = 0; i < count; i++)
> -		pages[i] = nth_page(page, i);
> +		pages[i] = page++;
>   	vaddr = vmap(pages, count, VM_DMA_COHERENT, prot);
>   	kvfree(pages);
>   

Best regards
-- 
Marek Szyprowski, PhD
Samsung R&D Institute Poland

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/debc61e1-683c-4fcc-9040-d55324f096f7%40samsung.com.
