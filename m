Return-Path: <kasan-dev+bncBDG6PF6SSYDRBGWOUDCQMGQEPEGKKJA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6CE99B31160
	for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 10:15:24 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-45a1b05d8d0sf12213125e9.1
        for <lists+kasan-dev@lfdr.de>; Fri, 22 Aug 2025 01:15:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755850524; cv=pass;
        d=google.com; s=arc-20240605;
        b=FzfLHpiDX4G8oslcQ1Qc4Tv6GTlOgm0BA8DAqReV2WEpEs5SPIjr9ztKgrNgOnVmJI
         ESL6Z3P3yzy7wUkc/t1BnmRomkxggM9fqSUyhgHqvB3Zu53yCCO4xjmvYxh4PwGxCxl/
         a+yDFXw/XAOaZeMekJFrxhNhMiR5BH33+5WS8AwQ8h7ar4oWJj/TnHKEnYfMNd5trlY3
         fue7ur5D1G0y6vEImmzim0fFhQTlbE6nTBM6nfj8ti8/Gl3hM1w+yhgnaF7qv4m1RIjZ
         4Ew8JdW7lQXmP37/VjlHcs7Z+F2Bfovzp9+C8zNP+pfke0QrAQcTz1EkH717lKM67bTA
         I5AA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-filter:sender:dkim-signature;
        bh=LKUHt2gl0l69ylXjSSL2eIuknfP+hUyPchf2B9NJmsY=;
        fh=wyyW4LobIpfxtt81zasEkvht7xGYJjzBORejZjo6aXs=;
        b=Nzxq3y0zHMJMmqUXzpu3BO+y/AvgBSKdr/8yHCGGf9PDsNGPpyWS4r0u6hXuSyYTgH
         MwPPSOa6VcyVXI5sqiKHGY7ESaT5cNyiXjXAfnERs/H5xYBCZQxObM+KhFHdeMvR8Jll
         ZTQ8RTKbO+elLLXjrsz1CFlpA3Q7OtVCJXn07/x15nd9d9V024iFgizdo5QJnxBUMFMZ
         UA3MLSFUG0XBMs171gHe113xz8kdxLvWQEsp7VipHed3mkf98Dp57qWK7t/Xe/OHZ3Db
         +w052x8NUPsFl4evPye6LR+w/XZgejq8bQt8/9zhyScE2BYcuHwQ7IQ/Wj3QDZrdx2A/
         aRGw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=e4dvoXQd;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755850524; x=1756455324; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:references:in-reply-to:from:content-language:cc
         :to:subject:user-agent:mime-version:date:message-id:dkim-filter
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=LKUHt2gl0l69ylXjSSL2eIuknfP+hUyPchf2B9NJmsY=;
        b=jgXDcevW1UgTEen1DCQ4IOihrtX1GrMWYnw/cMTvzvE893kh2FIYgJfJX+0Ec4BBOc
         PXBG6OSAFu7Y6o3dYBzlRaElbJNU/EKb3NnYYdgCoR+jmmGLt1nsRFftM6es1PPm7Hb6
         yB/zUtWVOMaMHciL8EvM/o8yTUh2Wo8A3rbXBbG7VTZvpEn1HvNt80YAVbGiChCD1sHS
         cI/lflZIkv7TPI3+Z9m72Qv+ti9+Nc/tthZXq0airaoYWWFWf0n04KrpBwoPApyk5BeN
         47QSA3mBqLLNIykWo8BWhBan8we4TtQ/s7K+KjAMXV4iGRVkHfkOc+eeeJJThK1VLP34
         hgmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755850524; x=1756455324;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:references
         :in-reply-to:from:content-language:cc:to:subject:user-agent
         :mime-version:date:message-id:dkim-filter:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LKUHt2gl0l69ylXjSSL2eIuknfP+hUyPchf2B9NJmsY=;
        b=PYSDjUdj0V2R3YGAQhlQWNZiF0KHQI6/7HUdf8ZKM2svGa6hfaMfGZwS7usYga5D5K
         NAMW6kqiRuv+3my8kbOWEoS0R5UnTl95BMlBSVIwM4PuwSjtsBm9Y4GXnazYb23p0XR9
         caGPCN53HuPE9tV+qzklVIZNeye1ZP1S3UwJATKQKyOJr548WoRooz/OdK1OS3IL4gvO
         onNzWXdJpzKkSyuYkNXCK5Ay3J0Fx+NyrU7713VkKJ3l5BlRYfgpQ0fxWP1h1Qwh6+4A
         LBsXIx9m6MmUXwMoU7MquCYz8BzG9ZVmNh03tTj65sAIduWb9bD11OQBSNuNee51esTs
         x1lA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXw4Z4UIQ4sSMomHNhjVtnuv7oK2yy8eD5m794i82ORTvUGpLQ4uVYasBDsKBrbheDCicRKaQ==@lfdr.de
X-Gm-Message-State: AOJu0Yz8WwLbsxsDE12GTWuzmlgumIYWcBBkohxnMwxzxUvJCq+OXmtB
	ZWVpCsZo6BejFJn1VljumSK2clijmq4rlG+7AvNxSj5vNDoxoJg4aBIb
X-Google-Smtp-Source: AGHT+IH8giFCQhdLhYZ1PlI9jSvcGnHvoOBBzRC8LxOX1BRXbhhwGnbnqkypAwjAlxcLubmhvEM9ZQ==
X-Received: by 2002:a05:600c:350c:b0:45b:47e1:f5ff with SMTP id 5b1f17b1804b1-45b517dbf8amr14977905e9.35.1755850523373;
        Fri, 22 Aug 2025 01:15:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcjYew7TO66gVL8SrrwDXTvjhZX9/x5xvNeyHziPmY8hA==
Received: by 2002:a05:600c:3148:b0:455:1744:2c98 with SMTP id
 5b1f17b1804b1-45b4c8d225cls14029725e9.1.-pod-prod-02-eu; Fri, 22 Aug 2025
 01:15:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVsNwrjFfs5BmoQV9yHlSsltNDadCdkmHjiREb47aerB+7n/cTP1QT2u0XPrfs8gwZVRSLLQu67fgQ=@googlegroups.com
X-Received: by 2002:a05:600c:3b23:b0:45b:47e1:f600 with SMTP id 5b1f17b1804b1-45b517dc59bmr15713955e9.36.1755850520692;
        Fri, 22 Aug 2025 01:15:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755850520; cv=none;
        d=google.com; s=arc-20240605;
        b=NWzMj+WRqb5HL7KnFRqEYIjjgZ8MggUDFJAuZJmRWyrVl7n5CuDMB1X74XA9Sl92ZR
         V1heanhLkeNY6louf8v/tKNP+k45oOApGNJ9YWOIDjXhUswCvM6cAcEWOBMiYBKEgQD3
         FeVjNxOpDDBK4ajzz/86r3qxy8hnCTfbqHoadN8H64Z0xRZ7I8ucAwjrwmnc4lsxvC2W
         agBHl8K6fq6Ag7TeBqY//9zS5S8Zj1OqpbQL7ho57JQWqrxsxL0iB55nAOnkrCA2FpqF
         a//IAMYWyc41DG34i9Io3kk60o2J4du23aJSunwKwOnOjF7CR9+YoYy4hv5I4puukYED
         sc8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=references:content-transfer-encoding:in-reply-to:from
         :content-language:cc:to:subject:user-agent:mime-version:date
         :message-id:dkim-signature:dkim-filter;
        bh=gSgM5v5QN4mf4R9UjO3p9g49c5fElcblzx9rfuNpgCM=;
        fh=HDaU2gOrRKRNJ8ECyZiTgKd3xYQHtmmON0mO+qx0FFY=;
        b=U7yvT+UmmOgg14wpUfbHrgyeFeIz/mmbPoNHtumiGyASBvCp9UkmqRKXn1rqmInjg1
         N+8fbLvh6eqS0zv46f6H9QBmFx/TAgtvqbQiTYs9ZWN9IiIDu8IrU/NOTEhbCRZ810hu
         71fO45fxaWV891N807tuzebyx48X9eMYvI8NthXP/52/W52guV8Fi3iJwQnCVSVDp9de
         jDHqPPp7CYcFEDfh091QnkO+sd8XnLRmxS9/eGkFMu44pa0/oPsiw7kvsfh/GxvGRf+p
         FrCfBv5kTpNJfS9X8RGqvZXCn3dNCtDZiwVa1rgNmZrY2KL2I1HoHGyGOsBkea0P2lCf
         KRqA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@samsung.com header.s=mail20170921 header.b=e4dvoXQd;
       spf=pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) smtp.mailfrom=m.szyprowski@samsung.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=samsung.com
Received: from mailout1.w1.samsung.com (mailout1.w1.samsung.com. [210.118.77.11])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45b50d5f750si431345e9.0.2025.08.22.01.15.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 22 Aug 2025 01:15:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.szyprowski@samsung.com designates 210.118.77.11 as permitted sender) client-ip=210.118.77.11;
Received: from eucas1p2.samsung.com (unknown [182.198.249.207])
	by mailout1.w1.samsung.com (KnoxPortal) with ESMTP id 20250822081519euoutp01946853c37392c604dd0c3ef7d9f9864d~eCL6pnShX0804708047euoutp01V;
	Fri, 22 Aug 2025 08:15:19 +0000 (GMT)
DKIM-Filter: OpenDKIM Filter v2.11.0 mailout1.w1.samsung.com 20250822081519euoutp01946853c37392c604dd0c3ef7d9f9864d~eCL6pnShX0804708047euoutp01V
Received: from eusmtip1.samsung.com (unknown [203.254.199.221]) by
	eucas1p1.samsung.com (KnoxPortal) with ESMTPA id
	20250822081519eucas1p173966299ee7e4ed7e44e5668490c5bb1~eCL6VCjyQ0206902069eucas1p1F;
	Fri, 22 Aug 2025 08:15:19 +0000 (GMT)
Received: from [106.210.134.192] (unknown [106.210.134.192]) by
	eusmtip1.samsung.com (KnoxPortal) with ESMTPA id
	20250822081515eusmtip1e7bc345219f25d2646a53b4e40310c91~eCL2XTm3N1429714297eusmtip1U;
	Fri, 22 Aug 2025 08:15:14 +0000 (GMT)
Message-ID: <8c4b0068-92be-427b-8bfc-9926eea6aa09@samsung.com>
Date: Fri, 22 Aug 2025 10:15:14 +0200
MIME-Version: 1.0
User-Agent: Betterbird (Windows)
Subject: Re: [PATCH RFC 23/35] scatterlist: disallow non-contigous page
 ranges in a single SG entry
To: David Hildenbrand <david@redhat.com>, linux-kernel@vger.kernel.org
Cc: Alexander Potapenko <glider@google.com>, Andrew Morton
	<akpm@linux-foundation.org>, Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>, Dmitry
	Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
	io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>, Jens Axboe
	<axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>, John Hubbard
	<jhubbard@nvidia.com>, kasan-dev@googlegroups.com, kvm@vger.kernel.org,
	"Liam R. Howlett" <Liam.Howlett@oracle.com>, Linus Torvalds
	<torvalds@linux-foundation.org>, linux-arm-kernel@axis.com,
	linux-arm-kernel@lists.infradead.org, linux-crypto@vger.kernel.org,
	linux-ide@vger.kernel.org, linux-kselftest@vger.kernel.org,
	linux-mips@vger.kernel.org, linux-mmc@vger.kernel.org, linux-mm@kvack.org,
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org, Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Marco Elver <elver@google.com>, Michal Hocko <mhocko@suse.com>, Mike
	Rapoport <rppt@kernel.org>, Muchun Song <muchun.song@linux.dev>,
	netdev@vger.kernel.org, Oscar Salvador <osalvador@suse.de>, Peter Xu
	<peterx@redhat.com>, Robin Murphy <robin.murphy@arm.com>, Suren Baghdasaryan
	<surenb@google.com>, Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com, x86@kernel.org, Zi Yan <ziy@nvidia.com>
Content-Language: en-US
From: Marek Szyprowski <m.szyprowski@samsung.com>
In-Reply-To: <20250821200701.1329277-24-david@redhat.com>
X-CMS-MailID: 20250822081519eucas1p173966299ee7e4ed7e44e5668490c5bb1
X-Msg-Generator: CA
Content-Type: text/plain; charset="UTF-8"
X-RootMTR: 20250821200818eucas1p2c3df1e12eeba86a68679743d2f5929a8
X-EPHeader: CA
X-CMS-RootMailID: 20250821200818eucas1p2c3df1e12eeba86a68679743d2f5929a8
References: <20250821200701.1329277-1-david@redhat.com>
	<CGME20250821200818eucas1p2c3df1e12eeba86a68679743d2f5929a8@eucas1p2.samsung.com>
	<20250821200701.1329277-24-david@redhat.com>
X-Original-Sender: m.szyprowski@samsung.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@samsung.com header.s=mail20170921 header.b=e4dvoXQd;       spf=pass
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
> The expectation is that there is currently no user that would pass in
> non-contigous page ranges: no allocator, not even VMA, will hand these
> out.
>
> The only problematic part would be if someone would provide a range
> obtained directly from memblock, or manually merge problematic ranges.
> If we find such cases, we should fix them to create separate
> SG entries.
>
> Let's check in sg_set_page() that this is really the case. No need to
> check in sg_set_folio(), as pages in a folio are guaranteed to be
> contiguous.
>
> We can now drop the nth_page() usage in sg_page_iter_page().
>
> Signed-off-by: David Hildenbrand <david@redhat.com>
Acked-by: Marek Szyprowski <m.szyprowski@samsung.com>
> ---
>   include/linux/scatterlist.h | 4 +++-
>   1 file changed, 3 insertions(+), 1 deletion(-)
>
> diff --git a/include/linux/scatterlist.h b/include/linux/scatterlist.h
> index 6f8a4965f9b98..8196949dfc82c 100644
> --- a/include/linux/scatterlist.h
> +++ b/include/linux/scatterlist.h
> @@ -6,6 +6,7 @@
>   #include <linux/types.h>
>   #include <linux/bug.h>
>   #include <linux/mm.h>
> +#include <linux/mm_inline.h>
>   #include <asm/io.h>
>   
>   struct scatterlist {
> @@ -158,6 +159,7 @@ static inline void sg_assign_page(struct scatterlist *sg, struct page *page)
>   static inline void sg_set_page(struct scatterlist *sg, struct page *page,
>   			       unsigned int len, unsigned int offset)
>   {
> +	VM_WARN_ON_ONCE(!page_range_contiguous(page, ALIGN(len + offset, PAGE_SIZE) / PAGE_SIZE));
>   	sg_assign_page(sg, page);
>   	sg->offset = offset;
>   	sg->length = len;
> @@ -600,7 +602,7 @@ void __sg_page_iter_start(struct sg_page_iter *piter,
>    */
>   static inline struct page *sg_page_iter_page(struct sg_page_iter *piter)
>   {
> -	return nth_page(sg_page(piter->sg), piter->sg_pgoffset);
> +	return sg_page(piter->sg) + piter->sg_pgoffset;
>   }
>   
>   /**

Best regards
-- 
Marek Szyprowski, PhD
Samsung R&D Institute Poland

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8c4b0068-92be-427b-8bfc-9926eea6aa09%40samsung.com.
