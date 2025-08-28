Return-Path: <kasan-dev+bncBD4YBRE7WQBBBQERYDCQMGQEAB5K4NI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33e.google.com (mail-wm1-x33e.google.com [IPv6:2a00:1450:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id B4BBBB395B4
	for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 09:44:02 +0200 (CEST)
Received: by mail-wm1-x33e.google.com with SMTP id 5b1f17b1804b1-45b7a0d1a71sf2554835e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 28 Aug 2025 00:44:02 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756367042; cv=pass;
        d=google.com; s=arc-20240605;
        b=Q5LJXhNn612+0k5xYxJAo3egbo6cFMn0a82TUnL8a3+7ZLU9roemZJ3CnjgSCwEjOI
         iss80y4iG5Ka0x6CCyClOmeJRNqetzv38A7ICbeUoDSt+F6A3tZCfYMzqCVGq8w3KQXE
         tZuHpV2nLz7zLwP7dXHdmtBbUhlEqn0omM/Fr009mGoAAJ70H9CzIq1zyP7ZJaD7v6ef
         8w/vKtarlXUQqleb+Gv7hpkFAMHB05WMZbx7bmLqbqfSELxkhiew/v5izNFj3AeIdujj
         tv2ZvKQ3S6JgC0kXZbegZNSJb+rP7yyJ/gG17y0AcFFT/3nApsW/PRx3cqOtrfuS0U9u
         JkfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:sender:dkim-signature:dkim-signature;
        bh=T7xYDcJTUbdAzJb+zUjpVrqcVljU9fYLcBIpHbPUBno=;
        fh=Lk3N2JJ9zdwMwRZB6qyuEGUQtsSeT+iJY9xfBcP9Myo=;
        b=VDjchZdtYED9Ty4PZ/CSok4Q817HA6Cr4dvmw8uJYXqldStGj9c3J9koAVk5wkR8x2
         HvtVidaLrdwiL8zXn81QOi3dwmtX9Q0K5yCEsADRf5MUEUWrGYA87C3EXPDPvZozn+/I
         h7Wdk62IbKywiKn8SThwRyjZdIK0ic0xDowBXmBi+FWrBtAzPiZRO9Bbh32AFMCzHUt3
         a+EoPG7sYrCuii1Bj9L6CAzuIIKtXfKH+0uIRMfdqwRQUwGwY/cyjTVDByxD8jsfSiii
         PtVULIMTYQAx0zCFqzRsGaNi6cb1ESVyoEwrtaWl3My/ct1YK9Lb6LzIzyyd9jx0qK2H
         XT9A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="cd9u/uQf";
       spf=pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756367042; x=1756971842; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=T7xYDcJTUbdAzJb+zUjpVrqcVljU9fYLcBIpHbPUBno=;
        b=MELEuUmAB9lse8wDTgY/0lAQnt1noaxIu8vY0v1A9g63l4R8oUtu58yCdpROtkG8QQ
         glvLaW6EFQzYihzbAN/r5MTdTihlj7GbVETCcUJf0AoqXAjIlIdfLEybCwnp1QsMfmfH
         gc5mYmXpxm+vHRkF4sSZoN8Z/hhE5WDCyWdbVfZGHgwvp+ySMYiQzmFB/h8PvA8IrRfv
         iLqQgJlZbjhTwCezGU5uYq/HS0P0wmmus0us7G3r/kwebo/fRyY2PSzUtjQTEHtspEym
         0gaOHm9OdaXeKabCPlX/eVpOBDoA0m2kK11mphNIwJB2aBkcwpm58tOrTwNfxkAyRza1
         AdZg==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1756367042; x=1756971842; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:reply-to:message-id:subject:cc:to:from:date
         :from:to:cc:subject:date:message-id:reply-to;
        bh=T7xYDcJTUbdAzJb+zUjpVrqcVljU9fYLcBIpHbPUBno=;
        b=RSVu77IY+mF59l79QrJdwixSc5/eUGHKzMCqLrDxXmRtuik4uhMteR5NYRbo2NEz1d
         UfZL3dZv735BK4NrLUQxQaeM/DbpZ/XvzBHtNjzA9AdVX/T3W+K6OvBGAVAD6UZytXsD
         O8Fo0z5SY1+Pi9R5ki/T33SeNQqdOtXnrp3C2VICB45LcHS5bK1EsZvVfaC96CA8EbaH
         BREoYBg1vpdpuA/p7wL8Cv0YAmV8ctCvu5g51Xy+wz3OvXpPYJKtOuh1Si70JnpmWbht
         VWS7hMHRTjU3T2nQV1g6Zx9Y4qJs5Hi0n0fIdqmYm40OAjjtT51et6ry/meVKHV4lYYy
         ODmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756367042; x=1756971842;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:reply-to
         :message-id:subject:cc:to:from:date:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=T7xYDcJTUbdAzJb+zUjpVrqcVljU9fYLcBIpHbPUBno=;
        b=FAH+DSaKEukPSZ4Z1GKz5t5YiALrWtGsD6HYndBwtiANHbYRl2PsCrxlsaNUsTPb4F
         fWPO1d16zP1ZXXGYwlo+X97c27789i07WXJ4NV4BHxuiTHZOI1xI9RPEGADZ36RKo5BU
         9BhnBXzXglDgJGAx3uA4oGm5ArCrvYZ4JPnGdsMyPkAi/vDqAAtraxAwBs+SGGgZc9P9
         uN1INLcq7sv678sUQGLc/kBZZCAFDaQiNvIXz2eaLcbh6LfjztUYl6Jl/UN3v1UvynRT
         KXaNM9+DbKUuQbATWONsLvAgmiQhvgtzZhnenzjZ7xPsegOvxiOuvMJC7ksolWNVvPxU
         LvQQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXe5m9dn2ONsOQgyEOuo16w3MviM6lH+lhLcsbPnjzQ+XHiqJ+gChyK5XZQidJCJCs63GZLpQ==@lfdr.de
X-Gm-Message-State: AOJu0Ywx3tFF+QkGbg11QokIBsFgzxUh5CazgH9pGlX8n+/WSYk1DcaR
	ph87VQ2sCOke5AI/C8XsaHMVsUCRFAvnASoNHJSFOX5KJFWXhLSB3pJW
X-Google-Smtp-Source: AGHT+IH4PFyNzxn5mrv5us34DCKATppouNh4AOEHdyaMbUDr8Y+wOcBXx8trsFsBGkBjzX/26CBaTw==
X-Received: by 2002:a05:600c:3b9e:b0:459:dc35:dc05 with SMTP id 5b1f17b1804b1-45b517a05e5mr197410075e9.9.1756367041656;
        Thu, 28 Aug 2025 00:44:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZchLwaKfgnQSBQUDTT79XBDToPPUUAHw3NTPkVOKcLkSA==
Received: by 2002:a05:600c:3b9c:b0:459:e1a3:c3bc with SMTP id
 5b1f17b1804b1-45b78cc856dls2792215e9.1.-pod-prod-09-eu; Thu, 28 Aug 2025
 00:43:57 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWxWUoeyzWJnK+eaCViJZIdHC9g+G0oGQdKv0rh7+TNmoBg8FG9jyJtuCjxjN3/ys/P7uPEpe+BvA0=@googlegroups.com
X-Received: by 2002:a05:600c:1f0e:b0:456:1611:cea5 with SMTP id 5b1f17b1804b1-45b517cbed7mr206523725e9.18.1756367037431;
        Thu, 28 Aug 2025 00:43:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756367037; cv=none;
        d=google.com; s=arc-20240605;
        b=lHWoU9LB2p0OaX7ch5251fz4f3HJhJ3TWp8Uq0QJ+C7Cos0WiOlO40abnGSrcu5WsO
         FqMht8+IFMQC84XA0Bsa/N5bqOxZGBOnEWHBVqQVTKCFyL4PCpa43t8ZDabu2v/r8YL0
         qmE6+TN2gVtosKMHB7tV3+jX1wvVQQTBUSXkIxcVpU3jMaB37akEv3qS2tBZudNCyo0j
         a8VYjezb+mnsfNJZ8AUT1BxX5HMpnfV7u+jY2RhjJyNGMExLOsanHRQerK0gEM90G+2f
         CveaayNEKWPZq9no9Zb3sSGKyScz9/ConeqPg8vzOsnaVm5fwahyBSuRjOETwaWliv4A
         202A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :reply-to:message-id:subject:cc:to:from:date:dkim-signature;
        bh=uCyWFKVmsqDpuka3mORfqvZ6ED5815cQsuT83UfJ0fY=;
        fh=Xwtd8i2q5Jsjh06DuuuKBwCnqBCRgy5L6u3wFUE9Blk=;
        b=RtU8N78FxSXZdxmgXQ91YeEHYzeNZghnLJYGVTfcge5ulrUp+inp/PI8YjUl9wslOY
         hslAhLL+4rW9Q6G7K+idH7zxU52emuEg6f5RPlOsR5TCd2piWsz+F0pTMWvRniVGN4rQ
         nxz7DKPXEpFSQpIU1qoZI9901EDtPq3bBlJIfQbMw9qOD6tSY3BEdo3NLFtXnGEuv+W4
         PSGI0YiN9GFm1No3DeIONH/AM8tioUSbULjhhmn3Ijl0XpSBO3lDOjTv+BBiJReuTlF1
         AiR6OR3jUSOdwZuDqkihCkz4MnucrvXTdcOpSHtO7v53jsOVMcxdlrY6wAbYslU7wm02
         cghw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="cd9u/uQf";
       spf=pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x532.google.com (mail-ed1-x532.google.com. [2a00:1450:4864:20::532])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45b6f072618si691405e9.0.2025.08.28.00.43.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 28 Aug 2025 00:43:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of richard.weiyang@gmail.com designates 2a00:1450:4864:20::532 as permitted sender) client-ip=2a00:1450:4864:20::532;
Received: by mail-ed1-x532.google.com with SMTP id 4fb4d7f45d1cf-6188b6f7f15so733726a12.2
        for <kasan-dev@googlegroups.com>; Thu, 28 Aug 2025 00:43:57 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUCEgNgf7FJOuaublq3e0hFBLQTCDuE18K9Xf7kkRnBjtR8uTFFGcnJl/CRptcSestgEb+ImiTxDAk=@googlegroups.com
X-Gm-Gg: ASbGnctHqBa5d7P8deh6y0ic4MouLZ6EyQnMQl2OHMESS1IiOdxD/lh3+FqxWk4dLEx
	yChg8/lOxLn1iG+yZ8MSDstYRAuwBDG99bV2RmCYYBe7DAE0aHMPV9FQMX1NWeyoWS4gHhc6TZD
	NVLwyeux/Mp8XY/oTonJQNsN1Mmh3NkqI76M+ftibTa/TxMpFutfTt03zUmY0pxCn5eOBYR2cQ4
	W7juCLhgbOJu3xenaczMRece7+ikqAS29+7Is53rFhJc6mNYTjVR35fFBlbTaS96Kf4mqypbrAO
	iFD/5Vd27AM/r3kTonYS9lKpqN7p1aIjOsCy2rPcsHBCl+NRu8VOoVDGEMNWrzr08NlXmMBfxlV
	mFnkautJu+amIRYu7CkoR8GNsqcsKipZ/Yv4awCZcCmBiaKg=
X-Received: by 2002:a17:906:3717:b0:afe:764d:6b31 with SMTP id a640c23a62f3a-afe764d736dmr1280383766b.4.1756367036783;
        Thu, 28 Aug 2025 00:43:56 -0700 (PDT)
Received: from localhost ([185.92.221.13])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-afe48fae316sm1165798866b.28.2025.08.28.00.43.56
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Thu, 28 Aug 2025 00:43:56 -0700 (PDT)
Date: Thu, 28 Aug 2025 07:43:56 +0000
From: Wei Yang <richard.weiyang@gmail.com>
To: David Hildenbrand <david@redhat.com>
Cc: linux-kernel@vger.kernel.org, Zi Yan <ziy@nvidia.com>,
	Alexander Potapenko <glider@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Brendan Jackman <jackmanb@google.com>,
	Christoph Lameter <cl@gentwo.org>, Dennis Zhou <dennis@kernel.org>,
	Dmitry Vyukov <dvyukov@google.com>, dri-devel@lists.freedesktop.org,
	intel-gfx@lists.freedesktop.org, iommu@lists.linux.dev,
	io-uring@vger.kernel.org, Jason Gunthorpe <jgg@nvidia.com>,
	Jens Axboe <axboe@kernel.dk>, Johannes Weiner <hannes@cmpxchg.org>,
	John Hubbard <jhubbard@nvidia.com>, kasan-dev@googlegroups.com,
	kvm@vger.kernel.org, "Liam R. Howlett" <Liam.Howlett@oracle.com>,
	Linus Torvalds <torvalds@linux-foundation.org>,
	linux-arm-kernel@axis.com, linux-arm-kernel@lists.infradead.org,
	linux-crypto@vger.kernel.org, linux-ide@vger.kernel.org,
	linux-kselftest@vger.kernel.org, linux-mips@vger.kernel.org,
	linux-mmc@vger.kernel.org, linux-mm@kvack.org,
	linux-riscv@lists.infradead.org, linux-s390@vger.kernel.org,
	linux-scsi@vger.kernel.org,
	Lorenzo Stoakes <lorenzo.stoakes@oracle.com>,
	Marco Elver <elver@google.com>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Michal Hocko <mhocko@suse.com>, Mike Rapoport <rppt@kernel.org>,
	Muchun Song <muchun.song@linux.dev>, netdev@vger.kernel.org,
	Oscar Salvador <osalvador@suse.de>, Peter Xu <peterx@redhat.com>,
	Robin Murphy <robin.murphy@arm.com>,
	Suren Baghdasaryan <surenb@google.com>, Tejun Heo <tj@kernel.org>,
	virtualization@lists.linux.dev, Vlastimil Babka <vbabka@suse.cz>,
	wireguard@lists.zx2c4.com, x86@kernel.org
Subject: Re: [PATCH v1 12/36] mm: simplify folio_page() and folio_page_idx()
Message-ID: <20250828074356.3xiuqugokg36yuxw@master>
Reply-To: Wei Yang <richard.weiyang@gmail.com>
References: <20250827220141.262669-1-david@redhat.com>
 <20250827220141.262669-13-david@redhat.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250827220141.262669-13-david@redhat.com>
User-Agent: NeoMutt/20170113 (1.7.2)
X-Original-Sender: richard.weiyang@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="cd9u/uQf";       spf=pass
 (google.com: domain of richard.weiyang@gmail.com designates
 2a00:1450:4864:20::532 as permitted sender) smtp.mailfrom=richard.weiyang@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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

On Thu, Aug 28, 2025 at 12:01:16AM +0200, David Hildenbrand wrote:
>Now that a single folio/compound page can no longer span memory sections
>in problematic kernel configurations, we can stop using nth_page().
>
>While at it, turn both macros into static inline functions and add
>kernel doc for folio_page_idx().
>
>Reviewed-by: Zi Yan <ziy@nvidia.com>
>Signed-off-by: David Hildenbrand <david@redhat.com>

Reviewed-by: Wei Yang <richard.weiyang@gmail.com>

The code looks good, while one nit below.

>---
> include/linux/mm.h         | 16 ++++++++++++++--
> include/linux/page-flags.h |  5 ++++-
> 2 files changed, 18 insertions(+), 3 deletions(-)
>
>diff --git a/include/linux/mm.h b/include/linux/mm.h
>index 2dee79fa2efcf..f6880e3225c5c 100644
>--- a/include/linux/mm.h
>+++ b/include/linux/mm.h
>@@ -210,10 +210,8 @@ extern unsigned long sysctl_admin_reserve_kbytes;
> 
> #if defined(CONFIG_SPARSEMEM) && !defined(CONFIG_SPARSEMEM_VMEMMAP)
> #define nth_page(page,n) pfn_to_page(page_to_pfn((page)) + (n))
>-#define folio_page_idx(folio, p)	(page_to_pfn(p) - folio_pfn(folio))
> #else
> #define nth_page(page,n) ((page) + (n))
>-#define folio_page_idx(folio, p)	((p) - &(folio)->page)
> #endif
> 
> /* to align the pointer to the (next) page boundary */
>@@ -225,6 +223,20 @@ extern unsigned long sysctl_admin_reserve_kbytes;
> /* test whether an address (unsigned long or pointer) is aligned to PAGE_SIZE */
> #define PAGE_ALIGNED(addr)	IS_ALIGNED((unsigned long)(addr), PAGE_SIZE)
> 
>+/**
>+ * folio_page_idx - Return the number of a page in a folio.
>+ * @folio: The folio.
>+ * @page: The folio page.
>+ *
>+ * This function expects that the page is actually part of the folio.
>+ * The returned number is relative to the start of the folio.
>+ */
>+static inline unsigned long folio_page_idx(const struct folio *folio,
>+		const struct page *page)
>+{
>+	return page - &folio->page;
>+}
>+
> static inline struct folio *lru_to_folio(struct list_head *head)
> {
> 	return list_entry((head)->prev, struct folio, lru);
>diff --git a/include/linux/page-flags.h b/include/linux/page-flags.h
>index 5ee6ffbdbf831..faf17ca211b4f 100644
>--- a/include/linux/page-flags.h
>+++ b/include/linux/page-flags.h
>@@ -316,7 +316,10 @@ static __always_inline unsigned long _compound_head(const struct page *page)
>  * check that the page number lies within @folio; the caller is presumed
>  * to have a reference to the page.
>  */
>-#define folio_page(folio, n)	nth_page(&(folio)->page, n)
>+static inline struct page *folio_page(struct folio *folio, unsigned long n)
>+{
>+	return &folio->page + n;
>+}
> 

Curious about why it is in page-flags.h. It seems not related to page-flags.

> static __always_inline int PageTail(const struct page *page)
> {
>-- 
>2.50.1
>

-- 
Wei Yang
Help you, Help me

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250828074356.3xiuqugokg36yuxw%40master.
