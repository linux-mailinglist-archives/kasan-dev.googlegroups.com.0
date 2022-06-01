Return-Path: <kasan-dev+bncBC7OBJGL2MHBBCFX3WKAMGQES2MQ36I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x139.google.com (mail-lf1-x139.google.com [IPv6:2a00:1450:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id E0EED53A4F1
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Jun 2022 14:28:57 +0200 (CEST)
Received: by mail-lf1-x139.google.com with SMTP id bi27-20020a0565120e9b00b004786caccc7dsf871826lfb.11
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Jun 2022 05:28:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654086537; cv=pass;
        d=google.com; s=arc-20160816;
        b=EKa+BYSVU/gAH93HWYm3z4fgokfmf/Ye0a+vgb+sCg4XY5ypoKUUN1iVe4VYq7K+M8
         7lVidg74GckozwVl5/IuVONqetGOwWwnqEGKwzXmZ7dLQjacGpZfD/OKaa2VhvNfkphb
         orUhL/pCfNq+iVRjXGp8uzXHQ1EU5v/YFBIsEnV6UCyU5kGR3D8DbvWM2LQvAKzwdD0L
         aaP51T0pdcZ9mXcU+sib3dY7YeJPQxHgm/JjWR8MlaC+2PRz2kpx1M9Iwg3xIKqqyKjd
         owfjM7tAkT45Z/tdJ0t20SIaSV+q47B9iD40tEykemNa4evmQhDPovbifFoAXA/PaWJE
         uEzA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=aWYkL+Onc4y9cpwpxngo2FGYc6bd3FiFEhEsI/RvYKY=;
        b=cIw2brnBxSvLWsHH/Xo+dYfWT5aDYBagofTbQlJ0dfEv02p2nuZRT5PB3ekB/4/Unu
         M4xmspYxWQRfEOcSN5x1lrswSfgxEKtGE39+w3VL2IXiFDUxqkvagIQ0UINirZR9qMJO
         6EMtm+atg4l/p6voKEachO+yOnKdCrvdtQa2il4pY6ZXzipZgvRDIzsAxVlHiPY9Rsnd
         oY3/YbL0AVqhTEiVuZnp7E+B9Te+GTJPy6uyN+uBvsLGX+v47PXCj95GVm5c4n/11erN
         Jlr9tn44fAWm4LwlNq0GqrCcpqw+h+Gzlf35xwW/Eu2RtbJE5zFuTXOaOAsfq6l1pboH
         9MlQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Xa5y6uuL;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=aWYkL+Onc4y9cpwpxngo2FGYc6bd3FiFEhEsI/RvYKY=;
        b=EPMyuNPy/jrZWH1iYL7lOUodhaFlaA1hMzHLs+tbb0lmonrsmkC5D+/WUV813PJAcY
         bmm2WFOaHzpvbW9LWQNA+10EnyIv0D/D9+O4VvlqogiIUxVeT7Wii9HGF7DIqb+1i0SR
         czzzWLwgSrCwBEiB+v6OBpjYu2EeEizhG77/ZjxE9RsEZFGF83PbVqWzgMASJIqhscQk
         OLQm7CoynJYMGRmhdUr0X2yxByNAOD7sidRgse74hkEqNNBy10cO5l2t1x6+eE0FbuPr
         uLoFIxfVAlmmfIWt2kYPt/FhMQDaLb7yzO3212KVOQI6pMRLYAkcC4ZkS3DlIXsTgSUG
         t0Dw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=aWYkL+Onc4y9cpwpxngo2FGYc6bd3FiFEhEsI/RvYKY=;
        b=4vU5X8u/N6yX/6mSGhunUldPezlPZYuYbR/1c9oLoNswQZmXISegCQHAmcFk0DXCC8
         tOzb/2+3gC8rv588gqQMLikRyvKRaoK9qzyPwpiPYrwBZ7AbjluCux7KY6iMOW1nLbmv
         58yQl3PzWUFx1Bi115TRtSbX1tthP0lx57+mVw5ltiyeRCfRo9L2VfU/tx/c6BhCZ7Y1
         2m+OVXRU6ojz4koknvufbm3UhAeKAH0quOF2oFN5H7QMlG9RW2ijnQV6V45F42952JLN
         1fsKO6UcVfsb+n4aphX7xTOHEohks2K5A6qvmHhOq9Ni2s9Yov6f8Hm7Hc628KrQA48t
         OiWg==
X-Gm-Message-State: AOAM532pNmNY8lD1MmR8oeuyiza/1yez8vXmJKk5EqMWV9YK4lMCOHph
	1pb4F2TK2xkiw3ziK/APhYw=
X-Google-Smtp-Source: ABdhPJy0n9VmdPBcgv+YPpJIGpu0sOY57mcjzlO/vxwD3Jl3x34YJgfCpz9n/QlwFYqt7ibv2ik89g==
X-Received: by 2002:ac2:5301:0:b0:477:a96f:6221 with SMTP id c1-20020ac25301000000b00477a96f6221mr48719000lfh.449.1654086537113;
        Wed, 01 Jun 2022 05:28:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:10cb:b0:478:7256:822a with SMTP id
 k11-20020a05651210cb00b004787256822als1676215lfg.3.gmail; Wed, 01 Jun 2022
 05:28:55 -0700 (PDT)
X-Received: by 2002:a05:6512:2348:b0:478:5ad6:af37 with SMTP id p8-20020a056512234800b004785ad6af37mr41350864lfu.26.1654086535599;
        Wed, 01 Jun 2022 05:28:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654086535; cv=none;
        d=google.com; s=arc-20160816;
        b=Jsp0pYXja1uBC9Q/ZJoybSV0nsih+sl0F+s2CSHXOMmf519mQDB3EF7ibipSRZKcWT
         a6Lc2u3nRZsGRnT2bg9YYH3M582QX0btaUD6F5ZxKF8vK3TVdVHgqFW7/jO7ST88p75V
         tVQm98ZtK4X4ADD/Qy5v0Zz/BwGRDB888L1T5cnXUMDRfgU6ARp3sAH9MX0EBQwokfFm
         6QKsS4Q+NStVXI5UnCmUR8lDms/A8ooz8xT7cKgIwGDVq0qeE9eHc5lwDbphpadNoKXY
         8le0b/udvWapKi7DdoSb9hIi/q5P7D8hSuMH9V5wzZRp4YFPkYiIaNXgWNxOuPHQ7jTg
         3F1w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=IelEAvxuftzpFUTjVmjDc8U27FXmxMCPT7XI/4vcyT8=;
        b=eximDevV74tYcnTWOAao4j46pbtOjED7fIeOgLqQ3R7JtVTOH24DwKZ212iAqNSvTj
         OjZdjYOCE8njraDbr/NzKii9RbiD8OLM0iTzeHfTC/xiySK6xyh6bBdYBq/kf9hJrqIs
         QYrvEs9jWjd5NEzYr1muWzslqCivy8EK5GbQBNzJFAhGsb7JjupwEhM95q0jXfa10e0s
         ger6+R/EqyyuW2ELtw74zDnwKRt48NsKoxUU1cOUgIHtcqQvS+Vgr8r/t15ckBPW6cge
         /8sgJlRFHFrigGaGDMK/fxYjZ5STeOXvNLR/CyS7OMsRXNe2tEAPOAhbwV/PAJuybRdB
         SZaA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=Xa5y6uuL;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id g1-20020a0565123b8100b00472523f3a8esi79614lfv.6.2022.06.01.05.28.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Jun 2022 05:28:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id q21so2154876wra.2
        for <kasan-dev@googlegroups.com>; Wed, 01 Jun 2022 05:28:55 -0700 (PDT)
X-Received: by 2002:a05:6000:16cb:b0:20e:63aa:7a31 with SMTP id h11-20020a05600016cb00b0020e63aa7a31mr54674152wrf.253.1654086534694;
        Wed, 01 Jun 2022 05:28:54 -0700 (PDT)
Received: from elver.google.com ([2a00:79e0:9c:201:ed43:9390:62cb:50ee])
        by smtp.gmail.com with ESMTPSA id l10-20020a5d410a000000b0020fc6590a12sm1447145wrp.41.2022.06.01.05.28.53
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 01 Jun 2022 05:28:54 -0700 (PDT)
Date: Wed, 1 Jun 2022 14:28:48 +0200
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: andrey.konovalov@linux.dev
Cc: Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: Re: [PATCH 3/3] kasan: fix zeroing vmalloc memory with HW_TAGS
Message-ID: <YpdbgGjjz954Us/y@elver.google.com>
References: <4c76a95aff79723de76df146a10888a5a9196faf.1654011120.git.andreyknvl@google.com>
 <bbc30451228f670abeaf1b8aad678b9f6dda4ad3.1654011120.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <bbc30451228f670abeaf1b8aad678b9f6dda4ad3.1654011120.git.andreyknvl@google.com>
User-Agent: Mutt/2.1.4 (2021-12-11)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=Xa5y6uuL;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::42d as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Tue, May 31, 2022 at 05:43PM +0200, andrey.konovalov@linux.dev wrote:
> From: Andrey Konovalov <andreyknvl@google.com>
> 
> HW_TAGS KASAN skips zeroing page_alloc allocations backing vmalloc
> mappings via __GFP_SKIP_ZERO. Instead, these pages are zeroed via
> kasan_unpoison_vmalloc() by passing the KASAN_VMALLOC_INIT flag.
> 
> The problem is that __kasan_unpoison_vmalloc() does not zero pages
> when either kasan_vmalloc_enabled() or is_vmalloc_or_module_addr() fail.
> 
> Thus:
> 
> 1. Change __vmalloc_node_range() to only set KASAN_VMALLOC_INIT when
>    __GFP_SKIP_ZERO is set.
> 
> 2. Change __kasan_unpoison_vmalloc() to always zero pages when the
>    KASAN_VMALLOC_INIT flag is set.
> 
> 3. Add WARN_ON() asserts to check that KASAN_VMALLOC_INIT cannot be set
>    in other early return paths of __kasan_unpoison_vmalloc().
> 
> Also clean up the comment in __kasan_unpoison_vmalloc.
> 
> Fixes: 23689e91fb22 ("kasan, vmalloc: add vmalloc tagging for HW_TAGS")
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> ---
>  mm/kasan/hw_tags.c | 30 ++++++++++++++++++++++--------
>  mm/vmalloc.c       | 10 +++++-----
>  2 files changed, 27 insertions(+), 13 deletions(-)
> 
> diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
> index 9e1b6544bfa8..c0ec01eadf20 100644
> --- a/mm/kasan/hw_tags.c
> +++ b/mm/kasan/hw_tags.c
> @@ -263,21 +263,31 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
>  	u8 tag;
>  	unsigned long redzone_start, redzone_size;
>  
> -	if (!kasan_vmalloc_enabled())
> -		return (void *)start;
> +	if (!kasan_vmalloc_enabled() || !is_vmalloc_or_module_addr(start)) {
> +		struct page *page;
> +		const void *addr;
> +
> +		/* Initialize memory if required. */
> +

This whole block of code looks out-of-place in this function, since it's
not at all related to unpoisoning but a fallback if KASAN-vmalloc is off
but we still want to initialize the memory.

Maybe to ease readability here I'd change it to look like:


diff --git a/mm/kasan/hw_tags.c b/mm/kasan/hw_tags.c
index 11f661a2494b..227c20d09258 100644
--- a/mm/kasan/hw_tags.c
+++ b/mm/kasan/hw_tags.c
@@ -257,6 +257,21 @@ static void unpoison_vmalloc_pages(const void *addr, u8 tag)
 	}
 }
 
+/*
+ * Explicit initialization of pages if KASAN does not handle VM_ALLOC
+ * allocations.
+ */
+static void init_vmalloc_pages_explicit(const void *start, unsigned long size)
+{
+	const void *addr;
+
+	for (addr = start; addr < start + size; addr += PAGE_SIZE) {
+		struct page *page = virt_to_page(addr);
+
+		clear_highpage_kasan_tagged(page);
+	}
+}
+
 void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 				kasan_vmalloc_flags_t flags)
 {
@@ -264,19 +279,8 @@ void *__kasan_unpoison_vmalloc(const void *start, unsigned long size,
 	unsigned long redzone_start, redzone_size;
 
 	if (!kasan_vmalloc_enabled() || !is_vmalloc_or_module_addr(start)) {
-		struct page *page;
-		const void *addr;
-
-		/* Initialize memory if required. */
-
-		if (!(flags & KASAN_VMALLOC_INIT))
-			return (void *)start;
-
-		for (addr = start; addr < start + size; addr += PAGE_SIZE) {
-			page = virt_to_page(addr);
-			clear_highpage_kasan_tagged(page);
-		}
-
+		if (flags & KASAN_VMALLOC_INIT)
+			init_vmalloc_pages_explicit(start, size);
 		return (void *)start;
 	}
 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YpdbgGjjz954Us/y%40elver.google.com.
