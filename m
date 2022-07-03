Return-Path: <kasan-dev+bncBCT4XGV33UIBBK6GRCLAMGQEIWSQ55Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43b.google.com (mail-pf1-x43b.google.com [IPv6:2607:f8b0:4864:20::43b])
	by mail.lfdr.de (Postfix) with ESMTPS id 78356564A7E
	for <lists+kasan-dev@lfdr.de>; Mon,  4 Jul 2022 01:15:58 +0200 (CEST)
Received: by mail-pf1-x43b.google.com with SMTP id y21-20020aa78555000000b00528641ccfc1sf106842pfn.13
        for <lists+kasan-dev@lfdr.de>; Sun, 03 Jul 2022 16:15:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1656890155; cv=pass;
        d=google.com; s=arc-20160816;
        b=nZ6A790CcWeobJo+De/DXAIIUAh4Si5XRlInlYSCa45DxLRL5J0yZ4EpbPPakS5Ij/
         2ZUWvoaxDXIN42FgZOuayvWUm98lbt/7Vyy8qbJRGEJEC9EwnAB40uo68ORc/Du+NUaS
         JIhCHNxf2+BevTXZypjKYzCJyy3FfuGU2q2BfYcurdPXKiOsb2SeGypOeN0xpWmw2Hyl
         ntaCpAgjGRTRSRX6WkNNpA5qSX1m76uBPrg9FPQGaSVuyrZq7Ip8m+uIO5Nnbh+wtW4r
         yi3qRDVg/OglkxXmzEj3jq1hD9BeqN3lVK5/BupVUTwQ858v0grBn08HZy/y1aDAZLT/
         ndog==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=M9TEOQJS0+A12WB8oW4R4+OhBvzjenco8ivCwZQlLPo=;
        b=bq9MZe9CuvoENd1gn/S7QV7yMcywoGqFQMZzuUBNoLQQuIG9BXZJtV4d4v6fmkdbNm
         96Uz+/lI1jpsncZv+VPnhMU4LAj93VNwMYxnNGe+nvnuAnVMiOM0BHaNZoB/ZsvBWb9A
         tfY/MJ+QriX4mJkTFTAAhjPpuTr1BBuTIlcExU2ypUCB8YaihXGzQ/Z73L+wbpHMqbHF
         99/XBwR5Ep1A1bqbEju9El/EsPB2uazupaR8Okr9XmziLIDRVk1w2G5qICBvfo6dpOYF
         8BMENrj05SoDWN560r5UWhgvRl76anEvW/GSEtbrARmTZJR1zP11mwXPmUwUQ+X/EpXZ
         SsFg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=I9H7MVvw;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M9TEOQJS0+A12WB8oW4R4+OhBvzjenco8ivCwZQlLPo=;
        b=aZgG8NcaUGJMtp4yJirFhptNsdAuxN5e/Xb7+eZGCCPLHk9j2wfc58qtgl1L8X6heT
         gHJ0iYUQCQmIH6flHWYfyOTXoYPOKhJYmQzBaLufmCF8W2DRI1hkk1KZYE7tmMZGH0pB
         EQDXyHDI3aI6iMt17yfQwIqDuRgCTPVOvy1uLiNtkZYPw4NRleMLVYc1/x/1k8v3mGhM
         MdunFcaln8zbl9kUMkbwpstauw7Rxa2wEuPUx4lETkwlRUlzeyIEXQvTe28aU1nxKRl3
         5AQSPA5ojtFwyWgDNbcPj9whL/0j6JbdLxf6mywgDrCtsyXUDCvLiSMcRNswvRejCsKw
         4oPw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=M9TEOQJS0+A12WB8oW4R4+OhBvzjenco8ivCwZQlLPo=;
        b=33zt6Rj0G50gtNUZbZcYGzQWWuKHQPmq5A6HV47Z+AD26GgMhODHi4YF3kyPOH932K
         OT8/MWqg5WdV5pBDAouIO1XGP8XU+a9ie4uky9NMFWemp6pllAncyuSp7gQg8dqoEeD3
         ZA4YoGKk/pv6YMNzuNSjxEDHFXF7lPGLfvwstff381qK7ZVu/pUbymwP6u6uAwKR3Y0n
         8jfnHe/rA/Y27k1D8Grzvxf8Ocv/Lw2ZFjkqeR/diUI8F3X095xymYJsBzw8a5c0i625
         dSPEfVOIgC01afhr/SKKmuZzMTN0wC0uSipv6On0BZSpB5Lnwk1WD4BqUdJi8sHehCDH
         xIhg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AJIora9HdFs1kmCb2a5NeeSEWKPOgZg9CYJyVO4976lIgZWZye4Jpl9K
	ecHKYGBGaIudF+7gZ9IEf/g=
X-Google-Smtp-Source: AGRyM1sOSLSt3KkyIQXGMM8N2gYK7A9aDAy7TXfdzFoysmBJYSitjBe7VNIlIV2MFAhSxvOY1ybuTQ==
X-Received: by 2002:a17:90a:f2d7:b0:1ef:8859:d61 with SMTP id gt23-20020a17090af2d700b001ef88590d61mr2281984pjb.215.1656890155312;
        Sun, 03 Jul 2022 16:15:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1955:b0:525:440c:2d91 with SMTP id
 s21-20020a056a00195500b00525440c2d91ls14203128pfk.11.gmail; Sun, 03 Jul 2022
 16:15:54 -0700 (PDT)
X-Received: by 2002:a63:2a8f:0:b0:412:5278:b90 with SMTP id q137-20020a632a8f000000b0041252780b90mr349737pgq.363.1656890154506;
        Sun, 03 Jul 2022 16:15:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1656890154; cv=none;
        d=google.com; s=arc-20160816;
        b=vgK/2BUGk27mL+/1WbyOMrscYVxQ8LQG9qwWBVMFWIlGA4h7LXAlh0SCfzSj2SRskQ
         3QIRGe4gHJ9BtKCr92DiclogHhnvPbNyIoY+0dM3dh5GWk9k21Ula/D9YL6ckeU8pi8r
         TLBWmNUmfeqwPHWtF1/cjjlV1U2MRQcrRZG85hLoBfm2e4Xpk7CDpWECijaNSMKzDtYY
         ef1SoJyHOCT6BwCF5hcH/mJgYVc4ZR9NIZHzi3J2cPspXJv7YteaDYRiN7FfsiQNicTk
         DU+NwcfgI9qlR3Plez/FK08OAI7bTQQ385BTyoaR/8YiDgIBxK116IX6QXvwrSfYCl3Y
         sopw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=4eyxsET1uUtYDmBiIGGjIUzqUUGx8+bu39Q63tWlZoY=;
        b=SUtIIGA86ePkOJEM0amD/eZCnbWJo+IYtJ9ouym8xdDHBOfDut8OFUw3/qbk08PnVJ
         mWzdHKGbFmEAs/GdiVsDUGxWaIPoxAbZ2hkFTQALG0vskmfJtVTNo25i7AKQR+t014yi
         MndAp6Eg8j1vLd2EL3FUHpHGBs4TONmVNZzobABrWpamg0TRlk4iNy8uFmsYgtUrc9W2
         p0Lb31H8zpMEIHZN2oPTyMEZk93CUNLiwXydbS05A+b0vuzoMzfuY3GrzWHwBvsqAqXO
         0vP5r/vJ2wkssd6g54wXFp2zHZvHEdVYjqBISUH4h1pTd/1jGo9TpDlcPzKNx/57BxxE
         d73w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=I9H7MVvw;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id jd12-20020a170903260c00b0016a1d4b22cdsi994427plb.0.2022.07.03.16.15.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Sun, 03 Jul 2022 16:15:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id D66A16122A;
	Sun,  3 Jul 2022 23:15:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id B8E80C341C6;
	Sun,  3 Jul 2022 23:15:52 +0000 (UTC)
Date: Sun, 3 Jul 2022 16:15:52 -0700
From: Andrew Morton <akpm@linux-foundation.org>
To: Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko
 <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov
 <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>,
 Matthias Brugger <matthias.bgg@gmail.com>, <chinwen.chang@mediatek.com>,
 <yee.lee@mediatek.com>, <casper.li@mediatek.com>,
 <andrew.yang@mediatek.com>, <kasan-dev@googlegroups.com>,
 <linux-mm@kvack.org>, <linux-kernel@vger.kernel.org>,
 <linux-arm-kernel@lists.infradead.org>,
 <linux-mediatek@lists.infradead.org>
Subject: Re: [PATCH] kasan: separate double free case from invalid free
Message-Id: <20220703161552.6a3304c8d316e4fdcce42caa@linux-foundation.org>
In-Reply-To: <20220615062219.22618-1-Kuan-Ying.Lee@mediatek.com>
References: <20220615062219.22618-1-Kuan-Ying.Lee@mediatek.com>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-redhat-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=I9H7MVvw;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 15 Jun 2022 14:22:18 +0800 Kuan-Ying Lee <Kuan-Ying.Lee@mediatek.com> wrote:

> Currently, KASAN describes all invalid-free/double-free bugs as
> "double-free or invalid-free". This is ambiguous.
> 
> KASAN should report "double-free" when a double-free is a more
> likely cause (the address points to the start of an object) and
> report "invalid-free" otherwise [1].
> 
> [1] https://bugzilla.kernel.org/show_bug.cgi?id=212193
> 
> ...

Could we please have some review of this?

Thanks.

> 
> diff --git a/mm/kasan/common.c b/mm/kasan/common.c
> index c40c0e7b3b5f..707c3a527fcb 100644
> --- a/mm/kasan/common.c
> +++ b/mm/kasan/common.c
> @@ -343,7 +343,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>  
>  	if (unlikely(nearest_obj(cache, virt_to_slab(object), object) !=
>  	    object)) {
> -		kasan_report_invalid_free(tagged_object, ip);
> +		kasan_report_invalid_free(tagged_object, ip, KASAN_REPORT_INVALID_FREE);
>  		return true;
>  	}
>  
> @@ -352,7 +352,7 @@ static inline bool ____kasan_slab_free(struct kmem_cache *cache, void *object,
>  		return false;
>  
>  	if (!kasan_byte_accessible(tagged_object)) {
> -		kasan_report_invalid_free(tagged_object, ip);
> +		kasan_report_invalid_free(tagged_object, ip, KASAN_REPORT_DOUBLE_FREE);
>  		return true;
>  	}
>  
> @@ -377,12 +377,12 @@ bool __kasan_slab_free(struct kmem_cache *cache, void *object,
>  static inline bool ____kasan_kfree_large(void *ptr, unsigned long ip)
>  {
>  	if (ptr != page_address(virt_to_head_page(ptr))) {
> -		kasan_report_invalid_free(ptr, ip);
> +		kasan_report_invalid_free(ptr, ip, KASAN_REPORT_INVALID_FREE);
>  		return true;
>  	}
>  
>  	if (!kasan_byte_accessible(ptr)) {
> -		kasan_report_invalid_free(ptr, ip);
> +		kasan_report_invalid_free(ptr, ip, KASAN_REPORT_DOUBLE_FREE);
>  		return true;
>  	}
>  
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index 610d60d6e5b8..01c03e45acd4 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -125,6 +125,7 @@ static inline bool kasan_sync_fault_possible(void)
>  enum kasan_report_type {
>  	KASAN_REPORT_ACCESS,
>  	KASAN_REPORT_INVALID_FREE,
> +	KASAN_REPORT_DOUBLE_FREE,
>  };
>  
>  struct kasan_report_info {
> @@ -277,7 +278,7 @@ static inline void kasan_print_address_stack_frame(const void *addr) { }
>  
>  bool kasan_report(unsigned long addr, size_t size,
>  		bool is_write, unsigned long ip);
> -void kasan_report_invalid_free(void *object, unsigned long ip);
> +void kasan_report_invalid_free(void *object, unsigned long ip, enum kasan_report_type type);
>  
>  struct page *kasan_addr_to_page(const void *addr);
>  struct slab *kasan_addr_to_slab(const void *addr);
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index b341a191651d..fe3f606b3a98 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -176,8 +176,12 @@ static void end_report(unsigned long *flags, void *addr)
>  static void print_error_description(struct kasan_report_info *info)
>  {
>  	if (info->type == KASAN_REPORT_INVALID_FREE) {
> -		pr_err("BUG: KASAN: double-free or invalid-free in %pS\n",
> -		       (void *)info->ip);
> +		pr_err("BUG: KASAN: invalid-free in %pS\n", (void *)info->ip);
> +		return;
> +	}
> +
> +	if (info->type == KASAN_REPORT_DOUBLE_FREE) {
> +		pr_err("BUG: KASAN: double-free in %pS\n", (void *)info->ip);
>  		return;
>  	}
>  
> @@ -433,7 +437,7 @@ static void print_report(struct kasan_report_info *info)
>  	}
>  }
>  
> -void kasan_report_invalid_free(void *ptr, unsigned long ip)
> +void kasan_report_invalid_free(void *ptr, unsigned long ip, enum kasan_report_type type)
>  {
>  	unsigned long flags;
>  	struct kasan_report_info info;
> @@ -448,7 +452,7 @@ void kasan_report_invalid_free(void *ptr, unsigned long ip)
>  
>  	start_report(&flags, true);
>  
> -	info.type = KASAN_REPORT_INVALID_FREE;
> +	info.type = type;
>  	info.access_addr = ptr;
>  	info.first_bad_addr = kasan_reset_tag(ptr);
>  	info.access_size = 0;
> -- 
> 2.18.0
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220703161552.6a3304c8d316e4fdcce42caa%40linux-foundation.org.
