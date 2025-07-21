Return-Path: <kasan-dev+bncBCSL7B6LWYHBBBEN7PBQMGQEZO43S2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id E6B35B0CD6E
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Jul 2025 01:00:23 +0200 (CEST)
Received: by mail-wr1-x43c.google.com with SMTP id ffacd0b85a97d-3a6d1394b07sf3152542f8f.3
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Jul 2025 16:00:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753138821; cv=pass;
        d=google.com; s=arc-20240605;
        b=Zl81P88NzCPRt9OSrJ0M4jLn+MLkVDPoQaqMORBQD2ZsJWI6DW+HJSeWjCV8zangl1
         lb9iiJrYmcHG42gyRb+MoZTp+WdgUqAaT2RoXI4TScc+j8V/NI/A+dPzgnBlc0Ak+XI1
         floMAbiqQ49Sy1UW19/sB6otuLE4NcW6vMgQq55HXLGWqe9ypVgoW/ldJOJS1GHZQzCq
         ThSdXH5FuWXXYCjL5gTtoXM9DhVqIyQ0t5Yx1x9+UVNvXd1WhTAMys78WD/ErSH9gWj3
         sG8wIfX7AcuoLBB9eGnIzhvYe0tdy3w6vwjWsI+ldf8pL9ApuWOBFbyDypZRpiMiOunH
         1fJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature:dkim-signature;
        bh=YFEKvTN8BKtOrTDdtjpWvrPEuCgopsxyKPr/hU93Sts=;
        fh=4NAiqOt1dFbusURMNzvK7lxH203K2vpUnYxAlt1BvzA=;
        b=RCB78GS7xMWQ3vBzfSeLzdd1My5xw+bCTl+AuSCBMCjnd0RWWtfxGOUcKJwapcaCYS
         Dip352f4UG787g5d/sWEKgouwD9JrASrGNwoGi2pWmxhnXMAi7lVbOh/l1/Xtwc/ENh1
         rPWRDLxMwyqIxiaSiqkFoW57PnqDFjoP/f3yqX798axu3e211KN3HVawxOf6fU6MXH+o
         zf/ZQleh8Yief6ggu5/BA3XcKpa24A58AcfDx6cqvmQnm8z4cCC6+uq/IGcb88XL3x+g
         NyLLmyGThXPkw1MgOuCSh+f7o9y6d36t8o0p7AuWhei92umCwfd32huvtOBO7ckKaeXE
         4iWw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UIH8ANfS;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753138821; x=1753743621; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=YFEKvTN8BKtOrTDdtjpWvrPEuCgopsxyKPr/hU93Sts=;
        b=rNYOxfvM3LkowvHfnTUXXh7g7vjS2XxFR4s3B0L5fs1VFKmekzqleqWxAh2x/VsfOF
         Cetu6VeWBDDlmjJvSp+425l6zq6qbk4xWvyHPhZ09seWxi6mIZLdEAxduFhv5Gl5iSVr
         xwTbOisrURzmSPXCrLFsByts/cbmFdqoXmrV8TiVSAPlWtKizfWJxIz1XHehidHdsr9d
         RiDsBdBC8ox6Kp1pWKp/dUCVrvmlV67h9ZR+kUol2Jp0KNaVO1QFhlVFdd7e7DYYFj4K
         sP0ML8PKQ5WOlwQjZGsXZ9lx9w69Ceom/7qbCPfkVm4bet6dDrO/OJuSvMl5k6uuBjcH
         /2+g==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1753138821; x=1753743621; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:from:to:cc
         :subject:date:message-id:reply-to;
        bh=YFEKvTN8BKtOrTDdtjpWvrPEuCgopsxyKPr/hU93Sts=;
        b=LEd+biGXtg+AyyrDZfo2U59BiNjA+OlIOmbuHSw4bRS65eK3E+4sBzvAdz7PaYbMr9
         ET9jilsJfo/yawhDOHe2NcVmF2yTYeI2kGQWm1bP/dUMAxkGvlbijtO9Gqy9/29HfwhG
         HIb/C583fKsh66cN6wbM68UTlzKiVGC16Xe2LzSUK3KoKsS0XpWW7ZxngMJJVtxHqJ0F
         8JmtGoV5vGPO3qeijinJrGGBKSKBxOxCr08GQlhGRZLPpmUBEbrocYbcG/9hXLu7OCLS
         Y0AVBgjJlHneM9tGG8zMuAJSz9YTtzTUixrwfCGCSekTRa/rlWKU9CEqrHM0+/YgmtiD
         ryqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753138821; x=1753743621;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=YFEKvTN8BKtOrTDdtjpWvrPEuCgopsxyKPr/hU93Sts=;
        b=e1SREOdVkP22k/VdXiqhJiCL/AD9DXrF+FzU3GP6V4li2LIEq5YOc18+kMqyg4VuFP
         DPArgF4w90ZUB/SXSr3UOZwYcrPsDrZadf1wGlk/2n7YWcJYHBAnZAuJI4l/olDb20pT
         u3zXZoz1pYpNSl5FbjkqYgc2ULcC9yijLR0jrcY4dwMQMLlsB1RtNwZxByPq8LmZubaW
         ipNCrAp/NNdve0No4YeeOFWqb9c6bjHQELc/7PnTwv7s+3/QmovGA6yE5UJZsxLJGDjx
         fY1Pawxjf2zIY8ITv1647bNe/ZDz3QPmEzsZ1QAFrSdZkpcdz0Fisr/ZV9JGtkL7fwVU
         C4GA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWzz3LfRjCENkRXyJloaaD/FbEflMHnF5k5b8jWyS8uIbi7TCvFS1J1VGBX+mUzEoYrCnxS1g==@lfdr.de
X-Gm-Message-State: AOJu0YzZW25TGTsRqnRDJefwcXgHpB6QovPbEjMCupkaoyHW0h09Rc2p
	tqRtucX/cNkg/YqaF3t+KJ0O2SAy4sAFLBZvoLHOFtgqVoipTyyLvklS
X-Google-Smtp-Source: AGHT+IHFuO1lXqwi+Am0oA9GjdcbR8Mj4CEodczVBUAn3+IYClQ/LFsGA+WUng8O+yM7o3TvjMribA==
X-Received: by 2002:a05:6000:280c:b0:3b6:11c:78df with SMTP id ffacd0b85a97d-3b60dd7b0e6mr11330920f8f.41.1753138821395;
        Mon, 21 Jul 2025 16:00:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdv41wMxHsfML9ij3ALiglljKAMRWSyBZc7ab6R4re9Vw==
Received: by 2002:a5d:5f47:0:b0:3a4:bfde:c058 with SMTP id ffacd0b85a97d-3b6137a20a7ls2564092f8f.2.-pod-prod-02-eu;
 Mon, 21 Jul 2025 16:00:18 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWnK5BHawnFxVdRTuvW6ZGm5kh+/4oNRhJB4KHPsF42GnPVmW6Mt8FQC3/mzo3/l4hCRZEJdHHZZx8=@googlegroups.com
X-Received: by 2002:a5d:64c5:0:b0:3b7:61e5:a8a5 with SMTP id ffacd0b85a97d-3b761e5a9b5mr2316456f8f.47.1753138818160;
        Mon, 21 Jul 2025 16:00:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753138818; cv=none;
        d=google.com; s=arc-20240605;
        b=jQnZNk8MKL8AYMrtiLCDQ4wOblJZfeaJB+o1/OdE93WHmK4jMIH3mHh5Dv5mSOWToQ
         uqAI5oZ1KMpntmGXBDqi4u1rQbXkoi6S/PS1boP4pWYKkAttXUeHT2V9GuaOsZTSQlXy
         EyKj4m0rRovsPIQxHn/sWXumayPyzXXzTMyD8Duv6iWDs28Zvo0MrIXG3FG6f7uWtEPe
         xZinTt/TPuM+yJDkxdeaim7EaA6AXxRnZNaN8dKg/Ce6imtOOYQdxTOVSzVC5GtmmlET
         Cdn+1dUJ4obfa32OibFEAkK9oNk6GTuxQ0ur/u+/UH+pLT/fRqqnIZmg0JXmUcMbJ44l
         xaCw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=qL9A0aUIl8Uddr//bj642F7utZi72l2outni4topsME=;
        fh=PrX5lOTXW49GyjGuZSSKhOwnL8mORSRapUCD1JTP9Sk=;
        b=YhdokzM79tnZfX6o/WAmqcDyGa3DklmSCN6B1ncJd8FNWlWqD4LHVD4iNltOsBQiJ/
         W6l1b3eKh3icF39LenNz8DzrdCQ3FTLocvvXK5nl60+CTBUz5YXGU+cW/WHK75jtJ9lP
         MtkWhUDNdlZbIMAg3E5sroCFckB7etm8muzwgHzSjK0QOrJ5U3YPHHyyrQnD4Os60mhz
         WGVrB9BLE9Kt6ynXB6tLy24kmvEi+8HT+zmYA/O7a7Ma0qk4DD5CA6SyZU3CLpRk0B4t
         ztZAY/OgGTLb4R1gEB1gJ1iRnV41RYGRfYz7KWCqwHtj1Ue72y7aQW5z3PY+hgIs6bWu
         s2YQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=UIH8ANfS;
       spf=pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::535 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ed1-x535.google.com (mail-ed1-x535.google.com. [2a00:1450:4864:20::535])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-4562e829bb2si2900025e9.2.2025.07.21.16.00.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Jul 2025 16:00:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::535 as permitted sender) client-ip=2a00:1450:4864:20::535;
Received: by mail-ed1-x535.google.com with SMTP id 4fb4d7f45d1cf-60fdd24613fso982444a12.1
        for <kasan-dev@googlegroups.com>; Mon, 21 Jul 2025 16:00:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWiStajvgmckAM12L4S28nRyFQuHEn7ILrzAO3jpsuGa5L7GytjL+/+U9exemEVtl4ZURtL+A3OIOg=@googlegroups.com
X-Gm-Gg: ASbGncs3hWROzHYYuPuixn6eB2aEJICuY2BSbTtTPPhfs+5yNbgANnMQtT+XtsSQmO1
	O7rI75YQmMospZ2loC/IUNQGtozxudMzFQZnHZ84q+6azliTFwPYnfF7Eubzb6H3wHkekxyG6gO
	yd7ySwCOyzvi7M6Xwz63O8zieeV0Kiu6TxRMAXmsdZXnofnpkXF0hAMIUqZfBVb7sBIjElY9fL1
	GN5Z5lubPKoHQw1TWe+0XCFWhVhKwUTBEjaRT3piHU7U9e36+JlNRg4h3bfYmaJXi8yI21ri4pZ
	CjHD+4mOOqR+HOSQHF5sgBpCsRWf3b1iSbaFHxxMNYIJ6s/QUdRagSeGYwGtVaifA7gbB2ffHgq
	D4yQMWADGTV596/FkFkbv1jpZXpj6E3BY/L1SVz5BuOBBLUcH6cDe3Ajed9abnAyIF0b0
X-Received: by 2002:a17:907:7fa1:b0:ae6:c555:8dbb with SMTP id a640c23a62f3a-ae9c9af98e3mr887526166b.11.1753138817353;
        Mon, 21 Jul 2025 16:00:17 -0700 (PDT)
Received: from [192.168.0.18] (cable-94-189-142-142.dynamic.sbb.rs. [94.189.142.142])
        by smtp.gmail.com with ESMTPSA id a640c23a62f3a-aec6c7d8357sm753164466b.52.2025.07.21.16.00.16
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Jul 2025 16:00:16 -0700 (PDT)
Message-ID: <c8b0be89-6c89-46ed-87c3-8905b6ccbbeb@gmail.com>
Date: Tue, 22 Jul 2025 00:59:56 +0200
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v3 07/12] kasan/loongarch: select ARCH_DEFER_KASAN and
 call kasan_init_generic
To: Sabyrzhan Tasbolatov <snovitoll@gmail.com>, hca@linux.ibm.com,
 christophe.leroy@csgroup.eu, andreyknvl@gmail.com, agordeev@linux.ibm.com,
 akpm@linux-foundation.org
Cc: glider@google.com, dvyukov@google.com, kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org, loongarch@lists.linux.dev,
 linuxppc-dev@lists.ozlabs.org, linux-riscv@lists.infradead.org,
 linux-s390@vger.kernel.org, linux-um@lists.infradead.org, linux-mm@kvack.org
References: <20250717142732.292822-1-snovitoll@gmail.com>
 <20250717142732.292822-8-snovitoll@gmail.com>
Content-Language: en-US
From: Andrey Ryabinin <ryabinin.a.a@gmail.com>
In-Reply-To: <20250717142732.292822-8-snovitoll@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: Ryabinin.A.A@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=UIH8ANfS;       spf=pass
 (google.com: domain of ryabinin.a.a@gmail.com designates 2a00:1450:4864:20::535
 as permitted sender) smtp.mailfrom=ryabinin.a.a@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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



On 7/17/25 4:27 PM, Sabyrzhan Tasbolatov wrote:

> diff --git a/arch/loongarch/include/asm/kasan.h b/arch/loongarch/include/asm/kasan.h
> index 62f139a9c87..0e50e5b5e05 100644
> --- a/arch/loongarch/include/asm/kasan.h
> +++ b/arch/loongarch/include/asm/kasan.h
> @@ -66,7 +66,6 @@
>  #define XKPRANGE_WC_SHADOW_OFFSET	(KASAN_SHADOW_START + XKPRANGE_WC_KASAN_OFFSET)
>  #define XKVRANGE_VC_SHADOW_OFFSET	(KASAN_SHADOW_START + XKVRANGE_VC_KASAN_OFFSET)
>  
> -extern bool kasan_early_stage;
>  extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
>  
>  #define kasan_mem_to_shadow kasan_mem_to_shadow
> @@ -75,12 +74,6 @@ void *kasan_mem_to_shadow(const void *addr);
>  #define kasan_shadow_to_mem kasan_shadow_to_mem
>  const void *kasan_shadow_to_mem(const void *shadow_addr);
>  
> -#define kasan_arch_is_ready kasan_arch_is_ready
> -static __always_inline bool kasan_arch_is_ready(void)
> -{
> -	return !kasan_early_stage;
> -}
> -
>  #define addr_has_metadata addr_has_metadata
>  static __always_inline bool addr_has_metadata(const void *addr)
>  {
> diff --git a/arch/loongarch/mm/kasan_init.c b/arch/loongarch/mm/kasan_init.c
> index d2681272d8f..cf8315f9119 100644
> --- a/arch/loongarch/mm/kasan_init.c
> +++ b/arch/loongarch/mm/kasan_init.c
> @@ -40,11 +40,9 @@ static pgd_t kasan_pg_dir[PTRS_PER_PGD] __initdata __aligned(PAGE_SIZE);
>  #define __pte_none(early, pte) (early ? pte_none(pte) : \
>  ((pte_val(pte) & _PFN_MASK) == (unsigned long)__pa(kasan_early_shadow_page)))
>  
> -bool kasan_early_stage = true;
> -
>  void *kasan_mem_to_shadow(const void *addr)
>  {
> -	if (!kasan_arch_is_ready()) {
> +	if (!kasan_enabled()) {

This doesn't make sense, !kasan_enabled() is compile-time check which is always false here.

>  		return (void *)(kasan_early_shadow_page);
>  	} else {
>  		unsigned long maddr = (unsigned long)addr;

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/c8b0be89-6c89-46ed-87c3-8905b6ccbbeb%40gmail.com.
