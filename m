Return-Path: <kasan-dev+bncBDDL3KWR4EBRB7OC2OBAMGQECWIUJ4Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x438.google.com (mail-pf1-x438.google.com [IPv6:2607:f8b0:4864:20::438])
	by mail.lfdr.de (Postfix) with ESMTPS id 064C334237C
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Mar 2021 18:38:07 +0100 (CET)
Received: by mail-pf1-x438.google.com with SMTP id w187sf10952998pfd.11
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Mar 2021 10:38:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1616175485; cv=pass;
        d=google.com; s=arc-20160816;
        b=i38L1tRT5M0XkWxE0Aq3k4DjFpqEA8c7XlA8gWLTqBnRhTo2wg922xZD80MMObFQG1
         ooSPP+A0vd95WiLFq+OA4Tq5cCZHSf15DtCqZh4AD4hRPLZvOp9ZjrrP+lHLZHt8nOWT
         +GLRclpR5Qz9jLun85OLfXvJUJqzm0W6nO7qwWsHkIxp5xEv6dQj25JnzxrfSKStwwV4
         9Py+Lcl/0ViInLY8DfVFidbS5LpRQl+pnb/EUDUrekjOO0aUrlCKkb/r/KHo0a+8bNwL
         RSjbEvZM0PCmHzKfCL6J4/6xOVvSgoI77wWtHX67wY9SWm56OCb/ulhCHwpe4u8qwOxY
         XkCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=l2zItQis43xRJVga1u244qB2ZWLNm4zbulzRC6fBlpE=;
        b=Ogn3jkOzuZ0gz4zw7kOeArUuEECiGesQijB3cF7mirILOJSqMBHepgiT1Vh9yvVa5J
         SA1wv0YeDj8JMqMRfKfo0QWMTqKBw/XUVblkowQII07jhg0kdiCJJU7AFMCwQhTkqOa6
         EiW/hcwceG8f3mCaDpHV0rohtbH5KN1N5vGDPdQn6M4Nv6mQtaYqr2lQQHQqXUH7mkJp
         SNRohzLOxtvAU+ZRwc4FXprsGNSoCg+8ST6i/+6V9n+wYkyTk8/4Mh+G3Bptv9/krMny
         aZW/6yqwAB7PXIq8Zvvzeix2kC/0ZF/WkYOhsd/r7iZs9GH4vWh+RSR6YntFNMqewbCx
         inXw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=l2zItQis43xRJVga1u244qB2ZWLNm4zbulzRC6fBlpE=;
        b=BavuAlA3zMbyMSNgSka6mY1AigDKhUa/2kCxtVsdDZSi+Hkvtxl4M8sKXWE/lcRqaG
         hQunBN2C4k0wWIsGITPkqHJBeguficilg7kQvulRUaPBOPQ9nWrj8D86NDI35D6RKmyH
         vxtv2PmKiJ8LVzzNR59dne8V6Q+E765K+YUVMe3ahE39iNtDeFX787G3Yk8bxuZpVdxu
         No7fpFjdSmqPXRrJb4jliweibmLPqAVu39j/RkhIceGolXBrq3D/VyyRrIle+g1bg7Ge
         8YR4QJNlFr7OQLll1XjkizYl17HxSlCEi77qU272uno/2jtIRY+4X9JVOQvol0Cqt3uS
         tWDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=l2zItQis43xRJVga1u244qB2ZWLNm4zbulzRC6fBlpE=;
        b=GN+N+wrOjAaVjtuiW7hUeFy61AQRFZNqBtStT7q/Sr+Je+eGOXURfGBpFWTZt/DJgO
         M+TgXVL3kQYn6EYsS+h2f2UMXjEJVoKHPsoQjfY1o2GH0t8xbRDE7H58X/UHKefFk9A1
         wuKjuf2WuUXTBD9O2Qe41EPaBM3HdwgPxnqzfNbXYWj0lp5ikzvS2zKerfvySY1nzvDN
         1Y94L1d23tj5wFTLzjvXinr9GauqVrpe7arssXfTiO4zY0R3xGNSp+qDOYzvM8fUC3iN
         0uGhhlSltAuy2HzpAafAAKnvpPxFIqp7JGQjZ16y78CRDXwaCikSrf0KWozmYmyRXjnv
         HUVg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5302dbjFN6JedFlCmEy64pM0yXHFTQB8WcwlNocwtN4JN3fv+HDN
	fFutKjyQs4uT1YRCQ9ort6s=
X-Google-Smtp-Source: ABdhPJxdYH8ouuq6WpTiAtyTpFBLT8ybwv7KY8RLzQzgZQG2sRz3qc9qe8KKRmBs7VQEARaBnRUMog==
X-Received: by 2002:a17:902:d346:b029:e4:c35b:dc0a with SMTP id l6-20020a170902d346b02900e4c35bdc0amr15255985plk.75.1616175485715;
        Fri, 19 Mar 2021 10:38:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:2138:: with SMTP id n24ls2689920pfj.1.gmail; Fri,
 19 Mar 2021 10:38:05 -0700 (PDT)
X-Received: by 2002:a63:ea51:: with SMTP id l17mr12562572pgk.117.1616175485105;
        Fri, 19 Mar 2021 10:38:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1616175485; cv=none;
        d=google.com; s=arc-20160816;
        b=gM20zFLZVek2L7srs3aqAc0o0xoN+Ti4WHS4E0GrlJjHINWzqNHlvCPTmyKsN95EOG
         9k5/FE06N24tfPGTV0WAvUOCNrGPRaZVVTZJMZZB9lAgKZdeJH27hds7+7lFKWxxnXiY
         Osypj7aXPjuRhdb0AUZ7UIDz9Qfp9gKuQo1p/PA40FvSO6IJsYU4KMzgQ3eXgMSdQAhS
         dT+bZr4XCyCu4bSkqRX/lGEkXKOuzMm1FHLCN2ecMhglejJZM6q1vHZL0z6tU+AFirlC
         eNlFYt908VNnFEnwhTY9Vl63W3TWB6pGOO1s6SP3o7s2U6w1mkuGmKmTM0sfr45Uin22
         M97A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=Y91GaYKg1WLMk7X8cJq5Jtk6ml1e7DkT+lmmcj83mCI=;
        b=mJuhV0hxsQakrtPT6vVT+hkB1tKIzSblhQ4ElOn1AOn6DI18C8gxNs/9iiQoqt+0Mm
         FkW0rmZlxRzV/GUsZMo4LS0r0di5Gm0J6ClbbbcznIg+O2tFe/OybV4hkOlp5pkZRBzi
         lRoUEIuZW4gdqCBGZypnqAdiMATB09n+WDT9mTEsDog5jm38n45Ex7bxB7JlDuz9k9xv
         ypdDy+K/GBTC1y4JXgTyBLquo4If7wFaTyeCn28X/3/CjnG5KAY4WNlSAaSYdkwiNxvk
         4BAHrQZi1CrCPiNyxz/GhxEti3jC8ORWH6ZZarIxOhe6EtXaGc+M6JWDRFKlP4j/Ek2u
         Wt0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=cmarinas@kernel.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=arm.com
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 131si334095pfa.2.2021.03.19.10.38.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 19 Mar 2021 10:38:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPSA id 5557B6197A;
	Fri, 19 Mar 2021 17:38:01 +0000 (UTC)
Date: Fri, 19 Mar 2021 17:37:58 +0000
From: Catalin Marinas <catalin.marinas@arm.com>
To: Lecopzer Chen <lecopzer.chen@mediatek.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org,
	will@kernel.org, dan.j.williams@intel.com, aryabinin@virtuozzo.com,
	glider@google.com, dvyukov@google.com, akpm@linux-foundation.org,
	linux-mediatek@lists.infradead.org, yj.chiang@mediatek.com,
	ardb@kernel.org, andreyknvl@google.com, broonie@kernel.org,
	linux@roeck-us.net, rppt@kernel.org, tyhicks@linux.microsoft.com,
	robin.murphy@arm.com, vincenzo.frascino@arm.com,
	gustavoars@kernel.org, lecopzer@gmail.com
Subject: Re: [PATCH v3 1/5] arm64: kasan: don't populate vmalloc area for
 CONFIG_KASAN_VMALLOC
Message-ID: <20210319173758.GC6832@arm.com>
References: <20210206083552.24394-1-lecopzer.chen@mediatek.com>
 <20210206083552.24394-2-lecopzer.chen@mediatek.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20210206083552.24394-2-lecopzer.chen@mediatek.com>
User-Agent: Mutt/1.10.1 (2018-07-13)
X-Original-Sender: catalin.marinas@arm.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of cmarinas@kernel.org designates 198.145.29.99 as
 permitted sender) smtp.mailfrom=cmarinas@kernel.org;       dmarc=fail (p=NONE
 sp=NONE dis=NONE) header.from=arm.com
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

On Sat, Feb 06, 2021 at 04:35:48PM +0800, Lecopzer Chen wrote:
> Linux support KAsan for VMALLOC since commit 3c5c3cfb9ef4da9
> ("kasan: support backing vmalloc space with real shadow memory")
> 
> Like how the MODULES_VADDR does now, just not to early populate
> the VMALLOC_START between VMALLOC_END.
> 
> Before:
> 
> MODULE_VADDR: no mapping, no zoreo shadow at init
> VMALLOC_VADDR: backed with zero shadow at init
> 
> After:
> 
> MODULE_VADDR: no mapping, no zoreo shadow at init
> VMALLOC_VADDR: no mapping, no zoreo shadow at init

s/zoreo/zero/

> Thus the mapping will get allocated on demand by the core function
> of KASAN_VMALLOC.
> 
>   -----------  vmalloc_shadow_start
>  |           |
>  |           |
>  |           | <= non-mapping
>  |           |
>  |           |
>  |-----------|
>  |///////////|<- kimage shadow with page table mapping.
>  |-----------|
>  |           |
>  |           | <= non-mapping
>  |           |
>  ------------- vmalloc_shadow_end
>  |00000000000|
>  |00000000000| <= Zero shadow
>  |00000000000|
>  ------------- KASAN_SHADOW_END
> 
> Signed-off-by: Lecopzer Chen <lecopzer.chen@mediatek.com>
> ---
>  arch/arm64/mm/kasan_init.c | 18 +++++++++++++-----
>  1 file changed, 13 insertions(+), 5 deletions(-)
> 
> diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
> index d8e66c78440e..20d06008785f 100644
> --- a/arch/arm64/mm/kasan_init.c
> +++ b/arch/arm64/mm/kasan_init.c
> @@ -214,6 +214,7 @@ static void __init kasan_init_shadow(void)
>  {
>  	u64 kimg_shadow_start, kimg_shadow_end;
>  	u64 mod_shadow_start, mod_shadow_end;
> +	u64 vmalloc_shadow_end;
>  	phys_addr_t pa_start, pa_end;
>  	u64 i;
>  
> @@ -223,6 +224,8 @@ static void __init kasan_init_shadow(void)
>  	mod_shadow_start = (u64)kasan_mem_to_shadow((void *)MODULES_VADDR);
>  	mod_shadow_end = (u64)kasan_mem_to_shadow((void *)MODULES_END);
>  
> +	vmalloc_shadow_end = (u64)kasan_mem_to_shadow((void *)VMALLOC_END);
> +
>  	/*
>  	 * We are going to perform proper setup of shadow memory.
>  	 * At first we should unmap early shadow (clear_pgds() call below).
> @@ -241,12 +244,17 @@ static void __init kasan_init_shadow(void)
>  
>  	kasan_populate_early_shadow(kasan_mem_to_shadow((void *)PAGE_END),
>  				   (void *)mod_shadow_start);
> -	kasan_populate_early_shadow((void *)kimg_shadow_end,
> -				   (void *)KASAN_SHADOW_END);
>  
> -	if (kimg_shadow_start > mod_shadow_end)
> -		kasan_populate_early_shadow((void *)mod_shadow_end,
> -					    (void *)kimg_shadow_start);

Not something introduced by this patch but what happens if this
condition is false? It means that kimg_shadow_end < mod_shadow_start and
the above kasan_populate_early_shadow(PAGE_END, mod_shadow_start)
overlaps with the earlier kasan_map_populate(kimg_shadow_start,
kimg_shadow_end).

> +	if (IS_ENABLED(CONFIG_KASAN_VMALLOC))
> +		kasan_populate_early_shadow((void *)vmalloc_shadow_end,
> +					    (void *)KASAN_SHADOW_END);
> +	else {
> +		kasan_populate_early_shadow((void *)kimg_shadow_end,
> +					    (void *)KASAN_SHADOW_END);
> +		if (kimg_shadow_start > mod_shadow_end)
> +			kasan_populate_early_shadow((void *)mod_shadow_end,
> +						    (void *)kimg_shadow_start);
> +	}
>  
>  	for_each_mem_range(i, &pa_start, &pa_end) {
>  		void *start = (void *)__phys_to_virt(pa_start);
> -- 
> 2.25.1
> 

-- 
Catalin

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210319173758.GC6832%40arm.com.
