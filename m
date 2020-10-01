Return-Path: <kasan-dev+bncBC7OBJGL2MHBB4FF3D5QKGQE7BYXB6Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D5D3280556
	for <lists+kasan-dev@lfdr.de>; Thu,  1 Oct 2020 19:33:37 +0200 (CEST)
Received: by mail-lj1-x23a.google.com with SMTP id o13sf1342379ljp.18
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Oct 2020 10:33:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1601573617; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ayd4dkVYPfuFfJuuXpg0SlvfzOQuPpa/o0IVObRxomAYehJBd78ORGsrnucahhQ9gG
         FqUfYmAgZvWp8OuHBBpNfVnvVTnvQoLstxzIaqZhCR5n9o/t6dV0+0y14zMPh7e5CGLr
         miLxHOlQ8K25nipuESjH0GHNzhmSs6z5ELi7j0vhv/GNs6JE6YnzKevV871FLZ06mKfm
         7gkIbmkA6Hnt8bQ2303xypyWwz2FlJjV7wAXc/fiHPvYehaIUVDKtDbiwO91pftdnlT1
         GEAqm76yY3jnueX5Q5snwMPQ/zRzLeeMfhnVd2EVi7mfeL0PSuAQ04Lgy9qjAfov/DGU
         bV1A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:dkim-signature;
        bh=Yfur6Jg5nF0NJDzbF9OCg/kTc2AfWw59PStTQ7WIieA=;
        b=aBWLXbh80Sh2rjUZ2UbUJyp5bexr8y0ldh20qH2uUQCMwKfRqirSYs17L237jXkmsv
         XHRMK3TZYqsk2BVWI3v/cUAQOsXUEgUoJQTUizINEZBqOT1CBqZ22PayfGtJn3AycFhK
         4k4vpStIol12GwEVJiDYMpRaisHEcjPBwhVnc0XdrdlencYFjT+vlMmTTc/S4mZvUS0+
         VP3XB1MMSOeRy4r3eWJSgbNKZVBns4J54/tzQJlTArh31iVmhtCMV2F0zhsmzbjnVRAy
         jMdmgY4z1hV09GA1q9Qdo9rDKxiHMtKdbzeTIE8ixtF2FdZUH0+AA4JGvEx99uE4YgNy
         2Ncg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ISKMXrHz;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=Yfur6Jg5nF0NJDzbF9OCg/kTc2AfWw59PStTQ7WIieA=;
        b=KS/YlF8xMgyhE5g/RgRwZ38AC7H5ph4zmg4j6n8VD38+7uxOESuloL8uJn1uLJ91di
         93DXGdvG5uyD8W9iRSUbv5EYXJaswx1/i4nRRHC4PTY5z5k55ii0XfiqrV9Du9w+l0A8
         1MFHH42SNW243yi+AottpUPpnBHwY9R2RLIIHfv52V60oRgBtwnssKU0EkGdy/KqAN+H
         hqWFDvlw8oEdTFvRLAeHILv9+gxFKyepEug4RpgXE9C9vcWHwZzzRGrDN7PZzd324UCH
         tTU03STr2D18ITa/IqDiy9wYlOe6+Q4T7+faGsDV3PRtJeUEuX4EV4YA5ySSFJNKcAs+
         zv/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:from:to:cc:subject:message-id:references
         :mime-version:content-disposition:in-reply-to:user-agent
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Yfur6Jg5nF0NJDzbF9OCg/kTc2AfWw59PStTQ7WIieA=;
        b=ZY9WO+cZmut+MU8rAqIkRznE8/V7ahxhNBaXekqKFur+Iz0iUpPK0qjFMlYvPsFg4w
         Nye2Dh1h3L1dpeTm10jFIlGS2kXUieiuq0SPXDuhkOSqn8Uy/HGBEYnKv+W/Vz2+PZNL
         V/Ma6jns6HJ8qJ78bd+WMcLSqR606kuTDX+/g+BQIUCRX9Ki1LROrj5dmWwrNfUIkrxz
         6/cuFl/dYpx7uBCJP+FfSIUPUG7M+S6lfpo9VctWbGHwx38e4OsT1CgBk1B+uIfLp/Pf
         C1zoUSFj3EyTx0GO66QcuJyx6Y16yDtFdrzUKhurrBSgvyXVGllqx1lG7iq6X64isGqk
         K0og==
X-Gm-Message-State: AOAM530OBqSCT3+Kdz7NT1ObhQ/HIvCSIpB/eSE+oV0w4nkk/F/4b/pH
	0sHgZRPZ/m8NNvHl7Z5ATO8=
X-Google-Smtp-Source: ABdhPJz+TsoleuXYqZKPfB0JCM087OwYV0pvexxDH59v9CT2Im2DGWmG3oGZNMo7uH1f6309+kvzDA==
X-Received: by 2002:ac2:4e92:: with SMTP id o18mr3281060lfr.527.1601573616814;
        Thu, 01 Oct 2020 10:33:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:651c:93:: with SMTP id 19ls970440ljq.4.gmail; Thu, 01
 Oct 2020 10:33:34 -0700 (PDT)
X-Received: by 2002:a2e:8115:: with SMTP id d21mr2913515ljg.16.1601573614117;
        Thu, 01 Oct 2020 10:33:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1601573614; cv=none;
        d=google.com; s=arc-20160816;
        b=AAR/7DV0+FmUMk3+2Z719V4ow1L6+q4L+L5ZRnDlIT2TEtjnzCArYK4Jch3cJg2AVv
         /F63/v3d/hiIIlM0QzxigJeviOGFAwgsnQUxvOO1gGPaQFrV0T3v1sERDR6cjAeLa5IM
         68OxYAb7tLbcxMLM+/dEWGzrYcwpOl+DihYPHV5uGoUaGpixy7qiGYGimkQaml2hLgk4
         soRfkEDdL2WN5x06IcUGgz9KxsQD4EtCvtrE+5Y8dBxDzq85aX7AXdvvf6JKj0Y8xoNQ
         eUJCdX85giGaE3229QbpspKTIpb8F5wyYTurwswKYyUF/sagvztgq+K/UMSy1/EonboA
         a/MA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=RyvBCHeBiWREspyplqvYLjTu6txMmCKxwBHGAY8/C40=;
        b=Cv7yF6kOfxaUUeO+q5vIVX83Bs59JLAjN/FjxLrgEXvrSKqNa+g9IPZxjaqeJW9Doq
         sd+LanJuXo+PGBfufaBiAVKsUeC4e9EnKT/2b5wOV/Yiz1erJtZ9WGmIt0phYDqzoXLh
         2Ep2HThae8Jg13puZMgV6XzMLTcm57OHwHIMz1foO7XfcNy7khYI/o0F4Q+KAmg2/eq9
         m46bkZEkkIbSIm91ov150vDrXFbCVnBL1pxrLdtoTNvWAGiiAz0kQPRBXhp774QNvATp
         lwlLVst3N5fCxKC3SXQJyf7+HeXet6qL9RWafGhUzaoEmS1Fgm7UQ/WQ+fw5KfXsgmds
         bHBQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ISKMXrHz;
       spf=pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x444.google.com (mail-wr1-x444.google.com. [2a00:1450:4864:20::444])
        by gmr-mx.google.com with ESMTPS id y75si145472lfa.3.2020.10.01.10.33.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 01 Oct 2020 10:33:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as permitted sender) client-ip=2a00:1450:4864:20::444;
Received: by mail-wr1-x444.google.com with SMTP id k10so6767744wru.6
        for <kasan-dev@googlegroups.com>; Thu, 01 Oct 2020 10:33:34 -0700 (PDT)
X-Received: by 2002:adf:9504:: with SMTP id 4mr10606938wrs.27.1601573613686;
        Thu, 01 Oct 2020 10:33:33 -0700 (PDT)
Received: from elver.google.com ([100.105.32.75])
        by smtp.gmail.com with ESMTPSA id k4sm10446478wrx.51.2020.10.01.10.33.32
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Oct 2020 10:33:32 -0700 (PDT)
Date: Thu, 1 Oct 2020 19:33:26 +0200
From: elver via kasan-dev <kasan-dev@googlegroups.com>
To: Andrey Konovalov <andreyknvl@google.com>
Cc: Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Catalin Marinas <catalin.marinas@arm.com>,
	kasan-dev@googlegroups.com,
	Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Elena Petrova <lenaptr@google.com>,
	Branislav Rankov <Branislav.Rankov@arm.com>,
	Kevin Brodsky <kevin.brodsky@arm.com>,
	Will Deacon <will.deacon@arm.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 09/39] kasan: define KASAN_GRANULE_PAGE
Message-ID: <20201001173326.GG4162920@elver.google.com>
References: <cover.1600987622.git.andreyknvl@google.com>
 <92a351d2bc4b1235a772f343db06bedf69a3cec9.1600987622.git.andreyknvl@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <92a351d2bc4b1235a772f343db06bedf69a3cec9.1600987622.git.andreyknvl@google.com>
User-Agent: Mutt/1.14.5 (2020-06-23)
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ISKMXrHz;       spf=pass
 (google.com: domain of elver@google.com designates 2a00:1450:4864:20::444 as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: elver@google.com
Reply-To: elver@google.com
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

On Fri, Sep 25, 2020 at 12:50AM +0200, Andrey Konovalov wrote:
> Define KASAN_GRANULE_PAGE as (KASAN_GRANULE_SIZE << PAGE_SHIFT), which is
> the same as (KASAN_GRANULE_SIZE * PAGE_SIZE), and use it across KASAN code
> to simplify it.
> 
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>

Reviewed-by: Marco Elver <elver@google.com>

> ---
> Change-Id: I0b627b24187d06c8b9bb2f1d04d94b3d06945e73
> ---
>  mm/kasan/init.c   | 10 ++++------
>  mm/kasan/kasan.h  |  1 +
>  mm/kasan/shadow.c | 16 +++++++---------
>  3 files changed, 12 insertions(+), 15 deletions(-)
> 
> diff --git a/mm/kasan/init.c b/mm/kasan/init.c
> index 1a71eaa8c5f9..26b2663b3a42 100644
> --- a/mm/kasan/init.c
> +++ b/mm/kasan/init.c
> @@ -441,9 +441,8 @@ void kasan_remove_zero_shadow(void *start, unsigned long size)
>  	addr = (unsigned long)kasan_mem_to_shadow(start);
>  	end = addr + (size >> KASAN_SHADOW_SCALE_SHIFT);
>  
> -	if (WARN_ON((unsigned long)start %
> -			(KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
> -	    WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
> +	if (WARN_ON((unsigned long)start % KASAN_GRANULE_PAGE) ||
> +	    WARN_ON(size % KASAN_GRANULE_PAGE))
>  		return;
>  
>  	for (; addr < end; addr = next) {
> @@ -476,9 +475,8 @@ int kasan_add_zero_shadow(void *start, unsigned long size)
>  	shadow_start = kasan_mem_to_shadow(start);
>  	shadow_end = shadow_start + (size >> KASAN_SHADOW_SCALE_SHIFT);
>  
> -	if (WARN_ON((unsigned long)start %
> -			(KASAN_GRANULE_SIZE * PAGE_SIZE)) ||
> -	    WARN_ON(size % (KASAN_GRANULE_SIZE * PAGE_SIZE)))
> +	if (WARN_ON((unsigned long)start % KASAN_GRANULE_PAGE) ||
> +	    WARN_ON(size % KASAN_GRANULE_PAGE))
>  		return -EINVAL;
>  
>  	ret = kasan_populate_early_shadow(shadow_start, shadow_end);
> diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
> index c31e2c739301..1865bb92d47a 100644
> --- a/mm/kasan/kasan.h
> +++ b/mm/kasan/kasan.h
> @@ -7,6 +7,7 @@
>  
>  #define KASAN_GRANULE_SIZE	(1UL << KASAN_SHADOW_SCALE_SHIFT)
>  #define KASAN_GRANULE_MASK	(KASAN_GRANULE_SIZE - 1)
> +#define KASAN_GRANULE_PAGE	(KASAN_GRANULE_SIZE << PAGE_SHIFT)
>  
>  #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
>  #define KASAN_TAG_INVALID	0xFE /* inaccessible memory tag */
> diff --git a/mm/kasan/shadow.c b/mm/kasan/shadow.c
> index ca0cc4c31454..1fadd4930d54 100644
> --- a/mm/kasan/shadow.c
> +++ b/mm/kasan/shadow.c
> @@ -161,7 +161,7 @@ static int __meminit kasan_mem_notifier(struct notifier_block *nb,
>  	shadow_end = shadow_start + shadow_size;
>  
>  	if (WARN_ON(mem_data->nr_pages % KASAN_GRANULE_SIZE) ||
> -		WARN_ON(start_kaddr % (KASAN_GRANULE_SIZE << PAGE_SHIFT)))
> +		WARN_ON(start_kaddr % KASAN_GRANULE_PAGE))
>  		return NOTIFY_BAD;
>  
>  	switch (action) {
> @@ -432,22 +432,20 @@ void kasan_release_vmalloc(unsigned long start, unsigned long end,
>  	unsigned long region_start, region_end;
>  	unsigned long size;
>  
> -	region_start = ALIGN(start, PAGE_SIZE * KASAN_GRANULE_SIZE);
> -	region_end = ALIGN_DOWN(end, PAGE_SIZE * KASAN_GRANULE_SIZE);
> +	region_start = ALIGN(start, KASAN_GRANULE_PAGE);
> +	region_end = ALIGN_DOWN(end, KASAN_GRANULE_PAGE);
>  
> -	free_region_start = ALIGN(free_region_start,
> -				  PAGE_SIZE * KASAN_GRANULE_SIZE);
> +	free_region_start = ALIGN(free_region_start, KASAN_GRANULE_PAGE);
>  
>  	if (start != region_start &&
>  	    free_region_start < region_start)
> -		region_start -= PAGE_SIZE * KASAN_GRANULE_SIZE;
> +		region_start -= KASAN_GRANULE_PAGE;
>  
> -	free_region_end = ALIGN_DOWN(free_region_end,
> -				     PAGE_SIZE * KASAN_GRANULE_SIZE);
> +	free_region_end = ALIGN_DOWN(free_region_end, KASAN_GRANULE_PAGE);
>  
>  	if (end != region_end &&
>  	    free_region_end > region_end)
> -		region_end += PAGE_SIZE * KASAN_GRANULE_SIZE;
> +		region_end += KASAN_GRANULE_PAGE;
>  
>  	shadow_start = kasan_mem_to_shadow((void *)region_start);
>  	shadow_end = kasan_mem_to_shadow((void *)region_end);
> -- 
> 2.28.0.681.g6f77f65b4e-goog
> 

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20201001173326.GG4162920%40elver.google.com.
